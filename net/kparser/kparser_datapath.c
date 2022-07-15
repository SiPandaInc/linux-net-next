// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2020, 2021, 2022 SiPanda Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* kparser main parsing logic - data path */
#include "kparser.h"
#include "kparser_types.h"
#include "kparser_metaextract.h"
#include "kparser_tlvs.h"
#include "kparser_flag_fields.h"
#include "kparser_metaextract.h"
#include "kparser_condexpr.h"
#include <linux/rhashtable.h>
#include <linux/skbuff.h>

/* Lookup a type in a node table*/
static const struct kparser_parse_node *lookup_node(int type,
		const struct kparser_proto_table *table)
{
	int i;

	if (!table)
		return NULL;

	for (i = 0; i < table->num_ents; i++)
		if (type == table->entries[i].value)
			return table->entries[i].node;

	return NULL;
}

/* Lookup a type in a node TLV table */
static const struct kparser_parse_tlv_node *lookup_tlv_node(int type,
				const struct kparser_proto_tlvs_table *table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (type == table->entries[i].type)
			return table->entries[i].node;

	return NULL;
}

/* Lookup up a protocol for the table associated with a parse node */
const struct kparser_parse_tlv_node *kparser_parse_lookup_tlv(
		const struct kparser_parse_tlvs_node *node,
		unsigned int type)
{
	return lookup_tlv_node(type, node->tlv_proto_table);
}

/* Lookup a flag-fields index in a protocol node flag-fields table */
static const struct kparser_parse_flag_field_node *lookup_flag_field_node(int idx,
				const struct kparser_proto_flag_fields_table
								*table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (idx == table->entries[i].index)
			return table->entries[i].node;

	return NULL;
}

/* Metadata table and conditional expressions handdling */

static void extract_metadata_table(
	const struct kparser_metadata_table *metadata_table,
	const void *_hdr, size_t hdr_len, size_t hdr_offset,
	void *_metadata, void *_frame, const struct kparser_ctrl_data *ctrl)
{
	int i;

	for (i = 0; i < metadata_table->num_ents; i++)
		kparser_metadata_extract(metadata_table->entries[i], _hdr,
					      hdr_len, hdr_offset, _metadata,
					      _frame, ctrl);
}

static int eval_parameterized_next_proto(
		const struct kparser_parameterized_next_proto *pf, void *_hdr)
{
	__u16 next_proto;

	_hdr += pf->src_off;

	switch (pf->size) {
	case 1:
		next_proto = *(__u8 *)_hdr;
		break;
	case 2:
		next_proto = *(__u16 *)_hdr;
		break;
	default:
		return KPARSER_STOP_UNKNOWN_PROTO;
	}

	return (next_proto & pf->mask) >> pf->right_shift;
}

static ssize_t eval_parameterized_len(
		const struct kparser_parameterized_len *pf, void *_hdr)
{
	__u32 len;

	_hdr += pf->src_off;

	switch (pf->size) {
	case 1:
		len = *(__u8 *)_hdr;
		break;
	case 2:
		len = *(__u16 *)_hdr;
		break;
	case 3:
		len = 0;
		memcpy(&len, _hdr, 3);
		break; // TODO
	case 4:
		len = *(__u32 *)_hdr;
		break;
	default:
		return KPARSER_STOP_LENGTH;
	}

	len = (len & pf->mask) >> pf->right_shift;

	return (len * pf->multiplier) + pf->add_value;
}

static bool eval_cond_exprs_and_table(
		const struct kparser_condexpr_table *table, void *_hdr)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (!kparser_expr_evaluate(&table->entries[i], _hdr))
			return false;

	return true;
}

static bool eval_cond_exprs_or_table(
		const struct kparser_condexpr_table *table, void *_hdr)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (kparser_expr_evaluate(&table->entries[i], _hdr))
			return true;

	return false;
}

static int eval_cond_exprs(const struct kparser_condexpr_tables *tables,
			   void *_hdr)
{
	bool res;
	int i;

	for (i = 0; i < tables->num_ents; i++) {
		const struct kparser_condexpr_table *table =
							tables->entries[i];

		switch (table->type) {
		case KPARSER_CONDEXPR_TYPE_OR:
			res = eval_cond_exprs_or_table(table, _hdr);
			break;
		case KPARSER_CONDEXPR_TYPE_AND:
			res = eval_cond_exprs_and_table(table, _hdr);
			break;
		}
		if (!res)
			return table->default_fail;
	}

	return KPARSER_OKAY;
}

static int kparser_parse_one_tlv(
		const struct kparser_parse_tlvs_node *parse_tlvs_node,
		const struct kparser_parse_tlv_node *parse_tlv_node,
		unsigned int flags, void *_obj_ref, void *_hdr,
		size_t tlv_len, size_t tlv_offset, void *_metadata,
		void *_frame, struct kparser_ctrl_data *ctrl)
{
	const struct kparser_parse_tlv_node *next_parse_tlv_node;
	const struct kparser_proto_tlv_node *proto_tlv_node;
	const struct kparser_proto_tlv_node_ops *proto_ops;
	int type, ret;

parse_again:

	proto_tlv_node = parse_tlv_node->proto_tlv_node;

	if (flags & KPARSER_F_DEBUG)
		pr_debug("PANDA parsing TLV %s\n", parse_tlv_node->name);

	if (proto_tlv_node && ((tlv_len < proto_tlv_node->min_len) ||
			       (tlv_len > proto_tlv_node->max_len))) {
		/* Treat check length error as an unrecognized TLV */
		parse_tlv_node = parse_tlvs_node->tlv_wildcard_node;
		if (parse_tlv_node)
			goto parse_again;
		else
			return parse_tlvs_node->unknown_tlv_type_ret;
	}

	proto_ops = proto_tlv_node ? &proto_tlv_node->ops : NULL;

	if (proto_ops) {
		ret = eval_cond_exprs(&proto_ops->cond_exprs, _hdr);
		if (ret != KPARSER_OKAY)
			return ret;
	}

	if (parse_tlv_node->metadata_table)
		extract_metadata_table(parse_tlv_node->metadata_table,
				       _hdr, tlv_len, tlv_offset, _metadata,
				       _frame, ctrl);

	if (!parse_tlv_node->overlay_table)
		return KPARSER_OKAY;

	/* We have an TLV overlay  node */
	if (proto_ops)
		type = eval_parameterized_next_proto(
				&proto_ops->pfoverlay_type, _hdr);
	else
		type = tlv_len;

	if (type < 0)
		return type;

	/* Get TLV node */
	next_parse_tlv_node =
			lookup_tlv_node(type, parse_tlv_node->overlay_table);
	if (next_parse_tlv_node) {
		parse_tlv_node = next_parse_tlv_node;
		goto parse_again;
	}

	/* Unknown TLV overlay node */
	next_parse_tlv_node = parse_tlv_node->overlay_wildcard_node;
	if (next_parse_tlv_node) {
		parse_tlv_node = next_parse_tlv_node;
		goto parse_again;
	}

	return parse_tlv_node->unknown_overlay_ret;
}

static int loop_limit_exceeded(int ret, unsigned int disp)
{
	switch (disp) {
	case KPARSER_LOOP_DISP_STOP_OKAY:
		return KPARSER_STOP_OKAY;
	case KPARSER_LOOP_DISP_STOP_NODE_OKAY:
		return KPARSER_STOP_NODE_OKAY;
	case KPARSER_LOOP_DISP_STOP_SUB_NODE_OKAY:
		return KPARSER_STOP_SUB_NODE_OKAY;
	case KPARSER_LOOP_DISP_STOP_FAIL:
	default:
		return ret;
	}
}

static __u64 eval_get_value(const struct kparser_parameterized_get_value *pf,
			    void *_hdr)
{
	__u64 ret;

	__kparser_metadata_byte_extract(_hdr + pf->src_off, (__u8 *)&ret,
					     pf->size, false);

	return ret;
}

static int kparser_parse_tlvs(const struct kparser_parse_node *parse_node,
			    unsigned int flags, void *_obj_ref,
			    void *_hdr, size_t hdr_len, size_t hdr_offset,
			    void *_metadata, void *_frame,
			    const struct kparser_ctrl_data *ctrl)
{
	unsigned int loop_cnt = 0, non_pad_cnt = 0, pad_len = 0;
	const struct kparser_parse_tlvs_node *parse_tlvs_node;
	const struct kparser_proto_tlvs_node *proto_tlvs_node;
	const struct kparser_parse_tlv_node *parse_tlv_node;
	struct kparser_ctrl_data tlv_ctrl = {};
	unsigned int consec_pad = 0;
	size_t len, tlv_offset;
	ssize_t off, tlv_len;
	__u8 *cp = _hdr;
	int type, ret;

	parse_tlvs_node = (struct kparser_parse_tlvs_node *)parse_node;
	proto_tlvs_node = (struct kparser_proto_tlvs_node *)
						parse_node->proto_node;

	/* Assume hlen marks end of TLVs */
	if (proto_tlvs_node->fixed_start_offset)
		off = proto_tlvs_node->start_offset;
	else
		off = eval_parameterized_len(
			&proto_tlvs_node->ops.pfstart_offset, cp);

	if (off < 0)
		return KPARSER_STOP_LENGTH;

	/* We assume start offset is less than or equal to minimal length */
	len = hdr_len - off;

	cp += off;
	tlv_offset = hdr_offset + off;

	while (len > 0) {
		if (++loop_cnt > parse_tlvs_node->config.max_loop)
			return loop_limit_exceeded(KPARSER_STOP_LOOP_CNT,
				parse_tlvs_node->config.disp_limit_exceed);

		if (proto_tlvs_node->pad1_enable &&
		   *cp == proto_tlvs_node->pad1_val) {
			/* One byte padding, just advance */
			cp++;
			tlv_offset++;
			len--;
			if (++pad_len > parse_tlvs_node->config.max_plen ||
			    ++consec_pad > parse_tlvs_node->config.max_c_pad)
				return loop_limit_exceeded(
				    KPARSER_STOP_TLV_PADDING,
				    parse_tlvs_node->config.disp_limit_exceed);
			continue;
		}

		if (proto_tlvs_node->eol_enable &&
		    *cp == proto_tlvs_node->eol_val) {
			cp++;
			tlv_offset++;
			len--;

			/* Hit EOL, we're done */
			break;
		}

		if (len < proto_tlvs_node->min_len) {
			/* Length error */
			return loop_limit_exceeded(KPARSER_STOP_TLV_LENGTH,
			    parse_tlvs_node->config.disp_limit_exceed);
		}

		/* If the len function is not set this degenerates to an
		 * array of fixed sized values (which maybe be useful in
		 * itself now that I think about it)
		 */
		do {
			if (proto_tlvs_node->ops.len_parameterized) {
				tlv_len = eval_parameterized_len(
					&proto_tlvs_node->ops.pflen, cp);
			} else {
				tlv_len = proto_tlvs_node->min_len;
				break;
			}

			if (!tlv_len || len < tlv_len)
				return loop_limit_exceeded(
				    KPARSER_STOP_TLV_LENGTH,
				    parse_tlvs_node->config.disp_limit_exceed);

			if (tlv_len < proto_tlvs_node->min_len)
				return loop_limit_exceeded(
				    KPARSER_STOP_TLV_LENGTH,
				    parse_tlvs_node->config.disp_limit_exceed);
		} while (0);

		if (proto_tlvs_node->ops.type_parameterized)
			type = eval_parameterized_next_proto(
					&proto_tlvs_node->ops.pftype, cp);

		if (proto_tlvs_node->padn_enable &&
		    type == proto_tlvs_node->padn_val) {
			/* N byte padding, just advance */
			if ((pad_len += tlv_len) >
					parse_tlvs_node->config.max_plen ||
			    ++consec_pad > parse_tlvs_node->config.max_c_pad)
				return loop_limit_exceeded(
				    KPARSER_STOP_TLV_PADDING,
				    parse_tlvs_node->config.disp_limit_exceed);
			goto next_tlv;
		}

		/* Get TLV node */
		parse_tlv_node = lookup_tlv_node(type,
				parse_tlvs_node->tlv_proto_table);
parse_one_tlv:
		if (parse_tlv_node) {
			const struct kparser_proto_tlv_node *proto_tlv_node =
					parse_tlv_node->proto_tlv_node;

			if (proto_tlv_node) {
				if (proto_tlv_node->is_padding) {
					if ((pad_len += tlv_len) >
						parse_tlvs_node->
							config.max_plen ||
						++consec_pad >
						parse_tlvs_node->
							config.max_c_pad)
						return loop_limit_exceeded(
						    KPARSER_STOP_TLV_PADDING,
						    parse_tlvs_node->config.
							disp_limit_exceed);
				} else if (++non_pad_cnt >
						parse_tlvs_node->
							config.max_non) {
					return loop_limit_exceeded(
					    KPARSER_STOP_OPTION_LIMIT,
					    parse_tlvs_node->config.
							disp_limit_exceed);
				}
			}

			ret = kparser_parse_one_tlv(parse_tlvs_node,
						  parse_tlv_node,
						  flags, _obj_ref, cp, tlv_len,
						  tlv_offset, _metadata,
						  _frame, &tlv_ctrl);
			if (ret != KPARSER_OKAY)
				return ret;
		} else {
			/* Unknown TLV */
			parse_tlv_node = parse_tlvs_node->tlv_wildcard_node;
			if (parse_tlv_node) {
				/* If a wilcard node is present parse that
				 * node as an overlay to this one. The
				 * wild card node can perform error processing
				 */
				goto parse_one_tlv;
			}
			/* Return default error code. Returning
			 * KPARSER_OKAY means skip
			 */
			if (parse_tlvs_node->unknown_tlv_type_ret !=
			    KPARSER_OKAY)
				return
				  parse_tlvs_node->unknown_tlv_type_ret;
		}

		/* Move over current header */
next_tlv:
		cp += tlv_len;
		tlv_offset += tlv_len;
		len -= tlv_len;
	}

	return KPARSER_OKAY;
}

static int kparser_parse_flag_fields(const struct kparser_parse_node *parse_node,
				   unsigned int pflags, void *_obj_ref,
				   void *_hdr, size_t hdr_len,
				   size_t hdr_offset, void *_metadata,
				   void *_frame,
				   const struct kparser_ctrl_data *ctrl)
{
	const struct kparser_parse_flag_fields_node *parse_flag_fields_node;
	const struct kparser_proto_flag_fields_node *proto_flag_fields_node;
	const struct kparser_parse_flag_field_node *parse_flag_field_node;
	const struct kparser_flag_fields *flag_fields;
	ssize_t off, field_len, field_offset;
	__u32 flags;
	int i;

	parse_flag_fields_node =
			(struct kparser_parse_flag_fields_node *)parse_node;
	proto_flag_fields_node =
			(struct kparser_proto_flag_fields_node *)
						parse_node->proto_node;
	flag_fields = proto_flag_fields_node->flag_fields;

	flags = eval_get_value(
			&proto_flag_fields_node->ops.pfget_flags, _hdr);

	/* Position at start of field data */
	off = eval_parameterized_len(
			&proto_flag_fields_node->ops.pfstart_fields_offset,
			_hdr);

	if (off < 0)
		return off;

	_hdr += off;
	hdr_offset += off;

	for (i = 0; i < flag_fields->num_idx; i++) {
		off = kparser_flag_fields_offset(i, flags, flag_fields);
		if (off < 0)
			continue;

		/* Flag field is present, try to find in the parse node
		 * table based on index in proto flag-fields
		 */
		parse_flag_field_node = lookup_flag_field_node(i,
			parse_flag_fields_node->flag_fields_proto_table);
		if (parse_flag_field_node) {
			const struct kparser_parse_flag_field_node_ops
				*ops = &parse_flag_field_node->ops;
			__u8 *cp = _hdr + off;

			field_len = flag_fields->fields[i].size;
			field_offset = hdr_offset + off;

			if (pflags & KPARSER_F_DEBUG)
				pr_debug("PANDA parsing flag-field %s\n",
				      parse_flag_field_node->name);

			if (eval_cond_exprs(&ops->cond_exprs, cp) < 0)
				return KPARSER_STOP_COMPARE;

			if (parse_flag_field_node->metadata_table)
				extract_metadata_table(
					parse_flag_field_node->metadata_table,
					cp, field_len, field_offset,
					_metadata, _frame, ctrl);
		}
	}

	return KPARSER_OKAY;
}


/* Parse a packet
 *
 * Arguments:
 *   - parser: Parser being invoked
 *   - hdr: pointer to start of packet
 *   - parse_len: length of data in parsing buffer (headers), this may be less
 *      than length of the object)
 *   - metadata: metadata structure
 *   - return code: 0 for success, > 0 for errno, < 0 for parser errno
 *
 * rcu lock must be held before calling this function.
 */
static int __kparser_parse(const struct kparser_parser *parser, void *_hdr,
		size_t parse_len, void *_metadata, size_t _metadata_len)
{
	struct kparser_ctrl_data ctrl = { .ret = KPARSER_OKAY };
	const struct kparser_parse_node *next_parse_node;
	const struct kparser_parse_node *parse_node;
	void *_frame, *_obj_ref = NULL;
	const void *base_hdr = _hdr;
	unsigned int frame_num = 0;
	ssize_t hdr_offset = 0;
	unsigned int flags;
	ssize_t hdr_len;
	int type;

	// Validate the caller passed metadata struct and buffer
	if (!parser || !_metadata || _metadata_len == 0 || !_hdr || parse_len == 0) {
		pr_debug("%s: one or more empty param(s).\n", __FUNCTION__);
		return EINVAL;
	}

	if (parse_len < parser->config.metameta_size) {
		pr_debug("%s: parse buf err, parse_len:%lu, mmd_len:%lu\n",
				__FUNCTION__, parse_len,
				parser->config.metameta_size);
		return EINVAL;
	}

	_frame = _metadata + parser->config.metameta_size;
	flags = parser->config.flags;

	ctrl.hdr_base = _hdr;
	ctrl.node_cnt = 0;
	ctrl.encap_levels = 0;

	parse_node = rcu_dereference(parser->root_node);
	// TODO: use rcu_dereference() elsewhere as needed

	if (!parse_node) {
		pr_debug("%s: root node missing,parser:%s\n",
			__FUNCTION__, parser->name);
		return ENOENT;
	}

	/* Main parsing loop. The loop normal teminates when we encounter a
	 * leaf protocol node, an error condition, hitting limit on layers of
	 * encapsulation, protocol condition to stop (i.e. flags that
	 * indicate to stop at flow label or hitting fragment), or
	 * unknown protocol result in table lookup for next node.
	 */

	do {
		const struct kparser_proto_node *proto_node =
			parse_node->proto_node;

		hdr_len = proto_node->min_len;

		if (++ctrl.node_cnt > parser->config.max_nodes) {
			ctrl.ret = KPARSER_STOP_MAX_NODES;
			goto parser_out;
		}
		/* Protocol node length checks */

		if (flags & KPARSER_F_DEBUG)
			pr_debug("PANDA parsing %s\n", proto_node->name);

		if (parse_len < hdr_len) {
			ctrl.ret = KPARSER_STOP_LENGTH;
			goto parser_out;
		}

		do {
			hdr_len = eval_parameterized_len(
					&proto_node->ops.pflen, _hdr);

			if (hdr_len < proto_node->min_len) {
				ctrl.ret = hdr_len < 0 ? hdr_len :
							KPARSER_STOP_LENGTH;
				goto parser_out;
			}
			if (parse_len < hdr_len) {
				ctrl.ret = KPARSER_STOP_LENGTH;
				goto parser_out;
			}
		} while (0);

		hdr_offset = _hdr - base_hdr;

		ctrl.pkt_len = parse_len;

		/* Callback processing order
		 *    1) Extract Metadata
		 *    2) Process TLVs
		 *	2.a) Extract metadata from TLVs
		 *	2.b) Process TLVs
		 *    3) Process protocol
		 */

		if (parse_node->metadata_table)
			extract_metadata_table(parse_node->metadata_table,
					       _hdr, hdr_len, hdr_offset,
					       _metadata, _frame, &ctrl);

		/* Process node type */
		switch (parse_node->node_type) {
		case KPARSER_NODE_TYPE_PLAIN:
		default:
			break;
		case KPARSER_NODE_TYPE_TLVS:
			/* Process TLV nodes */
			if (parse_node->proto_node->node_type !=
			    KPARSER_NODE_TYPE_TLVS)
				break;

			/* Need error in case parse_node is TLVs type, but
			 * proto_node is not TLVs type
			 */
			ctrl.ret = kparser_parse_tlvs(parse_node, flags,
						    _obj_ref, _hdr, hdr_len,
						    hdr_offset, _metadata,
						    _frame, &ctrl);
check_processing_return:
			switch (ctrl.ret) {
			case KPARSER_STOP_OKAY:
				goto parser_out;
			case KPARSER_OKAY:
				break; /* Go to the next node */
			case KPARSER_STOP_NODE_OKAY:
				/* Note KPARSER_STOP_NODE_OKAY means that
				 * post loop processing is not
				 * performed
				 */
				ctrl.ret = KPARSER_OKAY;
				goto after_post_processing;
			case KPARSER_STOP_SUB_NODE_OKAY:
				ctrl.ret = KPARSER_OKAY;
				break; /* Just go to next node */
			default:
				goto parser_out;
			}
			break;
		case KPARSER_NODE_TYPE_FLAG_FIELDS:
			/* Process flag-fields */
			if (parse_node->proto_node->node_type ==
						KPARSER_NODE_TYPE_FLAG_FIELDS) {
				/* Need error in case parse_node is flag-fields
				 * type but proto_node is not flag-fields type
				 */
				ctrl.ret = kparser_parse_flag_fields(parse_node,
						flags, _obj_ref, _hdr, hdr_len,
						hdr_offset, _metadata, _frame,
						&ctrl);
				goto check_processing_return;
			}
			break;
		}

after_post_processing:
		/* Proceed to next protocol layer */

		if (!parse_node->proto_table && !parse_node->wildcard_node) {
			/* Leaf parse node */

			goto parser_out;
		}

		if (proto_node->encap) {
			/* New encapsulation layer. Check against
			 * number of encap layers allowed and also
			 * if we need a new metadata frame.
			 */
			if (++ctrl.encap_levels > parser->config.max_encaps) {
				ctrl.ret = KPARSER_STOP_ENCAP_DEPTH;
				goto parser_out;
			}

			if (frame_num < parser->config.max_frames) {
				_frame += parser->config.frame_size;
				frame_num++;
			}
		}

		if (parse_node->proto_table) {
			do {
				ctrl.ret = eval_cond_exprs(
						&proto_node->ops.cond_exprs,
						_hdr);
				if (ctrl.ret != KPARSER_OKAY)
					goto parser_out;

				type = eval_parameterized_next_proto(
						&proto_node->ops.pfnext_proto,
						_hdr);
				if (type < 0) {
					ctrl.ret = type;
					goto parser_out;
				}

				/* Get next node */
				next_parse_node = lookup_node(type,
						parse_node->proto_table);

				if (next_parse_node)
					goto found_next;
			} while (0);
		}

		/* Try wildcard node. Either table lookup failed to find a
		 * node or there is only a wildcard
		 */
		if (parse_node->wildcard_node) {
			/* Perform default processing in a wildcard node */

			next_parse_node = parse_node->wildcard_node;
		} else {
			/* Return default code. Parsing will stop
			 * with the inidicated code
			 */

			ctrl.ret = parse_node->unknown_ret;
			goto parser_out;
		}

found_next:
		/* Found next protocol node, set up to process */

		if (!proto_node->overlay) {
			/* Move over current header */
			_hdr += hdr_len;
			parse_len -= hdr_len;
		}
		parse_node = next_parse_node;
	} while (1);

parser_out:
	parse_node = (ctrl.ret == KPARSER_OKAY ||
		      KPARSER_IS_OK_CODE(ctrl.ret)) ?
					parser->okay_node : parser->fail_node;

	if (!parse_node)
		return ctrl.ret == KPARSER_OKAY ? KPARSER_STOP_OKAY : ctrl.ret;

	/* Run an exit parse node. This is either the okay node or the fail
	 * node that is set in parser config
	 */

	extract_metadata_table(parse_node->metadata_table, _hdr,
			hdr_len, hdr_offset, _metadata, _frame,
			&ctrl);

	return ctrl.ret == KPARSER_OKAY ? KPARSER_STOP_OKAY : ctrl.ret;
}

int kparser_parse(struct sk_buff *skb,
		const struct kparser_hkey *kparser_key,
		void *_metadata, size_t _metadata_len)
{
	const struct kparser_parser *parser;
        void *data, *ptr;
        size_t pktlen;
        int err;

        err = skb_linearize(skb);
        if (err < 0)
                return err;

        BUG_ON(skb->data_len);

        data = skb_mac_header(skb);
        pktlen = skb_mac_header_len(skb) + skb->len;

	// Lookup associated kparser context
	if (!kparser_key) {
		pr_debug("%s: kparser_key is empty\n", __FUNCTION__);
		return EINVAL;
	}

	rcu_read_lock();

	ptr = kparser_namespace_lookup(KPARSER_NS_PARSER, kparser_key);
	parser = rcu_dereference(ptr);
	if (parser == NULL) {
		pr_debug("%s: parser htbl lookup failure for key: {%s:%u}\n",
			__FUNCTION__, kparser_key->name, kparser_key->id);
		rcu_read_unlock();
		return ENOENT;
	}

        err = __kparser_parse(parser, data, pktlen,
		_metadata, _metadata_len);

	rcu_read_unlock();

	return err;
}

EXPORT_SYMBOL(kparser_parse);
