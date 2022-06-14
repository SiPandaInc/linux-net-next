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
#include "kparser_metaextract.h"
#include <linux/rhashtable.h>

static __s32 eval_parameterized_next_proto(
		const struct kparser_nxt_proto_key *pf, void *hdr)
{
	__u16 next_proto;

	hdr += pf->src_off;

	switch (pf->size) {
	case 1:
		next_proto = *(__u8 *)hdr;
		break;
	case 2:
		next_proto = *(__u16 *)hdr;
		break;
	default:
		return -1;
	}

	return (next_proto & pf->mask) >> pf->right_shift;
}

static __s64 eval_parameterized_len(const struct kparser_parameterized_len *pf,
		const void *hdr, size_t hdr_len)
{
	__u32 len;

	if (hdr_len < pf->src_off)
		return -EFBIG;

	hdr += pf->src_off;

	switch (pf->size) {
	case 1:
		len = *(__u8 *)hdr;
		break;
	case 2:
		len = *(__u16 *)hdr;
		break;
	case 3:
		len = 0;
		memcpy(&len, hdr, 3);
		// TODO: check if missing break was intentional in orig code
		break;
	case 4:
		len = *(__u32 *)hdr;
		break;
	default:
		return -1;
	}

	len = (len & pf->mask) >> pf->right_shift;

	return (len * pf->multiplier) + pf->add_value;
}

/* Parse a packet
 *
 * Arguments:
 *   - parser: Parser being invoked
 *   - hdr: pointer to start of packet
 *   - parse_len: length of data in parsing buffer (headers), this may be less
 *      than length of the object)
 *   - obj_ref: opaque point to whole object
 *   - metadata: metadata structure
 *   - return code: 0 for success, > 0 for errno, < 0 for parser errno
 */
int kparser_do_parse(const struct kparser_hkey *kparser_key, void *hdr,
		size_t parse_len, void *obj_ref, 
		void *metadata_dbuf, size_t metadata_dbuf_len)
{
	size_t hdr_offset = 0, hdr_len = 0;
	__u16 frame_num = 0, node_cnt = 0;
	struct kparser_metadata *mdhdr;
	struct kparser_proto_ent *pent;
	struct kparser_parser *parser;
	struct kparser_node *nxtnode;
	struct kparser_node *node;
	struct kparser_proto *ptbl;
	const void *base_hdr = hdr;
	struct kparser_mdl *mdl;
	struct kparser_md *md;
	int nxt_proto_map, rc;
	void *frame_curr;
	int i;

	// Validate the caller passed metadata strcuct and buffer
	if (metadata_dbuf == NULL) {
		pr_debug("%s: metadata_dbuf is NULL\n", __FUNCTION__);
		return EINVAL;
	}

	if (metadata_dbuf_len < sizeof(*mdhdr)) {
		pr_debug("%s: metadata_dbuf_len must be atleast of size %lu\n",
				__FUNCTION__, sizeof(*mdhdr));
		return EINVAL;
	}

	mdhdr = metadata_dbuf;
	if (metadata_dbuf_len < (sizeof(*mdhdr) +
				mdhdr->meta_meta_data_size +
				(mdhdr->max_frame_num *
				mdhdr->frame_size))) {
		pr_debug("%s: metadata_dbuf_len must match to the total"
			 " specified user buffer requirement as per the"
			 " max_frame_num and meta_meta_data_size\n",
				__FUNCTION__);
		return EINVAL;
	}

	frame_curr = mdhdr->frame_data + mdhdr->meta_meta_data_size;

	// Lookup associated kparser context
	if (kparser_key == NULL) {
		pr_debug("%s: kparser_key is NULL\n", __FUNCTION__);
		return EINVAL;
	}
	parser = global_htbl_lookup(KPARSER_HTBL_PARSER, kparser_key);
	if (parser == NULL) {
		pr_debug("%s: parser htbl lookup failure for key: {%s:%u}\n",
			__FUNCTION__, kparser_key->name, kparser_key->id);
		return ENOENT;
	}

	node = parser->rnode_ref;
	// global_htbl_lookup(KPARSER_HTBL_NODE, &parser->arg.root_node_key);
	if (node == NULL) {
		pr_debug("%s: node htbl lookup failure for root"
			 " node, parser key: {%s:%u} root node key: {%s:%u}\n",
			__FUNCTION__,
			kparser_key->name, kparser_key->id,
			parser->arg.root_node_key.name,
			parser->arg.root_node_key.id);
		return ENOENT;
	}

	/* Main parsing loop. The loop normal teminates when we encounter a
	 * leaf protocol node, an error condition, hitting limit on layers of
	 * encapsulation, protocol condition to stop (i.e. flags that
	 * indicate to stop at flow label or hitting fragment), or
	 * unknown protocol result in table lookup for next node.
	 */
	while(1) {
		if (++node_cnt > parser->arg.config.max_nodes) {
			rc = PANDA_STOP_MAX_NODES;
			goto parser_error;
		}

		hdr_len = node->arg.minlen;
		// verify minimum hdr len
		if (parse_len < hdr_len) {
			rc = PANDA_STOP_LENGTH;
			goto parser_error;
		}

		if (0) {
			// find actual len of this protocol if configured
			hdr_len = eval_parameterized_len(&node->arg.plen,
					hdr, parse_len);
		}
		printk("DP:%s:%lu\n", __FUNCTION__, hdr_len);
		if (hdr_len < node->arg.minlen) {
			rc = (long int) hdr_len < 0 ? hdr_len : PANDA_STOP_LENGTH;
			goto parser_error;
		}
		if (parse_len < hdr_len) {
			rc = PANDA_STOP_LENGTH;
			goto parser_error;
		}
		hdr_offset = hdr - base_hdr;

		/* Processing order
		 *    1) Extract Metadata
		 *    2) Process TLVs
		 *	2.a) Extract metadata from TLVs
		 *	2.b) Process TLVs
		 *    3) Process protocol
		 */

		/* Extract metadata, per node processing
		 * Lookup associated mdtbl context for mdl
		 * Traverse all the md under that mdl
		 */
		mdl = node->mdl_ref;
		// global_htbl_lookup(KPARSER_HTBL_MDL, &node->arg.mdl_key);
		if (mdl) {
			pr_debug("%s:%d:%d\n", __FUNCTION__, __LINE__, rc);
			list_for_each_entry(md, &mdl->mdl, mdl_node) {
				rc = kparser_metadata_extract(md->arg.config,
						hdr, hdr_len, frame_curr,
						mdhdr->frame_data, hdr_offset);
				pr_debug("%s:%d:%d\n", __FUNCTION__, __LINE__, rc);
				printk("hdr_val:%02x\n", *((u16 *) (hdr + md->arg.soff)));
				printk("mddata_val:%02x\n", *((u16 *) frame_curr));
				if (rc != 0) {
					goto parser_error;
				}
			}
		}
#if 0
// TODO
		/* Process node type */
		switch (parse_node->node_type) {
		case PANDA_NODE_TYPE_PLAIN:
		default:
			break;
		case PANDA_NODE_TYPE_TLVS:
			/* Process TLV nodes */
			if (parse_node->proto_node->node_type !=
			    PANDA_NODE_TYPE_TLVS)
				break;

			/* Need error in case parse_node is TLVs type, but
			 * proto_node is not TLVs type
			 */
			ctrl.ret = panda_parse_tlvs(parse_node, hdr,
						    hdr_len, frame,
						    flags, obj_ref,
						    metadata_base,
						    hdr_offset, ctrl,
						    thread_set,
						    &handler_ret);
			switch (ctrl.ret) {
			case PANDA_STOP_OKAY:
				goto parser_okay;
			case PANDA_OKAY:
			case PANDA_STOP_NODE_OKAY:
			case PANDA_STOP_SUB_NODE_OKAY:
				/* Note PANDA_STOP_NODE_OKAY means that
				 * post loop processing is not
				 * performed. Currently, there is no
				 * post loop processing defined for the
				 * parser so this is treated like a
				 * PANDA_OKAY
				 */
				ctrl.ret = PANDA_OKAY;
				break; /* Just go to next node */
			default:
				goto parser_error;
			}
			break;
		case PANDA_NODE_TYPE_FLAG_FIELDS:
			/* Process flag-fields */
			if (parse_node->proto_node->node_type ==
						PANDA_NODE_TYPE_FLAG_FIELDS) {
				/* Need error in case parse_node is flag-fields
				 * type but proto_node is not flag-fields type
				 */
				ctrl.ret = panda_parse_flag_fields(parse_node,
						hdr, hdr_len, frame, flags,
						obj_ref, metadata_base,
						hdr_offset, ctrl, thread_set,
						&handler_ret);
				if (ctrl.ret != PANDA_OKAY)
					goto parser_error;
			}
			break;
		}
#endif
		/* Proceed to next protocol layer */
		if (node->arg.encap) {
			/* New encapsulation layer. Check against
			 * number of encap layers allowed and also
			 * if we need a new metadata frame.
			 */
			if (++mdhdr->encaps > parser->arg.config.max_encaps) {
				rc = PANDA_STOP_ENCAP_DEPTH;
				goto parser_error;
			}

			if (mdhdr->max_frame_num > frame_num) {
				frame_curr += mdhdr->frame_size;
				frame_num++;
			}
		}

		// Lookup associated proto tbl context
		ptbl = node->ptbl_ref;
		// global_htbl_lookup(KPARSER_HTBL_PTBL, &node->arg.prot_tbl_key);
		if (ptbl) {
#if 0
			// TODO
			if (proto_node->ops.cond_exprs_parameterized) {
				int res = eval_cond_exprs(
						&proto_node->ops.cond_exprs,
						hdr);
				if (res < 0) {
					ctrl.ret = res;
					goto parser_error;
				}
			}
#endif
			nxt_proto_map = eval_parameterized_next_proto(
					&ptbl->arg.pkeymap, hdr);
			printk("nxt_proto_map:%u\n", nxt_proto_map);
			if (nxt_proto_map < 0) {
				rc = nxt_proto_map;
				goto parser_error;
			}
			for (i = 0; i < ptbl->ent_tbl_size; i++) {
				pent = &ptbl->ent_tbl[i];
				if (pent->arg.idx_key_map ==
						(__u16) nxt_proto_map) {
					nxtnode = pent->node_ref; 
					#if 0
						global_htbl_lookup(
							KPARSER_HTBL_NODE,
							&pent->arg.node_key);
					#endif
					if (nxtnode == NULL) {
						pr_debug("%s:node lookup failed"
							 " key:{%s:%u}\n",
							 __FUNCTION__,
							pent->arg.node_key.name,
							pent->arg.node_key.id);
						rc = ENOENT;
						goto parser_error;
					}
					goto found_next;
				}
			}
#if 0
			// TODO
			if (!parse_node->wildcard_node) {
				/* Return default code. Parsing will stop
				 * with the inidicated code
				 */
				ctrl.ret = parse_node->unknown_ret;
				goto parser_error;
			}
#endif
		}

#if 0
		// TODO
		if (parse_node->wildcard_node) {
			// Perform default processing in a wildcard node 
			nxtnode = parse_node->wildcard_node;
			goto found_next;
		}
#endif

		/* Leaf parse node */
		goto parser_okay;
found_next:
		/* Found next protocol node, set up to process */
		if (!node->arg.overlay) {
			/* Move over current header */
			hdr += hdr_len;
			parse_len -= hdr_len;
		}

		node = nxtnode;
		continue;

parser_error:
#if 0
		// TODO
		handler = parser->config.fail_func;
		goto final_handler;
#endif
parser_okay:
		if (rc == PANDA_OKAY)
			rc = PANDA_STOP_OKAY;
// TODO: handler remove them later
		// handler = parser->config.okay_func; // TODO
#if 0
final_handler:
		// TODO
		if (!handler)
			return ctrl.ret;


		handler(hdr, hdr_len, frame, obj_ref, metadata_base,
				hdr_offset, ctrl);
#endif
		return rc;
	}
}
#if 0
/* Lookup a type in a node table*/
static const struct panda_parse_node *lookup_node(int type,
				    const struct panda_proto_table *table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (type == table->entries[i].value)
			return table->entries[i].node;

	return NULL;
}

/* Lookup a type in a node TLV table */
static const struct panda_parse_tlv_node *lookup_tlv_node(int type,
				const struct panda_proto_tlvs_table *table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (type == table->entries[i].type)
			return table->entries[i].node;

	return NULL;
}

/* Lookup up a protocol for the table associated with a parse node */
const struct panda_parse_tlv_node *panda_parse_lookup_tlv(
		const struct panda_parse_tlvs_node *node,
		unsigned int type)
{
	return lookup_tlv_node(type, node->tlv_proto_table);
}

/* Lookup a flag-fields index in a protocol node flag-fields table */
static const struct panda_parse_flag_field_node *lookup_flag_field_node(int idx,
				const struct panda_proto_flag_fields_table
								*table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (idx == table->entries[i].index)
			return table->entries[i].node;

	return NULL;
}


static bool eval_cond_exprs_and_table(
		const struct panda_parser_condexpr_table *table, void *hdr)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (!panda_parser_expr_evaluate(&table->entries[i], hdr))
			return false;

	return true;
}

static bool eval_cond_exprs_or_table(
		const struct panda_parser_condexpr_table *table, void *hdr)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (panda_parser_expr_evaluate(&table->entries[i], hdr))
			return true;

	return false;
}


static int eval_cond_exprs(const struct panda_parser_condexpr_tables *tables,
			   void *hdr)
{
	bool res;
	int i;

	for (i = 0; i < tables->num_ents; i++) {
		const struct panda_parser_condexpr_table *table =
							tables->entries[i];

		switch (table->type) {
		case PANDA_PARSER_CONDEXPR_TYPE_OR:
			res = eval_cond_exprs_or_table(table, hdr);
			break;
		case PANDA_PARSER_CONDEXPR_TYPE_AND:
			res = eval_cond_exprs_and_table(table, hdr);
			break;
		}
		if (!res)
			return table->default_fail;
	}

	return PANDA_OKAY;
}


static int panda_parse_one_tlv(
		const struct panda_parse_tlvs_node *parse_tlvs_node,
		const struct panda_parse_tlv_node *parse_tlv_node,
		void *hdr, size_t tlv_len, void *frame, unsigned int flags,
		void *obj_ref, void *metadata_base, size_t tlv_offset,
		struct panda_ctrl_data ctrl,
		struct panda_thread_set *thread_set, int *handler_ret)
{
	const struct panda_proto_tlv_node *proto_tlv_node =
					parse_tlv_node->proto_tlv_node;
	const struct panda_parse_tlv_node_ops *ops;
	int type;

parse_again:

	if (flags & PANDA_F_DEBUG)
		printf("PANDA parsing TLV %s\n", parse_tlv_node->name);

	if (proto_tlv_node && ((tlv_len < proto_tlv_node->min_len) ||
			       (tlv_len > proto_tlv_node->max_len))) {
		/* Treat check length error as an unrecognized TLV */
		parse_tlv_node = parse_tlvs_node->tlv_wildcard_node;
		if (parse_tlv_node)
			goto parse_again;
		else
			return parse_tlvs_node->unknown_tlv_type_ret;
	}

	ops = &parse_tlv_node->tlv_ops;

	if (ops->cond_exprs_parameterized &&
	    eval_cond_exprs(&ops->cond_exprs, hdr) < 0)
		return PANDA_STOP_COMPARE;

	if (ops->check_tlv) {
		int ret = ops->check_tlv(hdr);

		if (ret < 0)
			return ret;
	}

#ifndef PANDA_NO_PARSER_USE_THREADS
	if (flags & PANDA_F_TLV_METADATA_THREAD) {
		if (panda_parser_thread_start_ptr(thread_set,
				&parse_tlv_node->thread_funcs.extract_metadata,
				hdr, tlv_len, frame, NULL, metadata_base,
				tlv_offset, ctrl) != 0)
			return PANDA_STOP_THREADS_FAIL;
	} else
#endif
	if (ops->extract_metadata)
		ops->extract_metadata(hdr, tlv_len, frame,
				      metadata_base, tlv_offset, ctrl);

	if (parse_tlv_node->metadata_table)
		extract_metadata_table(parse_tlv_node->metadata_table,
				       hdr, tlv_len, frame,
					       metadata_base, tlv_offset, ctrl);

#ifndef PANDA_NO_PARSER_USE_THREADS
	if (flags & PANDA_F_TLV_HANDLER_THREAD) {
		if (panda_parser_thread_start_ptr(thread_set,
				&parse_tlv_node->thread_funcs.handle_proto,
				hdr, tlv_len, frame, obj_ref,
				metadata_base, tlv_offset, ctrl) != 0)
			return PANDA_STOP_THREADS_FAIL;
	} else
#endif
	if (ops->handle_tlv &&
	    (handler_ret == PANDA_OKAY || ops->no_kill_handler))
		*handler_ret = ops->handle_tlv(
				hdr, tlv_len, frame, obj_ref,
				metadata_base, tlv_offset, ctrl);

	if (!parse_tlv_node->overlay_table)
		return PANDA_OKAY;

	/* We have an TLV overlay  node */

	if (parse_tlv_node->tlv_ops.overlay_type_parameterized)
		type = eval_parameterized_next_proto(
				&parse_tlv_node->tlv_ops.pfoverlay_type, hdr);
	else if (parse_tlv_node->tlv_ops.overlay_type)
		type = parse_tlv_node->tlv_ops.overlay_type(hdr);
	else
		type = tlv_len;

	/* Get TLV node */
	parse_tlv_node = lookup_tlv_node(type, parse_tlv_node->overlay_table);
	if (parse_tlv_node)
		goto parse_again;

	/* Unknown TLV overlay node */
	parse_tlv_node = parse_tlv_node->overlay_wildcard_node;
	if (parse_tlv_node)
		goto parse_again;

	return parse_tlv_node->unknown_overlay_ret;
}


static int loop_limit_exceeded(int ret, unsigned int disp)
{
	switch (disp) {
	case PANDA_PARSER_LOOP_DISP_STOP_OKAY:
		return PANDA_STOP_OKAY;
	case PANDA_PARSER_LOOP_DISP_STOP_NODE_OKAY:
		return PANDA_STOP_NODE_OKAY;
	case PANDA_PARSER_LOOP_DISP_STOP_SUB_NODE_OKAY:
		return PANDA_STOP_SUB_NODE_OKAY;
	case PANDA_PARSER_LOOP_DISP_STOP_FAIL:
	default:
		return ret;
	}
}

static __u32 eval_get_value(const struct panda_parameterized_get_value *pf,
			    void *hdr)
{
	__u32 ret;

	__panda_parser_metadata_byte_extract(hdr + pf->src_off, (__u8 *)&ret,
					     pf->size, false);

	return ret;
}


static int panda_parse_tlvs(const struct panda_parse_node *parse_node,
			    void *hdr, size_t hdr_len, void *frame,
			    unsigned int flags, void *obj_ref,
			    void *metadata_base, size_t hdr_offset,
			    const struct panda_ctrl_data ctrl,
			    struct panda_thread_set *thread_set,
			    int *handler_ret)
{
	unsigned int loop_cnt = 0, non_pad_cnt = 0, pad_len = 0;
	const struct panda_parse_tlvs_node *parse_tlvs_node;
	const struct panda_proto_tlvs_node *proto_tlvs_node;
	const struct panda_parse_tlv_node *parse_tlv_node;
	struct panda_ctrl_data tlv_ctrl = {};
	size_t off, len, tlv_offset;
	unsigned int consec_pad = 0;
	ssize_t tlv_len;
	__u8 *cp = hdr;
	int type, ret;

	parse_tlvs_node = (struct panda_parse_tlvs_node *)parse_node;
	proto_tlvs_node = (struct panda_proto_tlvs_node *)
						parse_node->proto_node;

	/* Assume hlen marks end of TLVs */
	if (proto_tlvs_node->fixed_start_offset)
		off = proto_tlvs_node->start_offset;
	else if (proto_tlvs_node->ops.len_parameterized)
		off = eval_parameterized_len(
			&proto_tlvs_node->ops.pfstart_offset, cp);
	else
		off = proto_tlvs_node->ops.start_offset(hdr);

	/* We assume start offset is less than or equal to minimal length */
	len = hdr_len - off;

	cp += off;
	tlv_offset = hdr_offset + off;

	while (len > 0) {
		if (++loop_cnt > parse_tlvs_node->config.max_loop)
			return loop_limit_exceeded(PANDA_STOP_LOOP_CNT,
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
				    PANDA_STOP_TLV_PADDING,
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
			return loop_limit_exceeded(PANDA_STOP_TLV_LENGTH,
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
			} else if (proto_tlvs_node->ops.len) {
				tlv_len = proto_tlvs_node->ops.len(cp);
			} else {
				tlv_len = proto_tlvs_node->min_len;
				break;
			}

			if (!tlv_len || len < tlv_len)
				return loop_limit_exceeded(
				    PANDA_STOP_TLV_LENGTH,
				    parse_tlvs_node->config.disp_limit_exceed);

			if (tlv_len < proto_tlvs_node->min_len)
				return loop_limit_exceeded(
				    PANDA_STOP_TLV_LENGTH,
				    parse_tlvs_node->config.disp_limit_exceed);
		} while (0);

		if (proto_tlvs_node->ops.type_parameterized)
			type = eval_parameterized_next_proto(
					&proto_tlvs_node->ops.pftype, cp);
		else
			type = proto_tlvs_node->ops.type(cp);

		if (proto_tlvs_node->padn_enable &&
		    type == proto_tlvs_node->padn_val) {
			/* N byte padding, just advance */
			if ((pad_len += tlv_len) >
					parse_tlvs_node->config.max_plen ||
			    ++consec_pad > parse_tlvs_node->config.max_c_pad)
				return loop_limit_exceeded(
				    PANDA_STOP_TLV_PADDING,
				    parse_tlvs_node->config.disp_limit_exceed);
			goto next_tlv;
		}

		/* Get TLV node */
		parse_tlv_node = lookup_tlv_node(type,
				parse_tlvs_node->tlv_proto_table);
parse_one_tlv:
		if (parse_tlv_node && parse_tlv_node->proto_tlv_node) {
			if (parse_tlv_node->proto_tlv_node->is_padding) {
				if ((pad_len += tlv_len) >
					parse_tlvs_node->config.max_plen ||
					++consec_pad >
					     parse_tlvs_node->config.max_c_pad)
					return loop_limit_exceeded(
				    PANDA_STOP_TLV_PADDING,
				    parse_tlvs_node->config.disp_limit_exceed);
			} else if (++non_pad_cnt >
					parse_tlvs_node->config.max_non) {
				return loop_limit_exceeded(
				    PANDA_STOP_OPTION_LIMIT,
				    parse_tlvs_node->config.disp_limit_exceed);
			}

			ret = panda_parse_one_tlv(parse_tlvs_node,
						  parse_tlv_node,
						  cp, tlv_len, frame,
						  flags, obj_ref,
						  metadata_base,
						  tlv_offset, tlv_ctrl,
						  thread_set, handler_ret);
			if (ret != PANDA_OKAY)
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
			 * PANDA_OKAY means skip
			 */
			if (parse_tlvs_node->unknown_tlv_type_ret !=
			    PANDA_OKAY)
				return
				  parse_tlvs_node->unknown_tlv_type_ret;
		}

		/* Move over current header */
next_tlv:
		cp += tlv_len;
		tlv_offset += tlv_len;
		len -= tlv_len;
	}

	return PANDA_OKAY;
}

static int panda_parse_flag_fields(const struct panda_parse_node *parse_node,
			    void *hdr, size_t hdr_len, void *frame,
			    unsigned int pflags, void *obj_ref,
			    void *metadata_base, size_t hdr_offset,
			    const struct panda_ctrl_data ctrl,
			    struct panda_thread_set *thread_set,
			    int *handler_ret)
{
	const struct panda_parse_flag_fields_node *parse_flag_fields_node;
	const struct panda_proto_flag_fields_node *proto_flag_fields_node;
	const struct panda_parse_flag_field_node *parse_flag_field_node;
	const struct panda_flag_fields *flag_fields;
	ssize_t off, field_len, field_offset;
	__u32 flags;
	int i;

	parse_flag_fields_node =
			(struct panda_parse_flag_fields_node *)parse_node;
	proto_flag_fields_node =
			(struct panda_proto_flag_fields_node *)
						parse_node->proto_node;
	flag_fields = proto_flag_fields_node->flag_fields;

	if (proto_flag_fields_node->ops.get_flags_parameterized)
		flags = eval_get_value(
			&proto_flag_fields_node->ops.pfget_flags, hdr);
	else
		flags = proto_flag_fields_node->ops.get_flags(hdr);

	/* Position at start of field data */
	if (proto_flag_fields_node->ops.start_fields_offset_parameterized)
		off = eval_parameterized_len(
			&proto_flag_fields_node->ops.pfstart_fields_offset,
			hdr);
	else
		off = proto_flag_fields_node->ops.start_fields_offset(hdr);
	hdr += off;
	hdr_offset += off;

	for (i = 0; i < flag_fields->num_idx; i++) {
		off = panda_flag_fields_offset(i, flags, flag_fields);
		if (off < 0)
			continue;

		/* Flag field is present, try to find in the parse node
		 * table based on index in proto flag-fields
		 */
		parse_flag_field_node = lookup_flag_field_node(i,
			parse_flag_fields_node->flag_fields_proto_table);
		if (parse_flag_field_node) {
			const struct panda_parse_flag_field_node_ops
				*ops = &parse_flag_field_node->ops;
			struct panda_ctrl_data flag_ctrl = {};
			__u8 *cp = hdr + off;

			field_len = flag_fields->fields[i].size;
			field_offset = hdr_offset + off;

			if (pflags & PANDA_F_DEBUG)
				printf("PANDA parsing flag-field %s\n",
				      parse_flag_field_node->name);

			if (ops->cond_exprs_parameterized &&
			    eval_cond_exprs(&ops->cond_exprs, cp) < 0)
				return PANDA_STOP_COMPARE;

			if (ops->check_flag_field) {
				int ret = ops->check_flag_field(cp);

				if (ret < 0)
					return ret;
			}
#ifndef PANDA_NO_PARSER_USE_THREADS
			if (flags & PANDA_F_FLAG_FIELDS_METADATA_THREAD) {
				if (panda_parser_thread_start_ptr(thread_set,
				    &parse_flag_field_node->
					thread_funcs.extract_metadata,
				    cp, field_len, frame, NULL, metadata_base,
				    field_offset, ctrl) != 0)
					return PANDA_STOP_THREADS_FAIL;
			} else
#endif
			if (ops->extract_metadata)
				ops->extract_metadata(cp, field_len, frame,
						      metadata_base,
						      field_offset, ctrl);

			if (parse_flag_field_node->metadata_table)
				extract_metadata_table(
					parse_flag_field_node->metadata_table,
					cp, field_len, frame,
					metadata_base, field_offset, ctrl);

#ifndef PANDA_NO_PARSER_USE_THREADS
			if (flags & PANDA_F_FLAG_FIELDS_HANDLER_THREAD) {
				if (panda_parser_thread_start_ptr(thread_set,
				    &parse_flag_field_node->
					thread_funcs.handle_proto,
				    hdr, field_len, frame, obj_ref,
				    metadata_base, field_offset, ctrl) != 0)
					return PANDA_STOP_THREADS_FAIL;
			} else
#endif
			if (ops->handle_flag_field &&
			    (*handler_ret == PANDA_OKAY ||
			     ops->no_kill_handler))
				*handler_ret = ops->handle_flag_field(
						cp, field_len, frame, obj_ref,
						metadata_base, field_offset,
						flag_ctrl);
		}
	}

	return PANDA_OKAY;
}
#endif
