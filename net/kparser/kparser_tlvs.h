/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020,2021 SiPanda Inc.
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

#ifndef __KPARSER_TLVS_H
#define __KPARSER_TLVS_H

#include "kparser_types.h"

/* Definitions for parsing TLVs
 *
 * Operations can be specified either as a function or a parameterization
 * of a parameterized function
 *
 * TLVs are a common protocol header structure consisting of Type, Length,
 * Value tuple (e.g. for handling TCP or IPv6 HBH options TLVs)
 */

/* TLV parse node operations
 *
 * Operations to process a single TLV
 *
 * Operations can be specified either as a function or a parameterization
 * of a parameterized function
 *
 * extract_metadata: Extract metadata for the node. Input is the meta
 *	data frame which points to a parser defined metadata structure.
 *	If the value is NULL then no metadata is extracted
 * handle_tlv: Per TLV type handler which allows arbitrary processing
 *	of a TLV. Input is the TLV data and a parser defined metadata
 *	structure for the current frame. Return value is a parser
 *	return code: KPARSER_OKAY indicates no errors, KPARSER_STOP* return
 *	values indicate to stop parsing
 * check_tlv: Function to validate a TLV
 * cond_exprs: Parameterization of a set of conditionals to check before
 *	proceeding. In the case of functions being used, these
 *      conditionals would be in the check_tlv function
 */


/* Parse node for a single TLV. Use common parse node operations
 * (extract_metadata and handle_proto)
 *
 * proto_tlv_node: TLV protocol node
 * tlv_ops: Operations on a TLV
 * overlay_table: Lookup table for an overlay TLV
 * overlay_wildcard_node: Wildcard node to an overlay lookup miss
 * unknown_overlay_ret: Code to return on an overlay lookup miss and
 *	overlay_wildcard_node is NULL
 * name: Name for debugging
 * metadata_table: Table of parameterized metadata operations
 * thread_funcs: Thread functions
 */
struct kparser_parse_tlv_node {
	const struct kparser_proto_tlv_node __rcu *proto_tlv_node;
	const struct kparser_proto_tlvs_table __rcu *overlay_table;
	const struct kparser_parse_tlv_node __rcu *overlay_wildcard_node;
	int unknown_overlay_ret;
	const char name[KPARSER_MAX_NAME];
	const struct kparser_metadata_table __rcu *metadata_table;
};

/* One entry in a TLV table:
 *	type: TLV type
 *	node: associated TLV parse structure for the type
 */
struct kparser_proto_tlvs_table_entry {
	int type;
	const struct kparser_parse_tlv_node __rcu *node;
};

/* TLV table
 *
 * Contains a table that maps a TLV type to a TLV parse node
 */
struct kparser_proto_tlvs_table {
	int num_ents;
	const struct kparser_proto_tlvs_table_entry *entries;
};


/* Parse node for parsing a protocol header that contains TLVs to be
 * parser:
 *
 * parse_node: Node for main protocol header (e.g. IPv6 node in case of HBH
 *	options) Note that node_type is set in parse_node to
 *	KPARSER_NODE_TYPE_TLVS and that the parse node can then be cast to a
 *	parse_tlv_node
 * tlv_proto_table: Lookup table for TLV type
 * unknown_tlv_type_ret: Code to return on a TLV type lookup miss and
 *	tlv_wildcard_node is NULL
 * tlv_wildcard_node: Node to use on a TLV type lookup miss
 * config: Loop configuration
 */
struct kparser_parse_tlvs_node {
	const struct kparser_parse_node parse_node;
	const struct kparser_proto_tlvs_table __rcu *tlv_proto_table;
	int unknown_tlv_type_ret;
	const struct kparser_parse_tlv_node __rcu *tlv_wildcard_node;
	const struct kparser_loop_node_config config;
};

/* A protocol node for parsing proto with TLVs
 *
 * proto_node: proto node
 * ops: Operations for parsing TLVs
 * start_offset: When there TLVs start relative the enapsulating protocol
 *	(e.g. would be twenty for TCP)
 * pad1_val: Type value indicating one byte of TLV padding (e.g. would be
 *	for IPv6 HBH TLVs)
 * pad1_enable: Pad1 value is used to detect single byte padding
 * eol_val: Type value that indicates end of TLV list
 * eol_enable: End of list value in eol_val is used
 * fixed_start_offset: Take start offset from start_offset
 * min_len: Minimal length of a TLV option
 */
struct kparser_proto_tlvs_node {
	struct kparser_proto_node proto_node;
	struct kparser_proto_tlvs_opts ops;
	size_t start_offset;
	__u8 pad1_val;
	__u8 padn_val;
	__u8 eol_val;
	bool pad1_enable;
	bool padn_enable;
	bool eol_enable;
	bool fixed_start_offset;
	size_t min_len;
};

struct kparser_proto_tlv_node_ops {
	const struct kparser_parameterized_next_proto pfoverlay_type;
	const struct kparser_condexpr_tables cond_exprs;
};

/* A protocol node for parsing proto with TLVs
 *
 * min_len: Minimal length of TLV
 * max_len: Maximum size of a TLV option
 * is_padding: Indicates padding TLV
 */
struct kparser_proto_tlv_node {
	size_t min_len;
	size_t max_len;
	bool is_padding;
	struct kparser_proto_tlv_node_ops ops;
};

#define __KPARSER_TLVS_CONFIG_DEFAULTS()				\
	.config.max_loop = KPARSER_DEFAULT_TLV_MAX_LOOP,		\
	.config.max_non = KPARSER_DEFAULT_TLV_MAX_NON_PADDING,	\
	.config.max_plen =						\
			KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_BYTES,	\
	.config.max_c_pad =						\
			KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_OPTS,	\
	.config.disp_limit_exceed =					\
			KPARSER_DEFAULT_TLV_DISP_LIMIT_EXCEED,	\
	.config.exceed_loop_cnt_is_err =				\
			KPARSER_DEFAULT_TLV_EXCEED_LOOP_CNT_ERR,

/* Look up a TLV parse node given
 *
 * Arguments:
 *	- node: A TLVs parse node containing lookup table
 *	- type: TLV type to lookup
 *
 * Returns pointer to parse node if the protocol is matched else returns
 * NULL if the parse node isn't found
 */
const struct kparser_parse_tlv_node *kparser_parse_lookup_tlv(
				const struct kparser_parse_tlvs_node *node,
				unsigned int type);

/* Helper to create a TLV protocol table */
#define KPARSER_MAKE_TLV_TABLE(NAME, ...)					\
	static const struct kparser_proto_tlvs_table_entry __##NAME[] =	\
						{ __VA_ARGS__ };	\
	static const struct kparser_proto_tlvs_table NAME = {		\
		.num_ents = sizeof(__##NAME) /				\
			sizeof(struct kparser_proto_tlvs_table_entry),	\
		.entries = __##NAME,					\
	}

/* Forward declarations for TLV parser nodes */
#define KPARSER_DECL_TLVS_PARSE_NODE(TLVS_PARSE_NODE)			\
	static const struct kparser_parse_tlvs_node TLVS_PARSE_NODE

/* Forward declarations for TLV type tables */
#define KPARSER_DECL_TLVS_TABLE(TLVS_TABLE)				\
	static const struct kparser_proto_tlvs_table TLVS_TABLE

#define __KPARSER_TLVS_CONFIG_ENTRIES(PARSE_TLV_NODE,		\
					   PROTO_TLV_NODE,		\
					   EXTRACT_METADATA, HANDLER,	\
					   HANDLER_BLOCKERS,		\
					   HANDLER_WATCHERS,		\
					   POST_HANDLER,		\
					   POST_HANDLER_BLOCKERS,	\
					   POST_HANDLER_WATCHERS,	\
					   UNKNOWN_RET,			\
					   WILDCARD_NODE,		\
					   UNKNOWN_TLV_TYPE_RET,	\
					   TLV_WILDCARD_NODE,		\
					   PROTO_TABLE, TLV_TABLE,	\
					   METADATA_TABLE)		\
		.parse_node.node_type = KPARSER_NODE_TYPE_TLVS,		\
		.parse_node.proto_node = PROTO_TLV_NODE.proto_node,	\
		.parse_node.ops.extract_metadata = EXTRACT_METADATA,	\
		.parse_node.ops.handle_proto.func = HANDLER,		\
		.parse_node.ops.handle_proto.blockers =			\
					HANDLER_BLOCKERS,		\
		.parse_node.ops.handle_proto.watchers =			\
					HANDLER_WATCHERS,		\
		.parse_node.ops.post_handle_proto.func = POST_HANDLER,	\
		.parse_node.ops.post_handle_proto.blockers =		\
					POST_HANDLER_BLOCKERS,		\
		.parse_node.ops.post_handle_proto.watchers =		\
					POST_HANDLER_WATCHERS,		\
		.parse_node.unknown_ret = UNKNOWN_RET,			\
		.parse_node.wildcard_node = WILDCARD_NODE,		\
		.parse_node.proto_table = PROTO_TABLE,			\
		.parse_node.metadata_table = METADATA_TABLE,		\
		.tlv_proto_table = TLV_TABLE,				\
		.unknown_tlv_type_ret = UNKNOWN_TLV_TYPE_RET,		\
		.tlv_wildcard_node = TLV_WILDCARD_NODE,

/* Helper to create a parse node with a next protocol table */
#define __KPARSER_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
				     EXTRACT_METADATA, HANDLER,		\
				     HANDLER_BLOCKERS, HANDLER_WATCHERS,\
				     POST_HANDLER,			\
				     POST_HANDLER_BLOCKERS,		\
				     POST_HANDLER_WATCHERS,		\
				     UNKNOWN_RET, WILDCARD_NODE,	\
				     UNKNOWN_TLV_TYPE_RET,		\
				     TLV_WILDCARD_NODE,			\
				     PROTO_TABLE, TLV_TABLE,		\
				     METADATA_TABLE)			\
	__KPARSER_MAKE_THREAD_FUNCS(PARSE_TLV_NODE,,		\
					 EXTRACT_METADATA,		\
					 HANDLER, HANDLER_BLOCKERS,	\
					 HANDLER_WATCHERS,		\
					 POST_HANDLER,			\
					 POST_HANDLER_BLOCKERS,		\
					 POST_HANDLER_WATCHERS);	\
	static const struct kparser_parse_tlvs_node PARSE_TLV_NODE = {	\
		__KPARSER_TLVS_CONFIG_ENTRIES(PARSE_TLV_NODE,	\
			PROTO_TLV_NODE, EXTRACT_METADATA, HANDLER,	\
			HANDLER_BLOCKERS, HANDLER_WATCHERS,		\
			POST_HANDLER, POST_HANDLER_BLOCKERS,		\
			POST_HANDLER_WATCHERS, UNKNOWN_RET,		\
			WILDCARD_NODE, UNKNOWN_TLV_TYPE_RET,		\
			TLV_WILDCARD_NODE,				\
			PROTO_TABLE, TLV_TABLE, METADATA_TABLE)		\
		__KPARSER_TLVS_CONFIG_DEFAULTS()			\
		.parse_node.thread_funcs =				\
			__KPARSER_SET_THREAD_FUNCS(PARSE_TLV_NODE)	\
	}

/* KPARSER_MAKE_TLVS_PARSE_NODE_CONF allows complete specification of a
 * TLVs parse node including limits. Note that there are not _CONF variants
 * of KPARSER_MAKE_TLVS_OVERLAY_PARSE_NODE_CONF nor
 * KPARSER_MAKE_LEAF_TLVS_PARSE_NODE. An overlay node can be created
 * with a configuration by calling KPARSER_MAKE_TLVS_PARSE_NODE_CONF and
 * setting wildcard to the overlay node and the proto table to NULL.
 * A leaf node with configuration can be created with a configuration by
 * using KPARSER_MAKE_TLVS_PARSE_NODE_CONF and setting proto table and
 * wildcard nodes to NULL
 */
#define KPARSER_MAKE_TLVS_PARSE_NODE_CONF(PARSE_TLV_NODE,			\
					PROTO_TLV_NODE,			\
					EXTRACT_METADATA, HANDLER,	\
					HANDLER_BLOCKERS,		\
					HANDLER_WATCHERS,		\
					POST_HANDLER,			\
					POST_HANDLER_BLOCKERS,		\
					POST_HANDLER_WATCHERS,		\
					UNKNOWN_RET, WILDCARD_NODE,	\
					UNKNOWN_TLV_TYPE_RET,		\
					TLV_WILDCARD_NODE,		\
					PROTO_TABLE, TLV_TABLE,		\
					METADATA_TABLE,			\
					MAX_LOOP, MAX_NON,		\
					MAX_PLEN, MAX_C_PAD,		\
					DISP_LIMIT_EXCEED,		\
					EXCEED_LOOP_CNT_IS_ERR)		\
									\
	__KPARSER_MAKE_THREAD_FUNCS(NAME,,				\
					 EXTRACT_METADATA,		\
					 HANDLER, HANDLER_BLOCKERS,	\
					 HANDLER_WATCHERS,		\
					 POST_HANDLER,			\
					 POST_HANDLER_BLOCKERS,		\
					 POST_HANDLER_WATCHERS);	\
									\
	static const struct kparser_parse_tlvs_node PARSE_TLV_NODE = {	\
		__KPARSER_TLVS_CONFIG_ENTRIES(PARSE_TLV_NODE,	\
			PROTO_TLV_NODE, EXTRACT_METADATA, HANDLER,	\
			HANDLER_BLOCKERS, HANDLER_WATCHERS,		\
			POST_HANDLER, POST_HANDLER_BLOCKERS,		\
			POST_HANDLER_WATCHERS, UNKNOWN_RET,		\
			WILDCARD_NODE, UNKNOWN_TLV_TYPE_RET,		\
			TLV_WILDCARD_NODE, PROTO_TABLE, TLV_TABLE,	\
			METADATA_TABLE)					\
		.config.max_loop = MAX_LOOP,				\
		.config.max_non = MAX_NON,				\
		.config.max_plen = MAX_PLEN,				\
		.config.max_c_pad = MAX_C_PAD,				\
		.config.disp_limit_exceed = DISP_LIMIT_EXCEED,		\
		.config.exceed_cnt_is_err = EXCEED_LOOP_CNT_IS_ERR,	\
		.config.thread_funcs =					\
			__KPARSER_SET_THREAD_FUNCS(NAME)		\
	}

/* Helper to create a TLVs parse node with default unknown next proto
 * function that returns parse failure code and default unknown TLV
 * function that ignores unknown TLVs
 */
#define KPARSER_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
				   EXTRACT_METADATA, HANDLER,		\
				   POST_HANDLER, PROTO_TABLE,		\
				   TLV_TABLE)				\
	KPARSER_DECL_TLVS_TABLE(TLV_TABLE);				\
	KPARSER_DECL_PROTO_TABLE(PROTO_TABLE)				\
	__KPARSER_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE,			\
				    &(PROTO_NODE).pnode,		\
				    EXTRACT_METADATA, HANDLER, 0, 0,	\
				    POST_HANDLER, 0, 0,			\
				    KPARSER_STOP_UNKNOWN_PROTO, NULL,	\
				    KPARSER_OKAY, NULL,			\
				    &PROTO_TABLE, &TLV_TABLE, NULL)

/* Helper to create a TLVs parse node with default unknown next proto
 * function that returns parse failure code and default unknown TLV
 * function that ignores unknown TLVs
 */
#define KPARSER_MAKE_TLVS_OVERLAY_PARSE_NODE(PARSE_TLV_NODE,		\
					   PROTO_TLV_NODE,		\
					   EXTRACT_METADATA, HANDLER,	\
					   POST_HANDLER, OVERLAY_NODE,	\
					   TLV_TABLE)			\
	KPARSER_DECL_TLVS_TABLE(TLV_TABLE);				\
	__KPARSER_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE,			\
				    &(PROTO_NODE).pnode,		\
				    EXTRACT_METADATA, HANDLER, 0, 0,	\
				    POST_HANDLER, 0, 0,			\
				    KPARSER_STOP_UNKNOWN_PROTO,		\
				    OVERLAY_NODE, KPARSER_OKAY, NULL,	\
				    NULL, &TLV_TABLE, NULL)

/* Helper to create a leaf TLVs parse node with default unknown TLV
 * function that ignores unknown TLVs
 */
#define KPARSER_MAKE_LEAF_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
					EXTRACT_METADATA, HANDLER,	\
					POST_HANDLER, TLV_TABLE)	\
	KPARSER_DECL_TLVS_TABLE(TLV_TABLE);				\
	__KPARSER_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE, &PROTO_TLV_NODE,	\
				     EXTRACT_METADATA, HANDLER, 0, 0,	\
				     POST_HANDLER, 0, 0,		\
				     KPARSER_STOP_UNKNOWN_PROTO, NULL,	\
				     KPARSER_OKAY, NULL,			\
				     NULL, &TLV_TABLE, NULL)

#define __KPARSER_MAKE_TLV_PARSE_NODE(NODE_NAME, PROTO_TLV_NODE,		\
				    EXTRACT_METADATA, HANDLER,		\
				    HANDLER_BLOCKERS, HANDLER_WATCHERS,	\
				    OVERLAY_TABLE,			\
				    UNKNOWN_OVERLAY_RET,		\
				    OVERLAY_WILDCARD_NODE,		\
				    METADATA_TABLE)			\
	__KPARSER_MAKE_THREAD_FUNCS(NODE_NAME,, EXTRACT_METADATA,	\
					 HANDLER, HANDLER_BLOCKERS,	\
					 HANDLER_WATCHERS, NULL, 0, 0);	\
	static const struct kparser_parse_tlv_node NODE_NAME = {		\
		.name = #NODE_NAME,					\
		.proto_tlv_node = PROTO_TLV_NODE,			\
		.unknown_overlay_ret = UNKNOWN_OVERLAY_RET,		\
		.overlay_wildcard_node = OVERLAY_WILDCARD_NODE,		\
		.overlay_table = OVERLAY_TABLE,				\
		.metadata_table = METADATA_TABLE,			\
		.thread_funcs =						\
		    __KPARSER_SET_THREAD_FUNCS(NODE_NAME),		\
	}

#define KPARSER_MAKE_TLV_PARSE_NODE(NODE_NAME, PROTO_TLV_NODE,		\
				  METADATA_FUNC, HANDLER_FUNC)		\
	__KPARSER_MAKE_TLV_PARSE_NODE(NODE_NAME, &PROTO_TLV_NODE,	\
				    METADATA_FUNC, HANDLER_FUNC, 0, 0,	\
				    NULL, KPARSER_STOP_FAIL,		\
				    NULL, NULL)

#define KPARSER_MAKE_TLV_OVERLAY_PARSE_NODE(NODE_NAME,			\
					  METADATA_FUNC, HANDLER_FUNC,	\
					  OVERLAY_TABLE,		\
					  UNKNOWN_OVERLAY_RET,		\
					  OVERLAY_WILDCARD_NODE)	\
	KPARSER_DECL_TLVS_TABLE(OVERLAY_TABLE);				\
	__KPARSER_MAKE_TLV_PARSE_NODE(NODE_NAME, NULL,			\
				    METADATA_FUNC, HANDLER_FUNC,	\
				    0, 0, &OVERLAY_TABLE,		\
				    UNKNOWN_OVERLAY_RET,		\
				    OVERLAY_WILDCARD_NODE, NULL)


#endif /* __KPARSER_TLVS_H */
