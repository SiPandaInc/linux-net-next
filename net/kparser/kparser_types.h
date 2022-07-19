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

#ifndef __KPARSER_TYPES_H
#define __KPARSER_TYPES_H

#include <linux/hash.h>
#include <linux/kparser.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/rhashtable-types.h>
#include <linux/skbuff.h>
#include <linux/xxhash.h>

/* Panda parser return codes
 *
 * There are two variants of the KPARSER return codes. The normal variant is
 * a number between -15 and 0 inclusive where the name for the code is
 * prefixed by KPARSER_. There is also a special 16-bit encoding which is
 * 0xfff0 + -val where val is the negative number for the code so that
 * corresponds to values 0xfff0 to 0xffff. Names for the 16-bit encoding
 * are prefixed by KPARSER_16BIT_
 */

/* Sign extend an returned signed value */
#define KPARSER_EXTRACT_CODE(X) ((__s64)(short)(X))

#define KPARSER_IS_RET_CODE(X) (KPARSER_EXTRACT_CODE(X) < 0)

#define KPARSER_IS_NOT_OK_CODE(X)					\
	(KPARSER_EXTRACT_CODE(X) <= KPARSER_STOP_FAIL)

#define KPARSER_IS_OK_CODE(X)					\
	(KPARSER_IS_RET_CODE(X) &&					\
	 KPARSER_EXTRACT_CODE(X) >	KPARSER_STOP_FAIL)

/* Two bit code that describes the action to take when a loop node
 * exceeds a limit
 */
enum {
	KPARSER_LOOP_DISP_STOP_OKAY = 0,
	KPARSER_LOOP_DISP_STOP_NODE_OKAY = 1,
	KPARSER_LOOP_DISP_STOP_SUB_NODE_OKAY = 2,
	KPARSER_LOOP_DISP_STOP_FAIL = 3,
};

static inline __u64 kparser_ins32_disp_to_code(unsigned int disp)
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
		return KPARSER_STOP_FAIL;
	}
}

/* A table of conditional expressions, type indicates that the expressions
 * are or'ed of and'ed
 */
struct kparser_condexpr_table {
	int default_fail;
	enum kparser_condexpr_types type;
	unsigned int num_ents;
	const struct kparser_condexpr_expr __rcu *entries;
};

/* A table of tables of conditional expressions. This is used to create more
 * complex expressions using and's and or's
 */
struct kparser_condexpr_tables {
	unsigned int num_ents;
	const struct kparser_condexpr_table __rcu **entries;
};

/* Protocol parsing operations:
 *
 * Operations can be specified either as a function or a parameterization
 * of a parameterized function
 *
 * len: Return length of protocol header. If value is NULL then the length of
 *	the header is taken from the min_len in the protocol node. If the
 *	return value < 0 (a KPARSER_STOP_* return code value) this indicates an
 *	error and parsing is stopped. A the return value greater than or equal
 *	to zero then gives the protocol length. If the returned length is less
 *	than the minimum protocol length, indicated in min_len by the protocol
 *	node, then this considered and error.
 * next_proto: Return next protocol. If value is NULL then there is no
 *	next protocol. If return value is greater than or equal to zero
 *	this indicates a protocol number that is used in a table lookup
 *	to get the next layer protocol node.
 * cond_exprs: Parameterization only. This describes a set of conditionals
 *	check before proceeding. In the case of functions being used, these
 *	conditionals would be in the next_proto or length function
 */

struct kparser_parse_ops {
	bool flag_fields_length;
	bool len_parameterized;
	struct kparser_parameterized_len pflen;
	bool next_proto_parameterized;
	struct kparser_parameterized_next_proto pfnext_proto;
	bool cond_exprs_parameterized;
	struct kparser_condexpr_tables cond_exprs;
};

/* Protocol node
 *
 * This structure contains the definitions to describe parsing of one type
 * of protocol header. Fields are:
 *
 * node_type: The type of the node (plain, TLVs, flag-fields)
 * encap: Indicates an encapsulation protocol (e.g. IPIP, GRE)
 * overlay: Indicates an overlay protocol. This is used, for example, to
 *	switch on version number of a protocol header (e.g. IP version number
 *	or GRE version number)
 * name: Text name of protocol node for debugging
 * min_len: Minimum length of the protocol header
 * ops: Operations to parse protocol header
 */
struct kparser_proto_node {
	enum kparser_node_type node_type;
	__u8 encap;
	__u8 overlay;
	char name[KPARSER_MAX_NAME];
	size_t min_len;
	struct kparser_parse_ops ops;
};

/* Control data describing various values produced while parsing. This is
 * used an argument to metadata extraction and handler functions
 */
struct kparser_ctrl_data {
	int ret;
	size_t pkt_len;
	__u16 pkt_csum;
	__u16 hdr_csum;
	void *hdr_base;
	unsigned int node_cnt;
	unsigned int encap_levels;
};

/* Protocol node and parse node operations ordering. When processing a
 * layer, operations are called in following order:
 *
 * protoop.len
 * parseop.extract_metadata
 * parseop.handle_proto
 * protoop.next_proto
 */

struct kparser_parse_node;

/* One entry in a protocol table:
 *	value: protocol number
 *	node: associated parse node for the protocol number
 */
struct kparser_proto_table_entry {
	int value;
	const struct kparser_parse_node __rcu *node;
};

/* Protocol table
 *
 * Contains a protocol table that maps a protocol number to a parse
 * node
 */
struct kparser_proto_table {
	int num_ents;
	struct kparser_proto_table_entry __rcu *entries;
};

struct kparser_metadata_table;

/* Parse node definition. Defines parsing and processing for one node in
 * the parse graph of a parser. Contains:
 *
 * node_type: The type of the node (plain, TLVs, flag-fields)
 * unknown_ret: Code to return for a miss on the protocol table and the
 *	wildcard node is not set
 * proto_node: Protocol node
 * ops: Parse node operations
 * proto_table: Protocol table for next protocol. This must be non-null if
 *	next_proto is not NULL
 * wildcard_node: Node use for a miss on next protocol lookup
 * metadata_table: Table of parameterized metadata operations
 * thread_funcs: Thread functions
 */
struct kparser_parse_node {
	enum kparser_node_type node_type;
	int unknown_ret;
	const struct kparser_proto_node __rcu *proto_node;
	const struct kparser_proto_table __rcu *proto_table;
	const struct kparser_parse_node __rcu *wildcard_node;
	const struct kparser_metadata_table __rcu *metadata_table;
};

/* Definition of a KPARSER parser. Fields are:
 *
 * name: Text name for the parser
 * root_node: Root parse node of the parser. When the parser is invoked
 *	parsing commences at this parse node
 * okay_node: Processed at parser exit if no error
 * fail_node: Processed at parser exit if there was an error
 * parser_type: e.g. KPARSER_GENERIC, KPARSER_OPTIMIZED, KPARSER_KMOD, KPARSER_XDP
 * parser_entry_point: Function entry point for optimized parser
 * parser_xdp_entry_point: Function entry point for XDP parser
 * config: Parser conifguration
 */
struct kparser_parser {
	char name[KPARSER_MAX_NAME];
	const struct kparser_parse_node __rcu *root_node;
	const struct kparser_parse_node __rcu *okay_node;
	const struct kparser_parse_node __rcu *fail_node;
	struct kparser_config config;
};

static inline bool kparser_proto_node_convert(
		const struct kparser_conf_node_proto *conf,
		struct kparser_proto_node *node)
{
	node->node_type = KPARSER_NODE_TYPE_PLAIN;
	node->encap = conf->encap;
	node->overlay = conf->overlay;
	strcpy(node->name, conf->key.name);
	node->min_len = conf->min_len;
	node->ops.flag_fields_length = conf->ops.flag_fields_length;
	node->ops.next_proto_parameterized = conf->ops.next_proto_parameterized;
	node->ops.cond_exprs_parameterized = conf->ops.cond_exprs_parameterized;
	node->ops.pflen = conf->ops.pflen;
	node->ops.pfnext_proto = conf->ops.pfnext_proto;

	return true;
}

static inline bool kparser_parse_node_convert(
		const struct kparser_conf_node_parse *conf,
		struct kparser_parse_node *node,
		const struct kparser_proto_node *proto_node,
		const struct kparser_proto_table *proto_table,
		const struct kparser_parse_node *wildcard_node,
		const struct kparser_metadata_table *metadata_table)
{
	node->node_type = KPARSER_NODE_TYPE_PLAIN;
	rcu_assign_pointer(node->proto_node, proto_node);
	rcu_assign_pointer(node->proto_table, proto_table);
	rcu_assign_pointer(node->wildcard_node, wildcard_node);
	rcu_assign_pointer(node->metadata_table, metadata_table);
	return true;
}

static inline bool kparser_parser_convert(
		const struct kparser_conf_parser *conf,
		struct kparser_parser *parser,
		const struct kparser_parse_node *root_node,
		const struct kparser_parse_node *ok_node,
		const struct kparser_parse_node *fail_node)
{
	strcpy(parser->name, conf->key.name);
	rcu_assign_pointer(parser->root_node, root_node);
	rcu_assign_pointer(parser->okay_node, ok_node);
	rcu_assign_pointer(parser->fail_node, fail_node);
	parser->config = conf->config;
	return true;
}

#endif /* __KPARSER_TYPES_H */
