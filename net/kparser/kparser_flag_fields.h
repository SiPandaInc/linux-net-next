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

#ifndef __KPARSER_FLAG_FIELDS_H
#define __KPARSER_FLAG_FIELDS_H

/* Definitions and functions for processing and parsing flag-fields */

#include "kparser_types.h"

/* Definitions for parsing flag-fields
 *
 * Flag-fields is a common networking protocol construct that encodes optional
 * data in a set of flags and data fields. The flags indicate whether or not a
 * corresponding data field is present. The data fields are fixed length per
 * each flag-field definition and ordered by the ordering of the flags
 * indicating the presence of the fields (e.g. GRE and GUE employ flag-fields)
 */

/* Flag-fields descriptors and tables
 *
 * A set of flag-fields is defined in a table of type struct kparser_flag_fields.
 * Each entry in the table is a descriptor for one flag-field in a protocol and
 * includes a flag value, mask (for the case of a multi-bit flag), and size of
 * the cooresponding field. A flag is matched if "(flags & mask) == flag"
 */

/* One descriptor for a flag
 *
 * flag: protocol value
 * mask: mask to apply to field
 * size: size for associated field data
 */
struct kparser_flag_field {
	__u32 flag;
	__u32 mask;
	size_t size;
};

/* Descriptor for a protocol field with flag fields
 *
 * Defines the flags and their data fields for one instance a flag field in
 * in a protocol header (e.g. GRE v0 flags):
 *
 * num_idx: Number of flag_field structures
 * fields: List of defined flag fields
 */
struct kparser_flag_fields {
	size_t num_idx;
	struct kparser_flag_field fields[];
};

/* Compute the length of optional fields present in a flags field */
static inline size_t kparser_flag_fields_length(__u32 flags,
						const struct kparser_flag_fields
						*flag_fields)
{
	size_t len = 0;
	__u32 mask;
	int i;

	for (i = 0; i < flag_fields->num_idx; i++) {
		mask = flag_fields->fields[i].mask ? :
						flag_fields->fields[i].flag;

		if ((flags & mask) == flag_fields->fields[i].flag)
			len += flag_fields->fields[i].size;
	}

	return len;
}

static inline ssize_t __kparser_flag_fields_offset(__u32 targ_idx, __u32 flags,
						   const struct kparser_flag_fields
						   *flag_fields)
{
	size_t offset = 0;
	__u32 mask;
	int i;

	for (i = 0; i < targ_idx; i++) {
		mask = flag_fields->fields[i].mask ? :
						flag_fields->fields[i].flag;

		if ((flags & mask) == flag_fields->fields[i].flag)
			offset += flag_fields->fields[i].size;
	}

	return offset;
}

/* Determine offset of a field given a set of flags */
static inline ssize_t kparser_flag_fields_offset(__u32 targ_idx, __u32 flags,
						 const struct kparser_flag_fields
						 *flag_fields)
{
	__u32 mask;

	mask = flag_fields->fields[targ_idx].mask ? :
				flag_fields->fields[targ_idx].flag;
	if ((flags & mask) != flag_fields->fields[targ_idx].flag) {
		/* Flag not set */
		return -1;
	}

	return __kparser_flag_fields_offset(targ_idx, flags, flag_fields);
}

/* Check flags are legal */
static inline bool kparser_flag_fields_check_invalid(__u32 flags, __u32 mask)
{
	return !!(flags & ~mask);
}

/* Retrieve a byte value from a flag field */
static inline __u8 kparser_flag_fields_get8(const __u8 *fields, __u32 targ_idx,
					    __u32 flags,
					  const struct kparser_flag_fields
							*flag_fields)
{
	ssize_t offset = kparser_flag_fields_offset(targ_idx, flags,
						    flag_fields);

	if (offset < 0)
		return 0;

	return *(__u8 *)&fields[offset];
}

/* Retrieve a short value from a flag field */
static inline __u16 kparser_flag_fields_get16(const __u8 *fields,
					    __u32 targ_idx,
					    __u32 flags,
					    const struct kparser_flag_fields
					    *flag_fields)
{
	ssize_t offset = kparser_flag_fields_offset(targ_idx, flags, flag_fields);

	if (offset < 0)
		return 0;

	return *(__u16 *)&fields[offset];
}

/* Retrieve a 32 bit value from a flag field */
static inline __u32 kparser_get_flag_field32(const __u8 *fields, __u32 targ_idx,
					     __u32 flags,
					     const struct kparser_flag_fields
					     *flag_fields)
{
	ssize_t offset = kparser_flag_fields_offset(targ_idx, flags, flag_fields);

	if (offset < 0)
		return 0;

	return *(__u32 *)&fields[offset];
}

/* Retrieve a 64 bit value from a flag field */
static inline __u64 kparser_get_flag_field64(const __u8 *fields, __u32 targ_idx,
					     __u32 flags,
					     const struct kparser_flag_fields
					     *flag_fields)
{
	ssize_t offset = kparser_flag_fields_offset(targ_idx, flags,
						    flag_fields);

	if (offset < 0)
		return 0;

	return *(__u64 *)&fields[offset];
}

struct kparser_parameterized_get_value {
	__u16 src_off;
	__u32 mask;
	__u8 size;
};

/* Structure or parsing operations for flag-fields
 *
 * Operations can be specified either as a function or a parameterization
 * of a parameterized function
 *
 * flags_offset: Offset of flags in the protocol header
 * start_fields_offset: Return the offset in the header of the start of the
 *	flag fields data
 */
struct kparser_proto_flag_fields_ops {
	const struct kparser_parameterized_get_value pfget_flags;
	const struct kparser_parameterized_len pfstart_fields_offset;
};

/* Flag-field parse node operations
 *
 * Operations to process a single flag-field
 *
 * extract_metadata: Extract metadata for the node. Input is the meta
 *	data frame which points to a parser defined metadata structure.
 *	If the value is NULL then no metadata is extracted
 * handle_flag_field: Per flag-field handler which allows arbitrary processing
 *	of a flag-field. Input is the flag-field data and a parser defined
 *	metadata structure for the current frame. Return value is a parser
 *	return code: KPARSER_OKAY indicates no errors, KPARSER_STOP* return
 *	values indicate to stop parsing
 * check_flag_field: Function to validate a flag-field
 * cond_exprs: Parameterization of a set of conditionals to check before
 *      proceeding. In the case of functions being used, these
 *      conditionals would be in the check_flag_field function
 */
struct kparser_parse_flag_field_node_ops {
	const struct kparser_condexpr_tables cond_exprs;
};

/* A parse node for a single flag field
 *
 * name: Text name for debugging
 * metadata_table: Table of parameterized metadata operations
 * ops: Operations
 * thread_funcs: Thread functions
 */
struct kparser_parse_flag_field_node {
	const char name[KPARSER_MAX_NAME];
	struct kparser_metadata_table *metadata_table;
	const struct kparser_parse_flag_field_node_ops ops;
};

/* One entry in a flag-fields protocol table:
 *	index: flag-field index (index in a flag-fields table)
 *	node: associated TLV parse structure for the type
 */
struct kparser_proto_flag_fields_table_entry {
	int index;
	const struct kparser_parse_flag_field_node __rcu *node;
};

/* Flag-fields table
 *
 * Contains a table that maps a flag-field index to a flag-field parse node.
 * Note that the index correlates to an entry in a flag-fields table that
 * describes the flag-fields of a protocol
 */
struct kparser_proto_flag_fields_table {
	int num_ents;
	const struct kparser_proto_flag_fields_table_entry __rcu *entries;
};

/* A flag-fields parse node. Note this is a super structure for a KPARSER parse
 * node and tyoe is KPARSER_NODE_TYPE_FLAG_FIELDS
 */
struct kparser_parse_flag_fields_node {
	const struct kparser_parse_node parse_node;
	const struct kparser_proto_flag_fields_table __rcu
		     *flag_fields_proto_table;
};

/* A flag-fields protocol node. Note this is a super structure for aKPARSER 
 * protocol node and type is KPARSER_NODE_TYPE_FLAG_FIELDS
 */
struct kparser_proto_flag_fields_node {
	struct kparser_proto_node proto_node;
	struct kparser_proto_flag_fields_ops ops;
	const struct kparser_flag_fields __rcu *flag_fields;
};

/* Helper to create a flag-fields protocol table */
#define KPARSER_MAKE_FLAG_FIELDS_TABLE(NAME, ...)			\
	static const struct kparser_proto_flag_fields_table_entry	\
					__##NAME[] =  { __VA_ARGS__ };	\
	static const struct kparser_proto_flag_fields_table NAME = {	\
		.num_ents = sizeof(__##NAME) /				\
			sizeof(struct					\
				kparser_proto_flag_fields_table_entry),	\
		.entries = __##NAME,					\
	}

/* Forward declarations for flag-fields parse nodes */
#define KPARSER_DECL_FLAG_FIELDS_PARSE_NODE(FLAG_FIELDS_PARSE_NODE)	\
	static const struct kparser_parse_flag_fields_node		\
						FLAG_FIELDS_PARSE_NODE

/* Forward declarations for flag-field proto tables */
#define KPARSER_DECL_FLAG_FIELDS_TABLE(FLAG_FIELDS_TABLE)		\
	static const struct kparser_proto_flag_fields_table		\
						FLAG_FIELDS_TABLE


/* Helper to create a parse node with a next protocol table */
#define __KPARSER_MAKE_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					    PROTO_FLAG_FIELDS_NODE,	\
					    EXTRACT_METADATA, HANDLER,	\
					    HANDLER_BLOCKERS,		\
					    HANDLER_WATCHERS,		\
					    POST_HANDLER,		\
					    POST_HANDLER_BLOCKERS,	\
					    POST_HANDLER_WATCHERS,	\
					    WILDCARD_NODE,		\
					    PROTO_TABLE,		\
					    FLAG_FIELDS_TABLE)		\
									\
	static const struct kparser_parse_flag_fields_node		\
					PARSE_FLAG_FIELDS_NODE = {	\
		.flag_fields_proto_table = FLAG_FIELDS_TABLE,		\
		.parse_node.node_type = KPARSER_NODE_TYPE_FLAG_FIELDS,	\
		.parse_node.proto_node =				\
				&PROTO_FLAG_FIELDS_NODE.proto_node,	\
		.parse_node.ops.extract_metadata = EXTRACT_METADATA,	\
		.parse_node.ops.handle_proto.func = HANDLER,		\
		.parse_node.ops.handle_proto.blockers =			\
						HANDLER_BLOCKERS,	\
		.parse_node.ops.handle_proto.watchers =			\
						HANDLER_WATCHERS,	\
		.parse_node.ops.post_handle_proto.func = POST_HANDLER,	\
		.parse_node.ops.post_handle_proto.blockers =		\
						POST_HANDLER_BLOCKERS,	\
		.parse_node.ops.post_handle_proto.watchers =		\
						POST_HANDLER_WATCHERS,	\
		.parse_node.wildcard_node = WILDCARD_NODE,		\
		.parse_node.proto_table = PROTO_TABLE,			\
		.parse_node.thread_funcs =				\
			__KPARSER_SET_THREAD_FUNCS(		\
						PARSE_FLAG_FIELDS_NODE)	\
	}

/* Helper to create a flag-fields parse node */
#define KPARSER_MAKE_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					  PROTO_FLAG_FIELDS_NODE,	\
					  EXTRACT_METADATA, HANDLER,	\
					  POST_HANDLER, PROTO_TABLE,	\
					  FLAG_FIELDS_TABLE)		\
	KPARSER_DECL_FLAG_FIELDS_TABLE(FLAG_FIELDS_TABLE);		\
	KPARSER_DECL_PROTO_TABLE(PROTO_TABLE);				\
	__KPARSER_MAKE_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					    PROTO_FLAG_FIELDS_NODE,	\
					    EXTRACT_METADATA, HANDLER,	\
					    0, 0, POST_HANDLER,		\
					    0, 0, NULL, &PROTO_TABLE,	\
					    &FLAG_FIELDS_TABLE)

/* Helper to create an overlay flag-fields parse node */
#define KPARSER_MAKE_FLAG_FIELDS_OVERLAY_PARSE_NODE(			\
					PARSE_FLAG_FIELDS_NODE,		\
					PROTO_FLAG_FIELDS_NODE,		\
					EXTRACT_METADATA, HANDLER,	\
					POST_HANDLER, OVERLAY_NODE,	\
					FLAG_FIELDS_TABLE)		\
	KPARSER_DECL_FLAG_FIELDS_TABLE(FLAG_FIELDS_TABLE);		\
	__KPARSER_MAKE_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					    PROTO_FLAG_FIELDS_NODE,	\
					    EXTRACT_METADATA, HANDLER,	\
					    0, 0, POST_HANDLER,		\
					    0, 0, OVERLAY_NODE,		\
					    NULL, &FLAG_FIELDS_TABLE)

/* Helper to create a leaf flag-fields parse node */
#define KPARSER_MAKE_LEAF_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,\
					       PROTO_FLAG_FIELDS_NODE,	\
					       EXTRACT_METADATA,	\
					       HANDLER, POST_HANDLER,	\
					       FLAG_FIELDS_TABLE)	\
	KPARSER_DECL_FLAG_FIELDS_TABLE(FLAG_FIELDS_TABLE);		\
	__KPARSER_MAKE_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					    PROTO_FLAG_FIELDS_NODE,	\
					    EXTRACT_METADATA, HANDLER,	\
					    0, 0, POST_HANDLER, 0, 0,	\
					    NULL, NULL,	NULL,		\
					    &FLAG_FIELDS_TABLE)

/* Helper to create a parse node for a single flag-field */
#define __KPARSER_MAKE_FLAG_FIELD_PARSE_NODE(NODE_NAME, EXTRACT_METADATA,\
					   HANDLER, HANDLER_BLOCKERS,	\
					   HANDLER_WATCHERS,		\
					   METADATA_TABLE)		\
									\
	static const struct kparser_parse_flag_field_node NODE_NAME = {	\
		.name = #NODE_NAME,					\
		.metadata_table = METADATA_TABLE,			\
	}

#define KPARSER_MAKE_FLAG_FIELD_PARSE_NODE(NODE_NAME, METADATA_FUNC,	\
					 HANDLER_FUNC)			\
	__KPARSER_MAKE_FLAG_FIELD_PARSE_NODE(NODE_NAME, METADATA_FUNC,	\
					   HANDLER_FUNC, 0, 0, NULL)

/* Null flag-field node for filling out flag-fields table */
KPARSER_MAKE_FLAG_FIELD_PARSE_NODE(KPARSER_FLAG_NODE_NULL, NULL, NULL);

#endif /* __KPARSER_FLAG_FIELDS_H */
