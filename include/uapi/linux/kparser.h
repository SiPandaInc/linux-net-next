/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* kparser.h - KPARSER Interface */

#ifndef _LINUX_KPARSER_H
#define _LINUX_KPARSER_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>

#define BITS_IN_BYTE	8
#define BITS_IN_U32	(sizeof(__u32) * BITS_IN_BYTE)

#define setbit(A,k)	(A[(k)/BITS_IN_U32] |= (1 << ((k) % BITS_IN_U32)))
#define clearbit(A,k)	(A[(k)/BITS_IN_U32] &= ~(1 << ((k) % BITS_IN_U32)))
#define testbit(A,k)    (1 & (A[(k)/BITS_IN_U32] >> ((k) % BITS_IN_U32)))

/* NETLINK_GENERIC related info */
#define KPARSER_GENL_NAME	"kparser"
#define KPARSER_GENL_VERSION	0x1

#define KPARSER_ERR_STR_MAX_LEN 256
#define KPARSER_MAX_STR_LEN_U8 6
#define KPARSER_MAX_STR_LEN_U16 8
#define KPARSER_MAX_STR_LEN_U32 12
#define KPARSER_MAX_STR_LEN_U64 16

enum kparser_arg_val_type {
	KPARSER_ARG_VAL_STR,
	KPARSER_ARG_VAL_U8,
	KPARSER_ARG_VAL_U16,
	KPARSER_ARG_VAL_U32,
	KPARSER_ARG_VAL_U64,
	KPARSER_ARG_VAL_BOOL,
	KPARSER_ARG_VAL_FLAG,
	KPARSER_ARG_VAL_SET,
	KPARSER_ARG_VAL_ARRAY,
	KPARSER_ARG_VAL_HYB_KEY_NAME,
	KPARSER_ARG_VAL_HYB_KEY_ID,
	KPARSER_ARG_VAL_HYB_IDX,
	KPARSER_ARG_VAL_INVALID
};

#define KPARSER_SET_VAL_LEN_MAX 64

struct kparser_arg_set {
	const char *set_value_str;
	__u64 set_value_enum;
};

struct kparser_arg_key_val_token {
	enum kparser_arg_val_type type;
	const char *key_name;
	bool mandatory;
	bool semi_optional;
	int other_mandatory_idx;
	bool immutable;
	ssize_t str_arg_len_max;
	ssize_t w_offset;
	ssize_t w_len;
	union {
		struct {
			ssize_t default_val_size;
			const void *default_val;
		};
		struct {
			ssize_t value_set_len;
			const struct kparser_arg_set *value_set;
			__u64 def_value_enum;
		};
		struct {
			__u64 min_value;
			__u64 def_value;
			__u64 max_value;
		};
	};
	struct {
		enum kparser_arg_val_type elem_type;
		ssize_t elem_counter;
		ssize_t elem_size;
		ssize_t offset_adjust;
	};
	const char *help_msg;
	const struct kparser_arg_key_val_token *default_template_token;
};

enum kparser_global_namespace_ids {
	KPARSER_NS_INVALID,

	KPARSER_NS_METADATA,
	KPARSER_NS_METALIST,

	KPARSER_NS_NODE_PROTO,
	KPARSER_NS_NODE_PARSE,
	KPARSER_NS_PROTO_TABLE,

	KPARSER_NS_TLV_NODE_PROTO,
	KPARSER_NS_TLV_NODE_PARSE,
	KPARSER_NS_TLVS_NODE_PROTO,
	KPARSER_NS_TLVS_NODE_PARSE,
	KPARSER_NS_TLV_PROTO_TABLE,

	KPARSER_NS_FIELD,
	KPARSER_NS_FIELDS,
	KPARSER_NS_PARSER,
	KPARSER_NS_CONDEXPRS,
	KPARSER_NS_MAX
};

#define KPARSER_NAMESPACE_NAME_METADATA "metadata"
#define KPARSER_NAMESPACE_NAME_METALIST "metalist"

#define KPARSER_NAMESPACE_NAME_NODE_PROTO "node_proto"
#define KPARSER_NAMESPACE_NAME_NODE_PARSE "node_parse"
#define KPARSER_NAMESPACE_NAME_PROTO_TABLE "proto_table"

#define KPARSER_NAMESPACE_NAME_TLV_NODE_PROTO "tlv_node_proto"
#define KPARSER_NAMESPACE_NAME_TLV_NODE_PARSE "tlv_node_parse"
#define KPARSER_NAMESPACE_NAME_TLVS_NODE_PROTO "tlvs_node_proto"
#define KPARSER_NAMESPACE_NAME_TLVS_NODE_PARSE "tlvs_node_parse"
#define KPARSER_NAMESPACE_NAME_TLV_PROTO_TABLE "tlv_proto_table"

#define KPARSER_NAMESPACE_NAME_FIELDS "flags_fields"
#define KPARSER_NAMESPACE_NAME_PARSER "parser"
#define KPARSER_NAMESPACE_NAME_COND_EXPRS "condexprs"

struct kparser_global_namespaces {
	enum kparser_global_namespace_ids name_space_id;
	const char *name;
	ssize_t arg_tokens_count;
	const struct kparser_arg_key_val_token *arg_tokens; 
	int create_attr_id;
	int update_attr_id;
	int read_attr_id;
	int delete_attr_id;
	int rsp_attr_id;
};

#define KPARSER_DEFINE_ATTR_IDS(id_suffix)			\
	KPARSER_ATTR_CREATE_##id_suffix,	/* NLA_BINARY */\
	KPARSER_ATTR_UPDATE_##id_suffix,	/* NLA_BINARY */\
	KPARSER_ATTR_READ_##id_suffix,		/* NLA_BINARY */\
	KPARSER_ATTR_DELETE_##id_suffix,	/* NLA_BINARY */\
	KPARSER_ATTR_RSP_##id_suffix,				\

enum {
	KPARSER_ATTR_UNSPEC,

	KPARSER_DEFINE_ATTR_IDS(METADATA)
	KPARSER_DEFINE_ATTR_IDS(METALIST)

	KPARSER_DEFINE_ATTR_IDS(NODE_PROTO)
	KPARSER_DEFINE_ATTR_IDS(NODE_PARSE)
	KPARSER_DEFINE_ATTR_IDS(PROTO_TABLE)

	KPARSER_DEFINE_ATTR_IDS(TLV_NODE_PROTO)
	KPARSER_DEFINE_ATTR_IDS(TLV_NODE_PARSE)
	KPARSER_DEFINE_ATTR_IDS(TLVS_NODE_PROTO)
	KPARSER_DEFINE_ATTR_IDS(TLVS_NODE_PARSE)
	KPARSER_DEFINE_ATTR_IDS(TLV_PROTO_TABLE)

	KPARSER_DEFINE_ATTR_IDS(PARSER)

	KPARSER_ATTR_DELETE_ALL,
	KPARSER_ATTR_LIST_ALL,

	__KPARSER_ATTR_MAX,
};

#define KPARSER_ATTR_MAX		(__KPARSER_ATTR_MAX - 1)

enum {
	KPARSER_CMD_UNSPEC,
	KPARSER_CMD_CONFIGURE,
	__KPARSER_CMD_MAX,
};

#define KPARSER_CMD_MAX	(__KPARSER_CMD_MAX - 1)

#define KPARSER_INVALID_ID 0xffff

#define KPARSER_USER_ID_MIN 0
#define KPARSER_USER_ID_MAX 0x8000
#define KPARSER_KMOD_ID_MIN 0x8001
#define KPARSER_KMOD_ID_MAX 0xfffe

#define KPARSER_MAX_NAME 128
#define KPARSER_MAX_DIGIT_STR_LEN 16
#define KPARSER_DEF_NAME_PREFIX "kparser_default_name"

struct kparser_hkey {
	__u16 id;
	char name[KPARSER_MAX_NAME];
};

enum kparser_md_type {
	KPARSER_MD_INVALID,
	KPARSER_MD_HDRDATA,
	KPARSER_MD_HDRLEN,
	KPARSER_MD_OFFSET,
	KPARSER_MD_NUMENCAPS,
	KPARSER_MD_NUMNODES,
	KPARSER_MD_TIMESTAMP,
	KPARSER_MD_MAX
};

struct kparser_conf_metadata {
	struct kparser_hkey key;
	__u16 soff;
	__u16 doff;
	ssize_t len;
	bool frame;
	bool e_bit;
	enum kparser_md_type type;
	struct kparser_hkey array_hkey;
	__u16 array_doff;
	struct kparser_hkey array_counter_id;
};

struct kparser_conf_metadata_table {
	struct kparser_hkey key;
	ssize_t metadata_keys_count;
	struct kparser_hkey metadata_keys[0];
};

/* Types for parameterized functions */
struct kparser_parameterized_len {
        __u16 src_off;
        __u8 size;
        bool endian;
        __u32 mask;
        __u8 right_shift;
        __u8 multiplier;
        __u8 add_value;
};

struct kparser_parameterized_next_proto {
        __u16 src_off;
        __u16 mask;
        __u8 size;
        __u8 right_shift;
};

struct kparser_conf_parse_ops {
        struct kparser_parameterized_len pflen;
        struct kparser_parameterized_next_proto pfnext_proto;
	struct kparser_hkey cond_exprs_table;
};

struct kparser_conf_node_proto {
	struct kparser_hkey key;
	bool encap;
	bool overlay;
	ssize_t min_len;
	struct kparser_conf_parse_ops ops;
};

/* Kparse protocol node types */
enum kparser_node_type {
	/* Plain node, no super structure */
	KPARSER_NODE_TYPE_PLAIN,
	/* TLVs node with super structure for TLVs */
	KPARSER_NODE_TYPE_TLVS,
	/* Flag-fields with super structure for flag-fields */
	KPARSER_NODE_TYPE_FLAG_FIELDS,
	/* It represents the limit value */
	KPARSER_NODE_TYPE_MAX,
};

struct kparser_conf_node_parse {
	struct kparser_hkey key;
	enum kparser_node_type type;
	int unknown_ret;
	struct kparser_hkey proto_node;
	struct kparser_hkey proto_table;
	struct kparser_hkey wildcard_parse_node;
	struct kparser_hkey metadata_table;
};

struct kparser_conf_proto_table {
	struct kparser_hkey key;
	__u16 idx;
	int value;
	struct kparser_hkey parse_node_key;
};

struct kparser_conf_proto_tlv_node_ops {
        struct kparser_parameterized_next_proto pfoverlay_type;
	struct kparser_hkey cond_exprs_table;
};

struct kparser_conf_tlv_node_proto {
	struct kparser_hkey key;
	ssize_t min_len;
	ssize_t max_len;
	bool is_padding;
	struct kparser_conf_proto_tlv_node_ops ops;
};

struct kparser_conf_tlv_node_parse {
	struct kparser_hkey key;
	struct kparser_hkey proto_tlv_node_key;
	struct kparser_hkey overlay_proto_tlvs_table_key;
	struct kparser_hkey overlay_wildcard_parse_node;
	int unknown_ret;
	struct kparser_hkey metadata_table;
};

/* Descriptor for parsing operations of one type of TLV. Fields are:
 *
 * start_offset: Returns the offset of TLVs in a header
 * len: Return length of a TLV. Must be set. If the return value < 0 (a
 *	KPARSER_STOP_* return code value) this indicates an error and parsing
 *	is stopped. A the return value greater than or equal to zero then
 *	gives the protocol length. If the returned length is less than the
 *	minimum TLV option length, indicated by min_len by the TLV protocol
 *	node, then this considered and error.
 * type: Return the type of the TLV. If the return value is less than zero
 *	(KPARSER_STOP_* value) then this indicates and error and parsing stops
 */
struct kparser_proto_tlvs_opts {
        const struct kparser_parameterized_len pfstart_offset;
        bool len_parameterized;
        const struct kparser_parameterized_len pflen;
        bool type_parameterized;
        const struct kparser_parameterized_next_proto pftype;
};

struct kparser_conf_tlvs_node_proto {
	struct kparser_conf_node_proto proto_node;
	struct kparser_proto_tlvs_opts ops;
	ssize_t start_offset;
	__u8 pad1_val;
	__u8 padn_val;
	__u8 eol_val;
	bool pad1_enable;
	bool padn_enable;
	bool eol_enable;
	bool fixed_start_offset;
	ssize_t min_len;
};

#define KPARSER_DEFAULT_TLV_MAX_LOOP			255
#define KPARSER_DEFAULT_TLV_MAX_NON_PADDING		255
#define KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_BYTES	255
#define KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_OPTS		255
#define KPARSER_DEFAULT_TLV_DISP_LIMIT_EXCEED		0
#define KPARSER_DEFAULT_TLV_EXCEED_LOOP_CNT_ERR		0

/* Configuration for a TLV node (generally loop nodes)
 *
 * max_loop: Maximum number of TLVs to process
 * max_non: Maximum number of non-padding TLVs to process
 * max_plen: Maximum consecutive padding bytes
 * max_c_pad: Maximum number of consecutive padding options
 * disp_limit_exceed: Disposition when a TLV parsing limit is exceeded. See
 *	KPARSER_LOOP_DISP_STOP_* in parser.h
 * exceed_loop_cnt_is_err: True is exceeding maximum number of TLVS is an error
 */
struct kparser_loop_node_config {
        __u16 max_loop;
        __u16 max_non;
        __u8 max_plen;
        __u8 max_c_pad;
        __u8 disp_limit_exceed;
        bool exceed_loop_cnt_is_err;
};

struct kparser_conf_tlvs_node_parse {
	struct kparser_conf_node_parse parse_node;
	struct kparser_hkey tlv_proto_table_key;
	int unknown_ret;
	struct kparser_hkey tlv_wildcard_parse_node;
	struct kparser_loop_node_config config;
};

struct kparser_conf_tlv_proto_table {
	struct kparser_hkey key;
	__u16 idx;
	int type;
	struct kparser_hkey parse_tlv_node_key;
};

/* Configuration for a KPARSER parser
 *
 * flags: Flags KPARSER_F_* in parser.h
 * max_nodes: Maximum number of nodes to parse
 * max_encaps: Maximum number of encapsulations to parse
 * max_frames: Maximum number of metadata frames
 * metameta_size: Size of metameta data. The metameta data is at the head
 *	of the user defined metadata structure. This also serves as the
 *	offset of the first metadata frame
 * frame_size: Size of one metadata frame
 */
struct kparser_config {
        __u16 flags;
        __u16 max_nodes;
        __u16 max_encaps;
        __u16 max_frames;
        ssize_t metameta_size;
        ssize_t frame_size;
};

struct kparser_conf_parser {
	struct kparser_hkey key;
	struct kparser_config config;
	struct kparser_hkey root_node_key;
	struct kparser_hkey ok_node_key;
	struct kparser_hkey fail_node_key;
};

struct kparser_conf_cmd {
	enum kparser_global_namespace_ids namespace_id;
	union {
		struct kparser_hkey obj_key;
		struct kparser_conf_metadata md_conf;
		struct kparser_conf_metadata_table mdl_conf;
		struct kparser_conf_node_proto node_proto_conf;
		struct kparser_conf_node_parse node_parse_conf;
		struct kparser_conf_proto_table proto_table_conf;
		struct kparser_conf_tlv_node_proto tlv_node_proto_conf;
		struct kparser_conf_tlv_node_parse tlv_node_parse_conf;
		struct kparser_conf_tlvs_node_proto tlvs_node_proto_conf;
		struct kparser_conf_tlvs_node_parse tlvs_node_parse_conf;
		struct kparser_conf_tlv_proto_table tlv_proto_table_conf;
		struct kparser_conf_parser parser_conf;
	};
};

struct kparser_cmd_rsp_hdr {
	int op_ret_code;
	__u8 err_str_buf[KPARSER_ERR_STR_MAX_LEN];
	struct kparser_hkey key;
	ssize_t objects_len;
	struct kparser_conf_cmd object;
	// variable list of objects
	struct kparser_conf_cmd objects[0];
};

static inline bool kparser_hkey_id_empty(const struct kparser_hkey *key)
{
	if (!key)
		return true;
	return (key->id == KPARSER_INVALID_ID);
}

static inline bool kparser_hkey_name_empty(const struct kparser_hkey *key)
{
	if (!key)
		return true;
	return ((key->name[0] == '\0') ||
			!strcmp(key->name, KPARSER_DEF_NAME_PREFIX));
}

static inline bool kparser_hkey_empty(const struct kparser_hkey *key)
{
	return (kparser_hkey_id_empty(key) && kparser_hkey_name_empty(key));
}

#define KPARSER_USER_ID_MIN 0
#define KPARSER_USER_ID_MAX 0x8000
#define KPARSER_KMOD_ID_MIN 0x8001
#define KPARSER_KMOD_ID_MAX 0xfffe

static inline bool kparser_hkey_user_id_invalid(const struct kparser_hkey *key)
{
	if (!key)
		return true;
	return ((key->id == KPARSER_INVALID_ID) ||
			(key->id > KPARSER_USER_ID_MAX));
}

#endif /* _LINUX_KPARSER_H */
