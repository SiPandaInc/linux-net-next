/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KPARSER_H
#define __KPARSER_H

#include <linux/hash.h>
#include <linux/kparser.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rhashtable-types.h>
#include <linux/skbuff.h>
#include <linux/xxhash.h>

#include "kparser_types.h"
#include "kparser_condexpr.h"
#include "kparser_metaextract.h"
#include "kparser_types.h"

#if 0

Data structures:

The global kparser rhashtable contains all the kparsers.
Each kparser instance is identified by name and id (keys).

Any kparser instance is defined by atleast one root node.

The global node rhashtable contains all the proto nodes. Nodes can be shared
accross different kparsers (as roots). Each node is identified by name and
id (keys). Each node instance refers to a protocol table and a metadata_list
(id and name as keys).

The global prototable rhashtable contains all the prototables. Each protocol
table contains atleast one parse node entry. Parser nodes are same as
proto nodes but distinguished by the type field. Similar to proto nodes, parse
nodes can also be shared but among different proto tables. These nodes are also
identified by name and id (keys). prototable contains nodes both as an array
whose indexes are mapped with nodes map key and hashtbl.

Next the metadata_list is identified by name and id (keys). The global
metadata_list rhashtable contains all the metadata_list entries.
Each metadata_list entry can be also shared among different proto nodes.
Each metadata_list entry contains a list of meta data entries.

The global metadata rhashtable contains all the metadata entries. Metadata
entries are identified by name and id (keys). Each metadata entry can be shared
among different metadata_lists.

e.g. a simple ethernet header parser:

tc parser create metadata name ether.metadata.proto id 0x3001 soff 0 \
	   doff 12 length 2

tc parser create metalist name ether.metadata id 0x3000 metadata 0x3001

tc parser create node name ipv4-chk id 0x1 minlen 1
tc parser create node name ipv6-chk id 0x3 minlen 1

tc parser create table name ether id 0x402 default stop-okay size 2
tc parser create table/ether/0 name ether.tabent.IPv4 key 0x0800 node ipv4-chk
tc parser create table/ether/1 name ether.tabent.IPv6 key 0x0806 node ipv6-chk

tc parser create node name ether id 0x0 minlen 14 nxtoffset 12 nxtlength 2 \
	   prottable 0x402 metadata 0x3000
tc parser create parser name big_parser id 0x1000 root_node_name ether root_node_id 0x0

#endif

/* TODO: add comments on every member of DSs */

struct kparser_list {
	void *ptr;
	struct list_head list_node;
};

struct kparser_htbl {
	struct rhashtable tbl;
	struct rhashtable_params tbl_params;
};

struct kparser_global_namespaces_private {
	enum kparser_global_namespace_ids id;
	struct rhashtable tbl;
	struct rhashtable_params tbl_params;
};

struct kparser_glue {
	struct kparser_hkey key;
	struct rhash_head ht_node_id;
	struct rhash_head ht_node_name;
	struct kref refcount;
	struct kparser_conf_cmd config;
};

struct kparser_glue_condexpr_expr {
	struct kparser_glue glue;
	struct kparser_condexpr_expr expr;
};

struct kparser_glue_condexpr_table {
	struct kparser_glue glue;
	struct kparser_condexpr_table table;
};

struct kparser_glue_condexpr_tables {
	struct kparser_glue glue;
	struct kparser_condexpr_tables table;
};

struct kparser_glue_counter {
	struct kparser_glue glue;
	struct kparser_cntr_conf counter_cnf;
};

struct kparser_glue_counter_table {
	struct kparser_glue glue;
	__u8 elems_cnt;
	struct kparser_glue_counter k_cntrs[KPARSER_CNTR_NUM_CNTRS];
};

struct kparser_glue_metadata_extract {
	struct kparser_glue glue;
	struct kparser_metadata_extract mde; 
};

struct kparser_glue_metadata_table {
	struct kparser_glue glue;
	size_t md_configs_len;
	struct kparser_conf_cmd *md_configs;
	struct kparser_metadata_table metadata_table;
};

struct kparser_glue_node {
	struct kparser_glue glue;
	struct list_head parser_rev_ref_list;
	struct list_head ptblent_rev_ref_list;
};

struct kparser_glue_glue_parse_node {
	struct kparser_glue_node glue;
	union {
		struct kparser_parse_node node;
		struct kparser_parse_flag_fields_node flags_parse_node;
		struct kparser_parse_tlvs_node tlvs_parse_node;
	} parse_node;
};

struct kparser_glue_protocol_table {
	struct kparser_glue glue;
	struct kparser_proto_table proto_table;
};

struct kparser_glue_parse_tlv_node {
	struct kparser_glue_node glue;
	struct kparser_parse_tlv_node tlv_parse_node;
};

struct kparser_glue_proto_tlvs_table {
	struct kparser_glue glue;
	struct kparser_proto_tlvs_table tlvs_proto_table;
};

struct kparser_glue_flag_field {
	struct kparser_glue glue;
	struct kparser_flag_field flag_field;
};

struct kparser_glue_flag_fields {
	struct kparser_glue glue;
	struct kparser_flag_fields flag_fields;
};

struct kparser_glue_flag_field_node {
	struct kparser_glue_node glue;
	struct kparser_parse_flag_field_node node_flag_field;
};

struct kparser_glue_proto_flag_fields_table {
	struct kparser_glue glue;
	struct kparser_proto_flag_fields_table flags_proto_table;
};

struct kparser_glue_parser {
	struct kparser_glue glue;
	struct list_head list_node;
	struct kparser_parser parser;
};

static inline int kparser_cmp_fn_name(struct rhashtable_compare_arg *arg,
                              const void *ptr)
{
	const char *key2 = arg->key;
        const struct kparser_hkey *key1 = ptr;

	return strcmp(key1->name, key2);
}

static inline int kparser_cmp_fn_id(struct rhashtable_compare_arg *arg,
                              const void *ptr)
{
	const __u16 *key2 = arg->key;
        const __u16 *key1 = ptr;

	return (*key1 != *key2);
}

static inline __u32 kparser_gnric_hash_fn_name(const void *hkey, __u32 key_len,
		__u32 seed)
{
	const char *key = hkey;
	/*
	 * TODO: check if seed needs to be used here
	 * TODO: replace xxh32() with siphash
	 */
	return xxh32(hkey, strlen(key), 0);
}

static inline __u32 kparser_gnric_hash_fn_id(const void *hkey, __u32 key_len,
		__u32 seed)
{
	const __u16 *key = hkey;
	/*
	 * TODO: check if seed needs to be used here
	 */
	return *key;
}

static inline __u32 kparser_gnric_obj_hashfn_name(const void *obj, __u32 key_len,
		__u32 seed)
{
	const struct kparser_hkey *key;

	key = obj;
	/*
	 * TODO: check if seed needs to be used here
	 * TODO: replace xxh32() with siphash
	 * Note: this only works because key always in the start place
	 * of all the differnt kparser objects
	 */
	return xxh32(key->name, strlen(key->name), 0);
}

static inline __u32 kparser_gnric_obj_hashfn_id(const void *obj, __u32 key_len,
		__u32 seed)
{
	const struct kparser_hkey *key;

	key = obj;
	/*
	 * TODO: check if seed needs to be used here
	 * TODO: replace xxh32() with siphash
	 * Note: this only works because key always in the start place
	 * of all the differnt kparser objects
	 */
	return key->id;
}

int kparser_init(void);

int kparser_deinit(void);

int kparser_config_handler_add(const void *cmdarg, size_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len);

int kparser_config_handler_update(const void *cmdarg, size_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len);

int kparser_config_handler_read(const void *cmdarg, size_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len);

int kparser_config_handler_delete(const void *cmdarg, size_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len);

int __kparser_parse(const struct kparser_parser *parser, void *_hdr,
		size_t parse_len, void *_metadata, size_t metadata_len);

int kparser_do_parse(const struct kparser_hkey *kparser_key, void *_hdr,
		size_t parse_len,  void *_metadata, size_t metadata_len);

void * kparser_namespace_lookup(enum kparser_global_namespace_ids ns_id,
		const struct kparser_hkey *key);

const void * kparser_get_parser(const struct kparser_hkey *kparser_key);

bool kparser_put_parser(const void *parser);
#endif /* __KPARSER_H */
