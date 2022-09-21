/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser.h - kParser local header file
 *
 * Author:      Pratyush Kumar Khan <pratyush@sipanda.io>
 */

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

/* These are used to track owner/owned relationship between different objects
 */
struct kparser_ref_ctx {
	int nsid;
	const void *obj;
	const void __rcu **link_ptr;
	struct kref *refcount;
	struct list_head *list;
	struct list_head list_node;
};

#define KPARSER_LINK_OBJ_SIGNATURE		0xffaabbff

struct kparser_obj_link_ctx {
	int sig;
	struct kparser_ref_ctx owner_obj;
	struct kparser_ref_ctx owned_obj;
};

/* global hash table structures */
struct kparser_htbl {
	struct rhashtable tbl;
	struct rhashtable_params tbl_params;
};

/* it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue {
	struct kparser_hkey key;
	struct rhash_head ht_node_id;
	struct rhash_head ht_node_name;
	struct kref refcount;
	struct kparser_conf_cmd config;
	struct list_head owner_list;
	struct list_head owned_list;
};

/* internal namespace structures for conditionals */
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

/* internal namespace structures for counters */
struct kparser_glue_counter {
	struct kparser_glue glue;
	struct kparser_cntr_conf counter_cnf;
};

struct kparser_glue_counter_table {
	struct kparser_glue glue;
	__u8 elems_cnt;
	struct kparser_glue_counter k_cntrs[KPARSER_CNTR_NUM_CNTRS];
};

/* internal namespace structures for metadata */
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

/* internal namespace structures for node */
struct kparser_glue_node {
	struct kparser_glue glue;
};

struct kparser_glue_glue_parse_node {
	struct kparser_glue_node glue;
	union {
		struct kparser_parse_node node;
		struct kparser_parse_flag_fields_node flags_parse_node;
		struct kparser_parse_tlvs_node tlvs_parse_node;
	} parse_node;
};

/* internal namespace structures for table */
struct kparser_glue_protocol_table {
	struct kparser_glue glue;
	struct kparser_proto_table proto_table;
};

/* internal namespace structures for tlv nodes and tables */
struct kparser_glue_parse_tlv_node {
	struct kparser_glue_node glue;
	struct kparser_parse_tlv_node tlv_parse_node;
};

struct kparser_glue_proto_tlvs_table {
	struct kparser_glue glue;
	struct kparser_proto_tlvs_table tlvs_proto_table;
};

/* internal namespace structures for flagfields and tables*/
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

/* internal namespace structures for parser */
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

static inline __u32 kparser_generic_hash_fn_name(const void *hkey, __u32 key_len, __u32 seed)
{
	const char *key = hkey;
	/* TODO: check if seed needs to be used here
	 * TODO: replace xxh32() with siphash
	 */
	return xxh32(hkey, strlen(key), 0);
}

static inline __u32 kparser_generic_hash_fn_id(const void *hkey, __u32 key_len, __u32 seed)
{
	const __u16 *key = hkey;
	/* TODO: check if seed needs to be used here
	 */
	return *key;
}

static inline __u32 kparser_generic_obj_hashfn_name(const void *obj, __u32 key_len, __u32 seed)
{
	const struct kparser_hkey *key;

	key = obj;
	/* TODO: check if seed needs to be used here
	 * TODO: replace xxh32() with siphash
	 * Note: this only works because key always in the start place
	 * of all the differnt kparser objects
	 */
	return xxh32(key->name, strlen(key->name), 0);
}

static inline __u32 kparser_generic_obj_hashfn_id(const void *obj, __u32 key_len, __u32 seed)
{
	const struct kparser_hkey *key;

	key = obj;
	/* TODO: check if seed needs to be used here
	 * TODO: replace xxh32() with siphash
	 * Note: this only works because key always is the very first object in all the differnt
	 * kparser objects
	 */
	return key->id;
}

/* internal shared functions */
int kparser_init(void);

int kparser_deinit(void);

int kparser_config_handler_add(const void *cmdarg, size_t cmdarglen,
			       struct kparser_cmd_rsp_hdr **rsp,
			       size_t *rsp_len);

int kparser_config_handler_update(const void *cmdarg, size_t cmdarglen,
				  struct kparser_cmd_rsp_hdr **rsp,
				  size_t *rsp_len);

int kparser_config_handler_read(const void *cmdarg, size_t cmdarglen,
				struct kparser_cmd_rsp_hdr **rsp,
				size_t *rsp_len);

int kparser_config_handler_delete(const void *cmdarg, size_t cmdarglen,
				  struct kparser_cmd_rsp_hdr **rsp,
				  size_t *rsp_len);

int __kparser_parse(const struct kparser_parser *parser, void *_hdr,
		    size_t parse_len, void *_metadata, size_t metadata_len);

int kparser_do_parse(const struct kparser_hkey *kparser_key, void *_hdr,
		     size_t parse_len,  void *_metadata, size_t metadata_len);

void *kparser_namespace_lookup(enum kparser_global_namespace_ids ns_id,
			       const struct kparser_hkey *key);

const void *kparser_get_parser(const struct kparser_hkey *kparser_key);

bool kparser_put_parser(const void *parser);

void kparser_ref_get(struct kref *refcount);

void kparser_ref_put(struct kref *refcount);

struct get_kparser_funchooks {
	const void * (*kparser_get_parser_hook)(const struct kparser_hkey *kparser_key);
	int (*__kparser_parse_hook)(const struct kparser_parser *parser, void *_hdr,
				    size_t parse_len, void *_metadata, size_t metadata_len);
	bool (*kparser_put_parser_hook)(const void *prsr);
};

extern struct get_kparser_funchooks kparser_funchooks;

#endif /* __KPARSER_H */
