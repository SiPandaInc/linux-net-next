/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KPARSER_H
#define __KPARSER_H

#include <linux/hash.h>
#include <linux/kparser.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rhashtable-types.h>
#include <linux/xxhash.h>

// TODO: take definitions from "install/include/panda/parser_types.h"

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

// TODO: add comments on every member of DSs

struct kparser_list {
	void *ptr;
	struct list_head list_node;
};

struct kparser_md {
	struct kparser_arg_md arg;
	struct rhash_head ht_node;
	struct mutex mutex;
	struct kref refcount;
	struct list_head mdl_node;
};

struct kparser_tbl_md {
	struct rhashtable tbl;
	struct rhashtable_params tbl_params;
};

struct kparser_mdl {
	struct kparser_arg_mdl arg;
	struct rhash_head ht_node;
	struct mutex mutex;
	struct kref refcount;
	struct list_head mdl;
	struct list_head node_rev_ref_list;
};

struct kparser_tbl_mdl {
	struct rhashtable tbl;
	struct rhashtable_params tbl_params;
};

struct kparser_node {
	struct kparser_arg_node arg;
	struct rhash_head ht_node;
	struct mutex mutex;
	struct kref refcount;
	struct list_head parser_rev_ref_list;
	struct list_head ptblent_rev_ref_list;
	void *ptbl_ref;
	void *mdl_ref;
};

struct kparser_tbl_node {
	struct rhashtable tbl;
	struct rhashtable_params tbl_params;
};

struct kparser_proto_ent {
	struct kparser_proto_tbl_ent arg;
	struct mutex mutex;
	void *node_ref;
};

struct kparser_proto {
	struct kparser_arg_proto_tbl arg;
	struct mutex mutex;
	struct rhash_head ht_node;
	struct kref refcount;
	struct list_head node_rev_ref_list;
	u16 ent_tbl_size;
	struct kparser_proto_ent *ent_tbl;
};

struct kparser_tbl_proto {
	struct rhashtable tbl;
	struct rhashtable_params tbl_params;
};

struct kparser_parser {
	struct kparser_arg_parser arg;
	struct rhash_head ht_node;
	struct mutex mutex;
	struct kref refcount;
	void *rnode_ref;
};

struct kparser_tbl_parser {
	struct rhashtable tbl;
	struct rhashtable_params tbl_params;
};

static inline int kparser_cmp_fn(struct rhashtable_compare_arg *arg,
                              const void *ptr)
{
	const struct kparser_hkey *key2 = arg->key;
        const struct kparser_hkey *key1 = ptr;

	// printk("%s:%s:%u:%s:%u\n", __FUNCTION__, key1->name, key1->id, key2->name, key2->id);
	if (key1->id != key2->id)
		return 1;

	return strcmp(key1->name, key2->name);
}

static inline u32 kparser_gnric_hash_fn(const void *hkey, u32 key_len, u32 seed)
{
	// TODO: check if seed needs to be used here
	// TODO: replace xxh32() with siphash
	if (0) {
		const struct kparser_hkey *key2 = hkey;
		pr_debug("%s:%s:%u:%u\n", __FUNCTION__, key2->name, key2->id, key_len);
	}
	return xxh32(hkey, key_len, 0);
}

static inline u32 kparser_gnric_obj_hashfn(const void *obj, u32 key_len, u32 seed)
{
	// TODO: check if seed needs to be used here
	// TODO: replace xxh32() with siphash
	// Note: this only works because key always in the start place
	// of all the differnt kparser objects
	return xxh32(obj, key_len, 0);
}

s32 kparser_init(void);
s32 kparser_deinit(void);

void kparser_add_md(const struct kparser_arg_md *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_del_md(const struct kparser_arg_md *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_add_mdl(const struct kparser_arg_mdl *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_del_mdl(const struct kparser_arg_mdl *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_add_proto_tbl(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_del_proto_tbl(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_add_proto_tbl_ent(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_del_proto_tbl_ent(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_add_node(const struct kparser_arg_node *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_del_node(const struct kparser_arg_node *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_add_parser(const struct kparser_arg_parser *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_del_parser(const struct kparser_arg_parser *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_del_all(const void *arg,
		struct kparser_cmd_rsp_hdr *rsp);
void kparser_ls_all(const struct kparser_hkey *arg,
		struct kparser_cmd_rsp_hdr *rsp);
int kparser_do_parse(const struct kparser_hkey *kparser_key, void *hdr,
		size_t parse_len, void *obj_ref, 
		void *metadata_dbuf, size_t metadata_dbuf_len);

enum {
	KPARSER_HTBL_PARSER,
	KPARSER_HTBL_PTBL,
	KPARSER_HTBL_NODE,
	KPARSER_HTBL_MDL,
	KPARSER_HTBL_MD,
};

void * global_htbl_lookup(u16 htbl_id, const void *key);

enum {
	PANDA_OKAY = 0,                 /* Okay and continue */
	PANDA_RET_OKAY = -1,            /* Encoding of OKAY in ret code */

	PANDA_OKAY_USE_WILD = -2,       /* cam instruction */
	PANDA_OKAY_USE_ALT_WILD = -3,   /* cam instruction */

	PANDA_STOP_OKAY = -4,           /* Okay and stop parsing */
	PANDA_STOP_NODE_OKAY = -5,      /* Stop parsing current node */
	PANDA_STOP_SUB_NODE_OKAY = -6,  /* Stop parsing currnet sub-node */

	/* Parser failure */
	PANDA_STOP_FAIL = -12,
	PANDA_STOP_LENGTH = -13,
	PANDA_STOP_UNKNOWN_PROTO = -14,
	PANDA_STOP_ENCAP_DEPTH = -15,
	PANDA_STOP_UNKNOWN_TLV = -16,
	PANDA_STOP_TLV_LENGTH = -17,
	PANDA_STOP_BAD_FLAG = -18,
	PANDA_STOP_FAIL_CMP = -19,
	PANDA_STOP_LOOP_CNT = -20,
	PANDA_STOP_TLV_PADDING = -21,
	PANDA_STOP_OPTION_LIMIT = -22,
	PANDA_STOP_MAX_NODES = -23,
	PANDA_STOP_COMPARE = -24,
	PANDA_STOP_CNTR1 = -25,
	PANDA_STOP_CNTR2 = -26,
	PANDA_STOP_CNTR3 = -27,
	PANDA_STOP_CNTR4 = -28,
	PANDA_STOP_CNTR5 = -29,

	PANDA_STOP_THREADS_FAIL = -31,
};

static inline const char *panda_parser_code_to_text(int code)
{
	switch (code) {
	case PANDA_OKAY:
		return "okay";
	case PANDA_RET_OKAY:
		return "okay-ret";
	case PANDA_OKAY_USE_WILD:
		return "okay-use-wild";
	case PANDA_OKAY_USE_ALT_WILD:
		return "okay-use-alt-wild";
	case PANDA_STOP_OKAY:
		return "stop-okay";
	case PANDA_STOP_NODE_OKAY:
		return "stop-node-okay";
	case PANDA_STOP_SUB_NODE_OKAY:
		return "stop-sub-node-okay";
	case PANDA_STOP_FAIL:
		return "stop-fail";
	case PANDA_STOP_LENGTH:
		return "stop-length";
	case PANDA_STOP_UNKNOWN_PROTO:
		return "stop-unknown-proto";
	case PANDA_STOP_ENCAP_DEPTH:
		return "stop-encap-depth";
	case PANDA_STOP_UNKNOWN_TLV:
		return "stop-unknown-tlv";
	case PANDA_STOP_TLV_LENGTH:
		return "stop-tlv-length";
	case PANDA_STOP_BAD_FLAG:
		return "stop-bad-flag";
	case PANDA_STOP_FAIL_CMP:
		return "stop-fail-cmp";
	case PANDA_STOP_LOOP_CNT:
		return "stop-loop-cnt";
	case PANDA_STOP_TLV_PADDING:
		return "stop-tlv-padding";
	case PANDA_STOP_OPTION_LIMIT:
		return "stop-option-limit";
	case PANDA_STOP_MAX_NODES:
		return "stop-max-nodes";
	case PANDA_STOP_COMPARE:
		return "stop-compare";
	case PANDA_STOP_THREADS_FAIL:
		return "stop-thread-fail";
	default:
		return "unknown-code";
	}
}


#endif /* __KPARSER_H */
