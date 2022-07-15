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

#include "kparser.h"
#include <linux/rhashtable.h>
#include <linux/slab.h>

static DEFINE_MUTEX(kparser_config_lock);

/*
 * Layout for important config and data path data structures:
 *
 * metadata (md): Each metadata node specifies:
 *	soff: copy offset
 *	doff: write offset
 *	len:  write len
 *
 * metalist (mdl): All meta data nodes are referenced by zero or
 * more metalist nodes. Each metadata list node contains a hash
 * table of all the associated linear
 * link list which contains references to all the associated md
 * nodes.
 * 
 * Hence metalist contains a list of meta data nodes.  
 * Each protocol table contains a fixed number of protocol entries.
 * Each protocol entry will contain a reference to a protocol node.
 * Each proto node can belong to more than one protocol entry.
 * Hence each proto node maintains a list of owner protocol entries.
 */
static void kparser_free_proto_tbl(void *ptr, void *arg)
{
#if 0
	struct kparser_list *tmp_rev_ref = NULL;
	struct kparser_list *rev_ref = NULL;
	struct kparser_node *knode = NULL;
	struct kparser_proto *karg = ptr;
	u32 refcnt, idx;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	mutex_lock(&kparser_config_lock);

	refcnt = kref_read(&karg->refcount);
	if (refcnt != 1) {
		printk("%s:Active refcnt:%u \n",
			__FUNCTION__, refcnt);
	}

	pr_debug("%s:KEY:{%s:%u}, Refcnt:%u\n",
			__FUNCTION__, karg->arg.key.name,
			karg->arg.key.id, refcnt);

	mutex_destroy(&karg->mutex);

	for (idx = 0; idx < karg->ent_tbl_size; idx++) {
		mutex_destroy(&karg->mutex);
		knode = karg->ent_tbl[idx].node_ref;
		if (knode == NULL)
			continue;
		list_for_each_entry_safe(rev_ref, tmp_rev_ref,
				&knode->ptblent_rev_ref_list, list_node) {
			if (rev_ref->ptr == &karg->ent_tbl[idx]) {
				kref_put(&knode->refcount, NULL);
				list_del_init_careful(&rev_ref->list_node);
				kfree(rev_ref);
				break;
			}
		}
	}

	list_for_each_entry_safe(rev_ref, tmp_rev_ref,
			&karg->node_rev_ref_list, list_node) {
		knode = rev_ref->ptr;
		knode->ptbl_ref = NULL;
		list_del_init_careful(&rev_ref->list_node);
		kfree(rev_ref);
		kref_put(&karg->refcount, NULL);
	}

	kfree(karg->ent_tbl);
	kfree(karg);

	mutex_unlock(&kparser_config_lock);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
#endif
}

static void kparser_free_node_tbl(void *ptr, void *arg)
{
#if 0
	struct kparser_proto_ent *karg_ptbl_ent;
	struct kparser_list *tmp_rev_ref = NULL;
	struct kparser_list *rev_ref = NULL;
	struct kparser_parser *karg_parser;
	struct kparser_node *karg = ptr;
	struct kparser_proto *kptblarg;
	struct kparser_mdl *kmdlarg;
	u32 refcnt;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	mutex_lock(&kparser_config_lock);

	refcnt = kref_read(&karg->refcount);
	if (refcnt != 1) {
		printk("%s:Active refcnt:%u \n",
			__FUNCTION__, refcnt);
	}

	pr_debug("%s:KEY:{%s:%u}, Refcnt:%u\n",
			__FUNCTION__, karg->arg.key.name,
			karg->arg.key.id, refcnt);

	mutex_destroy(&karg->mutex);

	kmdlarg = karg->mdl_ref;
	if (kmdlarg) {
		list_for_each_entry_safe(rev_ref, tmp_rev_ref,
				&kmdlarg->node_rev_ref_list, list_node) {
			if (rev_ref->ptr == karg) {
				kref_put(&kmdlarg->refcount, NULL);
				list_del_init_careful(&rev_ref->list_node);
				kfree(rev_ref);
				break;
			}
		}
	}

	kptblarg = karg->ptbl_ref;
	if (kptblarg) {
		list_for_each_entry_safe(rev_ref, tmp_rev_ref,
				&kptblarg->node_rev_ref_list, list_node) {
			if (rev_ref->ptr == karg) {
				kref_put(&kptblarg->refcount, NULL);
				list_del_init_careful(&rev_ref->list_node);
				kfree(rev_ref);
				break;
			}
		}
	}

	list_for_each_entry_safe(rev_ref, tmp_rev_ref,
			&karg->parser_rev_ref_list, list_node) {
		karg_parser = rev_ref->ptr;
		karg_parser->rnode_ref = NULL;
		list_del_init_careful(&rev_ref->list_node);
		kfree(rev_ref);
		kref_put(&karg->refcount, NULL);
	}

	list_for_each_entry_safe(rev_ref, tmp_rev_ref,
			&karg->ptblent_rev_ref_list, list_node) {
		karg_ptbl_ent = rev_ref->ptr;
		karg_ptbl_ent->node_ref = NULL;
		list_del_init_careful(&rev_ref->list_node);
		kfree(rev_ref);
		kref_put(&karg->refcount, NULL);
	}

	kfree(karg);

	mutex_unlock(&kparser_config_lock);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
#endif
}

static void kparser_free_mdl(void *ptr, void *arg)
{
#if 0
	struct kparser_list *tmp_rev_ref = NULL;
	struct kparser_list *rev_ref = NULL;
	struct kparser_node *knode = NULL;
	struct kparser_mdl *karg = ptr;
	struct kparser_md *tmp_karg_md;
	struct kparser_md *karg_md;
	u32 refcnt;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	mutex_lock(&kparser_config_lock);

	refcnt = kref_read(&karg->refcount);
	if (refcnt != 1) {
		printk("%s:Active refcnt:%u \n",
			__FUNCTION__, refcnt);
	}

	pr_debug("%s:KEY:{%s:%u}, Refcnt:%u\n",
			__FUNCTION__, karg->arg.key.name,
			karg->arg.key.id, refcnt);

	mutex_destroy(&karg->mutex);

	list_for_each_entry_safe(karg_md, tmp_karg_md, &karg->mdl, mdl_node) {
		list_del_init_careful(&karg_md->mdl_node);
		kref_put(&karg_md->refcount, NULL);
	}

	list_for_each_entry_safe(rev_ref, tmp_rev_ref,
			&karg->node_rev_ref_list, list_node) {
		knode = rev_ref->ptr;
		knode->mdl_ref = NULL;
		list_del_init_careful(&rev_ref->list_node);
		kfree(rev_ref);
	}

	kfree(karg);
	mutex_unlock(&kparser_config_lock);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
#endif
}

static void kparser_free_md(void *ptr, void *arg)
{
#if 0
	struct kparser_md *karg = ptr;
	u32 refcnt;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	mutex_lock(&kparser_config_lock);

	refcnt = kref_read(&karg->refcount);
	if (refcnt != 1) {
		printk("%s:Active refcnt:%u \n",
			__FUNCTION__, refcnt);
	}

	pr_debug("%s:KEY:{%s:%u}, Refcnt:%u\n",
			__FUNCTION__,
			karg->arg.key.name,
			karg->arg.key.id,
			refcnt);

	mutex_destroy(&karg->mutex);
	list_del(&karg->mdl_node);
	kfree(karg);

	mutex_unlock(&kparser_config_lock);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
#endif
}

static void kparser_free_parser(void *ptr, void *arg)
{
#if 0
	struct kparser_list *tmp_rev_ref = NULL;
	struct kparser_list *rev_ref = NULL;
	struct kparser_node *knode = NULL;
	struct kparser_parser *karg = ptr;
	u32 refcnt;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	mutex_lock(&kparser_config_lock);
	refcnt = kref_read(&karg->refcount);
	if (refcnt != 1) {
		printk("%s:Active refcnt:%u \n",
			__FUNCTION__, refcnt);
		// return;
	}

	pr_debug("%s:KEY:{%s:%u}, Refcnt:%u\n",
			__FUNCTION__,
			karg->arg.key.name,
			karg->arg.key.id,
			refcnt);

	mutex_destroy(&karg->mutex);

	knode = karg->rnode_ref;
	if (knode) {
		list_for_each_entry_safe(rev_ref, tmp_rev_ref,
				&knode->parser_rev_ref_list, list_node) {
			if (rev_ref->ptr == karg) {
				kref_put(&knode->refcount, NULL);
				list_del_init_careful(&rev_ref->list_node);
				kfree(rev_ref);
				break;
			}
		}
	}

	kfree(karg);
	mutex_unlock(&kparser_config_lock);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
#endif
}

typedef int kparser_obj_create_update(const struct kparser_conf_cmd *conf,
		ssize_t conf_len, struct kparser_cmd_rsp_hdr **rsp,
		ssize_t *rsp_len);

typedef int kparser_obj_read_del(const struct kparser_hkey *key,
		struct kparser_cmd_rsp_hdr **rsp, ssize_t *rsp_len);

typedef void kparser_free_obj(void *ptr, void *arg);

struct kparser_mod_namespaces {
	enum kparser_global_namespace_ids namespace_id;
	const char *name;
	struct kparser_htbl htbl_name;
	struct kparser_htbl htbl_id;
	kparser_obj_create_update *create_handler;
	kparser_obj_create_update *update_handler;
	kparser_obj_read_del *read_handler;
	kparser_obj_read_del *del_handler;
	kparser_free_obj *free_handler;
	ssize_t bv_len;
	__u32 *bv;
};

kparser_obj_create_update
	kparser_create_md,
	kparser_create_mdl,
	kparser_create_proto_node,
	kparser_create_parse_node,
	kparser_create_proto_table,
	kparser_create_parser;

kparser_obj_read_del
	kparser_read_md,
	kparser_read_mdl,
	kparser_read_proto_node,
	kparser_read_parse_node,
	kparser_read_proto_table,
	kparser_read_parser,
	kparser_del_parser;

#define KPARSER_DEFINE_MOD_NAMESPACE(nsid, obj_name, field, g_ns_obj, create,	\
		read, update, delete, free)					\
static struct kparser_mod_namespaces g_ns_obj = {				\
	.namespace_id = KPARSER_NS_##nsid,					\
	.name = KPARSER_NAMESPACE_NAME_##nsid,					\
	.htbl_name =	{							\
		.tbl_params = {							\
			.head_offset = offsetof(				\
					struct k_##obj_name,			\
					field.ht_node_name),			\
			.key_offset = offsetof(					\
					struct k_##obj_name,			\
					field.key.name),			\
			.key_len = sizeof(((struct kparser_hkey *)0)->name),	\
			.automatic_shrinking = true,				\
			.hashfn = kparser_gnric_hash_fn_name,			\
			.obj_hashfn = kparser_gnric_obj_hashfn_name,		\
			.obj_cmpfn = kparser_cmp_fn_name,			\
		}								\
	},									\
	.htbl_id =	{							\
		.tbl_params = {							\
			.head_offset = offsetof(				\
					struct k_##obj_name,			\
					field.ht_node_id),			\
			.key_offset = offsetof(					\
					struct k_##obj_name,			\
					field.key.id),				\
			.key_len = sizeof(((struct kparser_hkey *)0)->id),	\
			.automatic_shrinking = true,				\
			.hashfn = kparser_gnric_hash_fn_id,			\
			.obj_hashfn = kparser_gnric_obj_hashfn_id,		\
			.obj_cmpfn = kparser_cmp_fn_id,				\
		}								\
	},									\
										\
	.create_handler = create,						\
	.read_handler = read,							\
	.update_handler = update,						\
	.del_handler = delete,							\
	.free_handler = free,							\
};										\

KPARSER_DEFINE_MOD_NAMESPACE(METADATA, metadata_extract, glue,
			     kparser_mod_namespace_md,
			     kparser_create_md,
			     kparser_read_md,
			     NULL,
			     NULL,
			     kparser_free_md);

KPARSER_DEFINE_MOD_NAMESPACE(METALIST, metadata_table, glue,
		kparser_mod_namespace_mdl,
		kparser_create_mdl,
		kparser_read_mdl,
		NULL,
		NULL,
		kparser_free_mdl);

KPARSER_DEFINE_MOD_NAMESPACE(NODE_PROTO, proto_node, glue.glue,
		kparser_mod_namespace_node_proto,
		kparser_create_proto_node,
		kparser_read_proto_node,
		NULL,
		NULL,
		kparser_free_node_tbl);

KPARSER_DEFINE_MOD_NAMESPACE(NODE_PARSE, parse_node, glue.glue,
		kparser_mod_namespace_node_parse,
		kparser_create_parse_node,
		kparser_read_parse_node,
		NULL,
		NULL,
		kparser_free_node_tbl);

KPARSER_DEFINE_MOD_NAMESPACE(PROTO_TABLE, protocol_table, glue,
		kparser_mod_namespace_proto_table,
		kparser_create_proto_table,
		kparser_read_proto_table,
		NULL,
		NULL,
		kparser_free_node_tbl);

KPARSER_DEFINE_MOD_NAMESPACE(TLV_NODE_PROTO, proto_tlv_node, glue.glue,
		kparser_mod_namespace_tlv_node_proto,
		NULL,
		NULL,
		NULL,
		NULL,
		kparser_free_node_tbl);

KPARSER_DEFINE_MOD_NAMESPACE(TLV_NODE_PARSE, parse_tlv_node, glue.glue,
		kparser_mod_namespace_tlv_node_parse,
		NULL,
		NULL,
		NULL,
		NULL,
		kparser_free_node_tbl);

KPARSER_DEFINE_MOD_NAMESPACE(TLVS_NODE_PROTO, proto_tlvs_node, glue.glue,
		kparser_mod_namespace_tlvs_node_proto,
		NULL,
		NULL,
		NULL,
		NULL,
		kparser_free_node_tbl);

KPARSER_DEFINE_MOD_NAMESPACE(TLVS_NODE_PARSE, parse_tlvs_node, glue.glue,
		kparser_mod_namespace_tlvs_node_parse,
		NULL,
		NULL,
		NULL,
		NULL,
		kparser_free_node_tbl);

KPARSER_DEFINE_MOD_NAMESPACE(TLV_PROTO_TABLE, proto_tlvs_table, glue,
		kparser_mod_namespace_tlv_proto_table,
		NULL,
		NULL,
		NULL,
		NULL,
		kparser_free_node_tbl);

KPARSER_DEFINE_MOD_NAMESPACE(FIELDS, flag_field, glue,
		kparser_mod_namespace_flag_fields,
		NULL,
		NULL,
		NULL,
		NULL,
		kparser_free_node_tbl); // TODO

KPARSER_DEFINE_MOD_NAMESPACE(PARSER, parser, glue,
		kparser_mod_namespace_parser,
		kparser_create_parser,
		kparser_read_parser,
		NULL,
		NULL, //kparser_del_parser,
		NULL); // kparser_free_parser);

static struct kparser_mod_namespaces *g_mod_namespaces[] = 
{
        [KPARSER_NS_INVALID] = NULL,
        [KPARSER_NS_METADATA] = &kparser_mod_namespace_md,
        [KPARSER_NS_METALIST] = &kparser_mod_namespace_mdl,
        [KPARSER_NS_NODE_PROTO] = &kparser_mod_namespace_node_proto,
        [KPARSER_NS_NODE_PARSE] = &kparser_mod_namespace_node_parse,
        [KPARSER_NS_PROTO_TABLE] = &kparser_mod_namespace_proto_table,
        [KPARSER_NS_TLV_NODE_PROTO] = &kparser_mod_namespace_tlv_node_proto,
        [KPARSER_NS_TLV_NODE_PARSE] = &kparser_mod_namespace_tlv_node_parse,
        [KPARSER_NS_TLVS_NODE_PROTO] = &kparser_mod_namespace_tlvs_node_proto,
        [KPARSER_NS_TLVS_NODE_PARSE] = &kparser_mod_namespace_tlvs_node_parse,
        [KPARSER_NS_TLV_PROTO_TABLE] = &kparser_mod_namespace_tlv_proto_table,
        [KPARSER_NS_FIELDS] = &kparser_mod_namespace_flag_fields,
        [KPARSER_NS_PARSER] = &kparser_mod_namespace_parser,
        [KPARSER_NS_CONDEXPRS] = NULL, // TODO
        [KPARSER_NS_MAX] = NULL,
};

extern void rhashtable_destroy(struct rhashtable *ht);
extern void rhashtable_free_and_destroy(struct rhashtable *ht,
		void (*free_fn)(void *ptr, void *arg), void *arg);

// TODO: free ids 
static inline __u16 allocate_id(__u16 id, int *bv, size_t bvsize)
{
	int i;

	if (id != KPARSER_INVALID_ID) {
		// try to allocate passed id
		if (!testbit(bv, id)) // already allocated, conflict
			return KPARSER_INVALID_ID;
		clearbit(bv, id);
		return id;
	}

	// allocate internally
	// scan bitvector
	for (i = 0; i < bvsize; i++) {
		// avoid bit vectors which are already full
		if (bv[i]) {
			id = __builtin_ffs(bv[i]);
			if (id) {
				id--;
				id += (i * BITS_IN_U32);
				clearbit(bv, id);
				return (id + KPARSER_KMOD_ID_MIN);
			}
			printk("failed here:%d:%d\n", id, i);
			return KPARSER_INVALID_ID;
		}
	}

	printk("failed now here:%d\n", i);
	return KPARSER_INVALID_ID;
}

static inline bool kparser_allocate_key_id(
		enum kparser_global_namespace_ids ns_id,
		const struct kparser_hkey *key,
		struct kparser_hkey *new_key)
{
		*new_key = *key;
                new_key->id = allocate_id(KPARSER_INVALID_ID,
				g_mod_namespaces[ns_id]->bv,
				g_mod_namespaces[ns_id]->bv_len);

                if (new_key->id == KPARSER_INVALID_ID)
			return false;

		return true;
}

static inline bool kparser_allocate_key_name(
		enum kparser_global_namespace_ids ns_id,
		const struct kparser_hkey *key,
		struct kparser_hkey *new_key)
{
		*new_key = *key;
		memset(new_key->name, 0, sizeof(new_key->name));
		snprintf(new_key->name, sizeof(new_key->name),
				"%s-%s-%u", KPARSER_DEF_NAME_PREFIX,
				g_mod_namespaces[ns_id]->name, key->id);
		new_key->name[sizeof(new_key->name) - 1] = '\0';
		return true;
}

static inline bool kparser_conf_key_manager(
		enum kparser_global_namespace_ids ns_id,
		const struct kparser_hkey *key,
		struct kparser_hkey *new_key,
		struct kparser_cmd_rsp_hdr *rsp)
{
	if (kparser_hkey_empty(key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: HKey missing", __FUNCTION__);
		return false;
	}

	if (kparser_hkey_id_empty(key) && new_key) {
		return kparser_allocate_key_id(ns_id, key, new_key);
	}

	if (kparser_hkey_user_id_invalid(key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: HKey id invalid:%u",
				__FUNCTION__, key->id);
		return false;
	}

	if (kparser_hkey_name_empty(key) && new_key) {
		return kparser_allocate_key_name(ns_id, key, new_key);
	}

	if (new_key)
		*new_key = *key;

	return true;
}

void * kparser_namespace_lookup(
		enum kparser_global_namespace_ids ns_id,
		const struct kparser_hkey *key)
{
	void *ret;

	if (ns_id == KPARSER_NS_INVALID || ns_id >= KPARSER_NS_MAX)
		return NULL;

	if (!g_mod_namespaces[ns_id])
		return NULL;

	ret = rhashtable_lookup(&g_mod_namespaces[ns_id]->htbl_id.tbl,
				&key->id,
				g_mod_namespaces[ns_id]->htbl_id.tbl_params);

	if (ret)
		return ret;

	ret = rhashtable_lookup(&g_mod_namespaces[ns_id]->htbl_name.tbl,
				key->name,
				g_mod_namespaces[ns_id]->htbl_name.tbl_params);

	return ret;
}

static inline int kparser_namespace_insert(
		enum kparser_global_namespace_ids ns_id,
		struct rhash_head *obj_id,
		struct rhash_head *obj_name)
{
	int rc;

	if (ns_id == KPARSER_NS_INVALID || ns_id >= KPARSER_NS_MAX)
		return EINVAL;

	if (!g_mod_namespaces[ns_id])
		return ENOENT;

	rc = rhashtable_insert_fast(
			&g_mod_namespaces[ns_id]->htbl_id.tbl, obj_id,
			g_mod_namespaces[ns_id]->htbl_id.tbl_params);

	if (rc)
		return rc;

	rc = rhashtable_insert_fast(
			&g_mod_namespaces[ns_id]->htbl_name.tbl, obj_name,
			g_mod_namespaces[ns_id]->htbl_name.tbl_params);

	return rc;
}

int kparser_init(void)
{
	int err, i, j;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	for (i = 0; i < (sizeof(g_mod_namespaces) /
				sizeof(g_mod_namespaces[0])); i++) {

		if (!g_mod_namespaces[i])
			continue;

		err = rhashtable_init(&g_mod_namespaces[i]->htbl_name.tbl,
				&g_mod_namespaces[i]->htbl_name.tbl_params);
		if (err)
			break;

		err = rhashtable_init(&g_mod_namespaces[i]->htbl_id.tbl,
				&g_mod_namespaces[i]->htbl_id.tbl_params);
		if (err)
			break;

		g_mod_namespaces[i]->bv_len =
			((KPARSER_KMOD_ID_MAX - KPARSER_KMOD_ID_MIN) /
			 BITS_IN_U32) + 1;

		g_mod_namespaces[i]->bv = kzalloc(
				sizeof(__u32) * g_mod_namespaces[i]->bv_len,
				GFP_KERNEL);

		if (!g_mod_namespaces[i]->bv) {
			printk("%s: kzalloc() failed\n", __FUNCTION__);
			break;
		}

		memset(g_mod_namespaces[i]->bv, 0xff,
				g_mod_namespaces[i]->bv_len * sizeof(__u32));
	}

	pr_debug("OUT: %s:%s:%d:err:%d\n", __FILE__, __FUNCTION__,
			__LINE__, err);

	if (!err)
		return 0;

	for (j = 0; j < i; j++) {

		if (!g_mod_namespaces[j])
			continue;

		rhashtable_destroy(&g_mod_namespaces[j]->htbl_name.tbl);
		rhashtable_destroy(&g_mod_namespaces[j]->htbl_id.tbl);

		if (g_mod_namespaces[j]->bv)
			kfree(g_mod_namespaces[j]->bv);
		g_mod_namespaces[j]->bv_len = 0;
	}

	pr_debug("%s() failed, err: %d\n", __FUNCTION__, err);

	return err;
}

int kparser_deinit(void)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	for (i = 0; i < (sizeof(g_mod_namespaces) /
				sizeof(g_mod_namespaces[0])); i++) {

		if (!g_mod_namespaces[i])
			continue;

		rhashtable_destroy(&g_mod_namespaces[i]->htbl_name.tbl);
		rhashtable_free_and_destroy(&g_mod_namespaces[i]->htbl_id.tbl,
				g_mod_namespaces[i]->free_handler,
				NULL);

		if (g_mod_namespaces[i]->bv)
			kfree(g_mod_namespaces[i]->bv);

		g_mod_namespaces[i]->bv_len = 0;
	}

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return 0;
}

int kparser_create_md(const struct kparser_conf_cmd *conf,
		      ssize_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      ssize_t *rsp_len)
{
	const struct kparser_conf_metadata *arg;
	struct k_metadata_extract *kmde = NULL;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!conf || conf_len < sizeof(*conf) || !rsp ||
			*rsp || !rsp_len || (*rsp_len != 0) ||
			(conf->namespace_id != KPARSER_NS_METADATA)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	mutex_lock(&kparser_config_lock);

	arg = &conf->md_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	kmde = kzalloc(sizeof(*kmde), GFP_KERNEL);
	if (!kmde) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	kmde->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kmde->glue.ht_node_id,
				      &kmde->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	kmde->glue.config.namespace_id = conf->namespace_id;
	kmde->glue.config.md_conf = *arg;
	kmde->glue.config.md_conf.key = key;
	kref_init(&kmde->glue.refcount);

	if (!kparser_md_convert(arg, &kmde->mde)) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_md_convert() err",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = key;
	(*rsp)->object.namespace_id = conf->namespace_id;
	(*rsp)->object.md_conf = kmde->glue.config.md_conf;
	(*rsp)->objects_len = 0;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (kmde)
			kfree(kmde);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_METADATA;
}

int kparser_read_md(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    ssize_t *rsp_len)
{
	const struct k_metadata_extract *kmde;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!key || !rsp || *rsp || !rsp_len || (*rsp_len != 0)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmde = kparser_namespace_lookup(KPARSER_NS_METADATA, key);
	if (!kmde) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = kmde->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.namespace_id = kmde->glue.config.namespace_id;
	(*rsp)->object.md_conf = kmde->glue.config.md_conf;
	(*rsp)->objects_len = 0;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_METADATA;
}

int kparser_create_mdl(const struct kparser_conf_cmd *conf,
		      ssize_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      ssize_t *rsp_len)
{
	const struct kparser_conf_metadata_table *arg;
	const struct k_metadata_extract *kmde = NULL;
	struct k_metadata_table *kmdl = NULL;
	struct kparser_hkey key;
	int rc, i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!conf || conf_len < sizeof(*conf) || !rsp ||
			*rsp || !rsp_len || (*rsp_len != 0) ||
			(conf->namespace_id != KPARSER_NS_METALIST)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	mutex_lock(&kparser_config_lock);

	arg = &conf->mdl_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	kmdl = kzalloc(sizeof(*kmdl), GFP_KERNEL);
	if (!kmdl) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	kmdl->glue.key = key;
	kmdl->glue.config.namespace_id = conf->namespace_id;
	kmdl->glue.config.mdl_conf = *arg;
	kmdl->glue.config.mdl_conf.key = key;
	kmdl->glue.config.mdl_conf.metadata_keys_count = 0;
	kref_init(&kmdl->glue.refcount);

	conf_len -= sizeof(*conf);

	for (i = 0; i < arg->metadata_keys_count; i++) {

		if (conf_len < sizeof(struct kparser_hkey)) {
			(*rsp)->op_ret_code = EINVAL;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: conf len/buffer incomplete",
					__FUNCTION__);
			goto done;
		}

		conf_len -= sizeof(struct kparser_hkey);

		pr_debug("Key: {ID:%u Name:%s}\n",
				arg->metadata_keys[i].id,
				arg->metadata_keys[i].name);

		kmde = kparser_namespace_lookup(KPARSER_NS_METADATA,
						&arg->metadata_keys[i]);
		if (!kmde) {
			(*rsp)->op_ret_code = ENOENT;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: Object key {%s:%u} not found",
					__FUNCTION__,
					arg->metadata_keys[i].name,
					arg->metadata_keys[i].id);
			goto done;
		}
		kmdl->metadata_table.num_ents++;
		kmdl->metadata_table.entries = krealloc(
				kmdl->metadata_table.entries,
				kmdl->metadata_table.num_ents * sizeof(*kmde),
				GFP_KERNEL | ___GFP_ZERO);
		if (!kmdl->metadata_table.entries) {
			(*rsp)->op_ret_code = ENOMEM;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: krealloc() err, ents:%d, size:%lu",
					__FUNCTION__,
					kmdl->metadata_table.num_ents,
					sizeof(*kmde));
			goto done;
		}
		kmdl->metadata_table.entries[i] = kmde->mde;

		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + ((*rsp)->objects_len *
				sizeof(struct kparser_conf_cmd));
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
				__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			if (kmdl) {
				if (kmdl->metadata_table.entries)
					kfree(kmdl->metadata_table.entries);
				kfree(kmdl);
			}
			return KPARSER_ATTR_UNSPEC;
		}
		(*rsp)->objects[i].namespace_id =
			kmde->glue.config.namespace_id;
		(*rsp)->objects[i].md_conf = kmde->glue.config.md_conf;

		kmdl->md_configs_len++;
		kmdl->md_configs = krealloc(kmdl->md_configs,
				kmdl->md_configs_len *
				sizeof(struct kparser_conf_cmd),
				GFP_KERNEL | ___GFP_ZERO);
		if (!kmdl->md_configs) {
			(*rsp)->op_ret_code = ENOMEM;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: krealloc() err, ents:%lu, size:%lu",
					__FUNCTION__,
					kmdl->md_configs_len,
					sizeof(struct kparser_conf_cmd));
			goto done;
		}
		kmdl->md_configs[i].namespace_id =
			kmde->glue.config.namespace_id;
		kmdl->md_configs[i].md_conf = kmde->glue.config.md_conf; 
	}

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kmdl->glue.ht_node_id,
				      &kmdl->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = key;
	(*rsp)->object.namespace_id = conf->namespace_id;
	(*rsp)->object.mdl_conf = kmdl->glue.config.mdl_conf;
	(*rsp)->object.mdl_conf.metadata_keys_count = 0;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (kmdl) {
			if (kmdl->metadata_table.entries)
				kfree(kmdl->metadata_table.entries);
			if (kmdl->md_configs)
				kfree(kmdl->md_configs);
			kfree(kmdl);
		}
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_METALIST;
}

int kparser_read_mdl(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    ssize_t *rsp_len)
{
	const struct k_metadata_table *kmdl;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!key || !rsp || *rsp || !rsp_len || (*rsp_len != 0)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST, key);
	if (!kmdl) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(*rsp)->key = kmdl->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.namespace_id = kmdl->glue.config.namespace_id;
	(*rsp)->object.mdl_conf = kmdl->glue.config.mdl_conf;

	for (i = 0; i < kmdl->md_configs_len; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + ((*rsp)->objects_len *
				sizeof(struct kparser_conf_cmd));
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
				__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		(*rsp)->objects[i].namespace_id =
			kmdl->md_configs[i].namespace_id;
		(*rsp)->objects[i].md_conf = kmdl->md_configs[i].md_conf;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_METALIST;
}

int kparser_create_proto_node(const struct kparser_conf_cmd *conf,
		      ssize_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      ssize_t *rsp_len)
{
	const struct kparser_conf_node_proto *arg;
	struct k_proto_node *kprotonode = NULL;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!conf || conf_len < sizeof(*conf) || !rsp ||
			*rsp || !rsp_len || (*rsp_len != 0) ||
			(conf->namespace_id != KPARSER_NS_NODE_PROTO)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	mutex_lock(&kparser_config_lock);

	arg = &conf->node_proto_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	kprotonode = kzalloc(sizeof(*kprotonode), GFP_KERNEL);
	if (!kprotonode) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	kprotonode->glue.glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kprotonode->glue.glue.ht_node_id,
				      &kprotonode->glue.glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	kprotonode->glue.glue.config.namespace_id = conf->namespace_id;
	kprotonode->glue.glue.config.node_proto_conf = *arg;
	kprotonode->glue.glue.config.node_proto_conf.key = key;
	kref_init(&kprotonode->glue.glue.refcount);

	if (!kparser_proto_node_convert(arg, &kprotonode->node)) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_proto_node_convert() err",
				__FUNCTION__);
		goto done;
	}


	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = key;
	(*rsp)->object.namespace_id = conf->namespace_id;
	(*rsp)->object.node_proto_conf =
		kprotonode->glue.glue.config.node_proto_conf;
	(*rsp)->objects_len = 0;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (kprotonode)
			kfree(kprotonode);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_NODE_PROTO;
}

int kparser_read_proto_node(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    ssize_t *rsp_len)
{
	const struct k_proto_node *kprotonode;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!key || !rsp || *rsp || !rsp_len || (*rsp_len != 0)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kprotonode = kparser_namespace_lookup(KPARSER_NS_NODE_PROTO, key);
	if (!kprotonode) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = kprotonode->glue.glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.namespace_id = kprotonode->glue.glue.config.namespace_id;
	(*rsp)->object.node_proto_conf =
		kprotonode->glue.glue.config.node_proto_conf;
	(*rsp)->objects_len = 0;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_NODE_PROTO;
}

int kparser_create_parse_node(const struct kparser_conf_cmd *conf,
		      ssize_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      ssize_t *rsp_len)
{
	struct k_parse_node *kparsenode = NULL, *kparsewildcardnode = NULL;
	struct kparser_metadata_table *metadata_table = NULL;
	struct kparser_parse_node *wildcardnode = NULL;
	struct kparser_proto_table *proto_table = NULL;
	struct kparser_proto_node *protonode = NULL;
	const struct kparser_conf_node_parse *arg;
	struct k_protocol_table *kprototbl = NULL;
	struct k_proto_node *kprotonode = NULL;
	struct k_metadata_table *kmdl = NULL;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!conf || conf_len < sizeof(*conf) || !rsp ||
			*rsp || !rsp_len || (*rsp_len != 0) ||
			(conf->namespace_id != KPARSER_NS_NODE_PARSE)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	mutex_lock(&kparser_config_lock);

	arg = &conf->node_parse_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	kparsenode = kzalloc(sizeof(*kparsenode), GFP_KERNEL);
	if (!kparsenode) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	kparsenode->glue.glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kparsenode->glue.glue.ht_node_id,
				      &kparsenode->glue.glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	kparsenode->glue.glue.config.namespace_id = conf->namespace_id;
	kparsenode->glue.glue.config.node_parse_conf = *arg;
	kparsenode->glue.glue.config.node_parse_conf.key = key;
	kref_init(&kparsenode->glue.glue.refcount);

	kparsewildcardnode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&arg->wildcard_parse_node);
	if (kparsewildcardnode)
		wildcardnode = &kparsewildcardnode->node;

	kprotonode = kparser_namespace_lookup(KPARSER_NS_NODE_PROTO,
			&arg->proto_node);
	if (kprotonode)
		protonode = &kprotonode->node;

	kprototbl = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE,
			&arg->proto_table);
	if (kprototbl)
		proto_table = &kprototbl->proto_table;

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST,
			&arg->metadata_table);
	if (kmdl)
		metadata_table = &kmdl->metadata_table;

	if (!kparser_parse_node_convert(arg, &kparsenode->node,
					protonode,
					proto_table,
					wildcardnode,
					metadata_table)) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_parse_node_convert() err",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = key;
	(*rsp)->object.namespace_id = conf->namespace_id;
	(*rsp)->object.node_parse_conf =
		kparsenode->glue.glue.config.node_parse_conf;
	(*rsp)->objects_len = 0;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (kparsenode)
			kfree(kparsenode);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_NODE_PARSE;
}

int kparser_read_parse_node(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    ssize_t *rsp_len)
{
	const struct k_parse_node *kparsenode;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!key || !rsp || *rsp || !rsp_len || (*rsp_len != 0)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparsenode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, key);
	if (!kparsenode) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = kparsenode->glue.glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.namespace_id = kparsenode->glue.glue.config.namespace_id;
	(*rsp)->object.node_parse_conf =
		kparsenode->glue.glue.config.node_parse_conf;
	(*rsp)->objects_len = 0;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_NODE_PARSE;
}

static bool kparser_create_proto_table_ent(
		const struct kparser_conf_proto_table *arg,
		struct k_protocol_table **proto_table,
		struct kparser_cmd_rsp_hdr *rsp)
{
	const struct k_parse_node *kparsenode;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE,
			&arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		return false;
	}

	kparsenode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&arg->parse_node_key);
	if (!kparsenode) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key:{%s:%u} not found",
				__FUNCTION__,
				arg->parse_node_key.name,
				arg->parse_node_key.id);
		return false;
	}

	if (arg->idx >= (*proto_table)->proto_table.num_ents) {
		(*proto_table)->proto_table.num_ents++;
		(*proto_table)->proto_table.entries = krealloc(
				(*proto_table)->proto_table.entries,
				(*proto_table)->proto_table.num_ents *
				sizeof(struct kparser_proto_table_entry),
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*proto_table)->proto_table.entries) {
			rsp->op_ret_code = ENOMEM;
			(void) snprintf(rsp->err_str_buf,
					sizeof(rsp->err_str_buf),
					"%s: krealloc() err, ents:%d, size:%lu",
					__FUNCTION__,
					(*proto_table)->proto_table.num_ents,
					sizeof(struct kparser_proto_table_entry));
			return false;
		}
	}

	(*proto_table)->proto_table.entries[arg->idx].value = arg->value;
	(*proto_table)->proto_table.entries[arg->idx].node = &kparsenode->node;

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return true;
}

int kparser_create_proto_table(const struct kparser_conf_cmd *conf,
		      ssize_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      ssize_t *rsp_len)
{
	const struct kparser_conf_proto_table *arg;
	struct k_protocol_table *proto_table = NULL;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!conf || conf_len < sizeof(*conf) || !rsp ||
			*rsp || !rsp_len || (*rsp_len != 0) ||
			(conf->namespace_id != KPARSER_NS_PROTO_TABLE)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	mutex_lock(&kparser_config_lock);

	arg = &conf->proto_table_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	//create protocol table entry
	if ((arg->idx != 0xffff) &&
		(kparser_create_proto_table_ent(arg,
					&proto_table, *rsp) == false)) {
		goto done;
	}

	goto skip_table_create;

	//create protocol table
	proto_table = kzalloc(sizeof(*proto_table), GFP_KERNEL);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	proto_table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
			&proto_table->glue.ht_node_id,
			&proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.proto_table_conf = *arg;
	proto_table->glue.config.proto_table_conf.key = key;
	kref_init(&proto_table->glue.refcount);

skip_table_create:
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = key;
	(*rsp)->object.namespace_id = conf->namespace_id;
	(*rsp)->object.proto_table_conf =
		proto_table->glue.config.proto_table_conf;
	(*rsp)->objects_len = 0;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (proto_table && (arg->idx == 0xffff))
			kfree(proto_table);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_PROTO_TABLE;
}

int kparser_read_proto_table(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    ssize_t *rsp_len)
{
	const struct k_protocol_table *proto_table;
	const struct k_parse_node *parse_node;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!key || !rsp || *rsp || !rsp_len || (*rsp_len != 0)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.namespace_id = proto_table->glue.config.namespace_id;
	(*rsp)->object.proto_table_conf =
		proto_table->glue.config.proto_table_conf;
	(*rsp)->objects_len = 0;

	for (i = 0; i < proto_table->proto_table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + ((*rsp)->objects_len *
				sizeof(struct kparser_conf_cmd));
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
					__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		(*rsp)->objects[i].namespace_id =
			proto_table->glue.config.namespace_id;
		(*rsp)->objects[i].proto_table_conf =
			proto_table->glue.config.proto_table_conf;
		(*rsp)->objects[i].proto_table_conf.idx = i;
		(*rsp)->objects[i].proto_table_conf.value =
			proto_table->proto_table.entries[i].value;
		parse_node = container_of(proto_table->proto_table.entries[i].node,
				struct k_parse_node, node);
		(*rsp)->objects[i].proto_table_conf.parse_node_key =
			parse_node->glue.glue.key;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_PROTO_TABLE;
}

int kparser_create_parser(const struct kparser_conf_cmd *conf,
		      ssize_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      ssize_t *rsp_len)
{
	struct k_parse_node *root = NULL, *ok = NULL, *fail = NULL;
	struct kparser_parse_node *rootnode = NULL, *oknode = NULL;
	struct kparser_parse_node *failnode = NULL;
	const struct kparser_conf_parser *arg;
	struct k_parser *kparsr = NULL;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!conf || conf_len < sizeof(*conf) || !rsp ||
			*rsp || !rsp_len || (*rsp_len != 0) ||
			(conf->namespace_id != KPARSER_NS_PARSER)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	mutex_lock(&kparser_config_lock);

	arg = &conf->parser_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	kparsr = kzalloc(sizeof(*kparsr), GFP_KERNEL);
	if (!kparsr) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	kparsr->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kparsr->glue.ht_node_id,
				      &kparsr->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	kparsr->glue.config.namespace_id = conf->namespace_id;
	kparsr->glue.config.parser_conf = *arg;
	kparsr->glue.config.parser_conf.key = key;
	kref_init(&kparsr->glue.refcount);

	root = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&arg->root_node_key);
	if (root)
		rootnode = &root->node;

	ok = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&arg->ok_node_key);
	if (ok)
		oknode = &ok->node;

	fail = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&arg->fail_node_key);
	if (fail)
		failnode = &fail->node;

	if (!kparser_parser_convert(arg, &kparsr->parser,
				    rootnode, oknode, failnode)) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_parse_node_convert() err",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = key;
	(*rsp)->object.namespace_id = conf->namespace_id;
	(*rsp)->object.parser_conf =
		kparsr->glue.config.parser_conf;
	(*rsp)->objects_len = 0;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (kparsr)
			kfree(kparsr);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_PARSER;
}

int kparser_read_parser(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    ssize_t *rsp_len)
{
	const struct k_parser *kparsr;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!key || !rsp || *rsp || !rsp_len || (*rsp_len != 0)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparsr = kparser_namespace_lookup(KPARSER_NS_PARSER, key);
	if (!kparsr) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s: ok", __FUNCTION__);

	(*rsp)->key = kparsr->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.namespace_id = kparsr->glue.config.namespace_id;
	(*rsp)->object.parser_conf =
		kparsr->glue.config.parser_conf;
	(*rsp)->objects_len = 0;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP_PARSER;
}


#if 0
void kparser_create_md(const struct kparser_arg_md *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	struct kparser_cmd_rsp_hdr *rsp;
	struct kparser_md *karg = NULL;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);
	
	pr_debug("MD Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_hkey_empty(&arg->key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: MD Key missing", __FUNCTION__);
		goto done;
	}

	pr_debug("MD Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("MD:soff:%u doff:%u len:%lu \n", arg->soff, arg->doff, arg->len);

	if (kparser_namespace_lookup(KPARSER_NS_INVALID, &arg->key)) {
		rsp->op_ret_code = -EEXIST;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Duplicate Key", __FUNCTION__);
		goto done;
	}

	karg = kzalloc(sizeof(*karg), GFP_KERNEL);
	if (!karg) {
		rsp->op_ret_code = -ENOMEM;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	karg->arg = *arg;
	rc = rhashtable_insert_fast(&g_tbl_md.tbl, &karg->ht_node,
			g_tbl_md.tbl_params);
	if (rc) {
		rsp->op_ret_code = rc;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: rhashtable_insert_fast() err",
				__FUNCTION__);
		goto done;
	}

	mutex_init(&karg->mutex);
	kref_init(&karg->refcount);
	if (1) {
		// TODO:
		karg->arg.config =
			kparser_metadata_make_byte_extract(
					karg->arg.soff,
					karg->arg.doff,
					karg->arg.len,
					true);
	}

	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s ok", __FUNCTION__);

done:
	mutex_unlock(&kparser_config_lock);

	if (rsp->op_ret_code != 0)
		if (karg)
			kfree(karg);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}
#endif


#if 0
void kparser_add_mdl(const struct kparser_arg_mdl *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	struct kparser_cmd_rsp_hdr *rsp;
	struct kparser_md *karg_mmd = NULL;
	struct kparser_md *karg_md = NULL;
	struct kparser_mdl *karg = NULL;
	u16 idx;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	rsp->op_ret_code = 0;
	rsp->key = arg->key;
	rsp->err_str_buf[0] = '\0';

	mutex_lock(&kparser_config_lock);

	if (kparser_hkey_empty(&arg->key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: MDL Key missing", __FUNCTION__);
		goto done;
	}

	pr_debug("MDL Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("MDL MMD Key: {ID:%u Name:%s}\n",
			arg->mdkey.id, arg->mdkey.name);

	if (kparser_namespace_lookup(KPARSER_NS_INVALID, &arg->key)) {
		rsp->op_ret_code = -EEXIST;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Duplicate Key", __FUNCTION__);
		goto done;
	}

	karg = kzalloc(sizeof(*karg), GFP_KERNEL);
	if (!karg) {
		rsp->op_ret_code = -ENOMEM;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	karg_mmd = kparser_namespace_lookup(KPARSER_NS_INVALID, &arg->key);
	if (karg_mmd == NULL) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: MMD Key {%u:%s} not found.",
				__FUNCTION__, arg->mdkey.id,
				arg->mdkey.name);
		goto done;
	}

	for (idx = 0; idx < arg->mdkeys_count; idx++) {
		pr_debug("MDL MD Key: {ID:%u Name:%s}\n",
				arg->mdkeys[idx].id, arg->mdkeys[idx].name);
		karg_md = kparser_namespace_lookup(KPARSER_NS_INVALID,
				&arg->mdkeys[idx]);
		if (karg_md == NULL) {
			rsp->op_ret_code = -EINVAL;
			(void) snprintf(rsp->err_str_buf,
					sizeof(rsp->err_str_buf),
					"%s: MD Key {%u:%s} not found.",
					__FUNCTION__, arg->mdkeys[idx].id,
					arg->mdkeys[idx].name);
			goto done;
		}
	}

	karg->arg = *arg;
	rc = rhashtable_insert_fast(&g_tbl_mdl.tbl, &karg->ht_node,
			g_tbl_mdl.tbl_params);
	if (rc) {
		rsp->op_ret_code = rc;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: rhashtable_insert_fast() err",
				__FUNCTION__);
		goto done;
	}

	mutex_init(&karg->mutex);
	kref_init(&karg->refcount);
	INIT_LIST_HEAD(&karg->mdl);
	INIT_LIST_HEAD(&karg->node_rev_ref_list);
	// TODO: allow sharing MD node across multiple MDLs
	list_add(&karg_mmd->mdl_node, &karg->mdl);
	kref_get(&karg_mmd->refcount);

	for (idx = 0; idx < arg->mdkeys_count; idx++) {
		karg_md = kparser_namespace_lookup(KPARSER_NS_INVALID,
				&arg->mdkeys[idx]);
		list_add(&karg_md->mdl_node, &karg->mdl);
		kref_get(&karg_md->refcount);
	}

	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s ok", __FUNCTION__);
done:
	mutex_unlock(&kparser_config_lock);

	if (rsp->op_ret_code != 0)
		if (karg)
			kfree(karg);


	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_add_proto_tbl(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	struct kparser_proto *karg = NULL;
	struct kparser_cmd_rsp_hdr *rsp;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	rsp->op_ret_code = 0;
	rsp->key = arg->key;
	rsp->err_str_buf[0] = '\0';

	mutex_lock(&kparser_config_lock);

	if (kparser_hkey_empty(&arg->key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Proto Tbl Key missing", __FUNCTION__);
		goto done;
	}

	pr_debug("PTBL Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("PTBL def_val:%d\n", arg->def_val);

	if (kparser_namespace_lookup(KPARSER_NS_INVALID, &arg->key)) {
		rsp->op_ret_code = -EEXIST;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Duplicate Key", __FUNCTION__);
		goto done;
	}

	karg = kzalloc(sizeof(*karg), GFP_KERNEL);
	if (!karg) {
		rsp->op_ret_code = -ENOMEM;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	karg->arg = *arg;
	rc = rhashtable_insert_fast(&g_tbl_proto.tbl, &karg->ht_node,
			g_tbl_parser.tbl_params);
	if (rc) {
		rsp->op_ret_code = rc;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: rhashtable_insert_fast() err",
				__FUNCTION__);
		goto done;
	}

	mutex_init(&karg->mutex);
	kref_init(&karg->refcount);
	INIT_LIST_HEAD(&karg->node_rev_ref_list);
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s ok", __FUNCTION__);

done:
	mutex_unlock(&kparser_config_lock);

	if (rsp->op_ret_code != 0)
		if (karg)
			kfree(karg);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_add_proto_tbl_ent(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	struct kparser_proto_ent *new_ent = NULL;
	struct kparser_list *rev_ref_list = NULL;
	struct kparser_proto *kptblarg = NULL;
	struct kparser_node *knodearg = NULL;
	struct kparser_cmd_rsp_hdr *rsp;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	rsp->op_ret_code = 0;
	rsp->key = arg->key;
	rsp->err_str_buf[0] = '\0';

	if (kparser_hkey_empty(&arg->key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Proto Tbl Key missing", __FUNCTION__);
		goto done;
	}

	pr_debug("PTBL Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("PTBL ENT Key: {ID:%u Name:%s}\n",
			arg->tbl_ent.key.id, arg->tbl_ent.key.name);
	pr_debug("PTBL ENT idx_key_map:%u\n", arg->tbl_ent.idx_key_map);
	pr_debug("PTBL ENT Node Key: {ID:%u Name:%s}\n",
			arg->tbl_ent.node_key.id, arg->tbl_ent.node_key.name);

	kptblarg = kparser_namespace_lookup(KPARSER_NS_INVALID, &arg->key);
	if (kptblarg == NULL) {
		rsp->op_ret_code = -ENOENT;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Proto Table key not found!", __FUNCTION__);
		goto done;
	}

	knodearg = kparser_namespace_lookup(KPARSER_NS_INVALID,
			&arg->tbl_ent.node_key);
	if (knodearg == NULL) {
		rsp->op_ret_code = -ENOENT;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: PTBL Entry's node key not found!",
				__FUNCTION__);
		goto done;
	}

	new_ent = krealloc_array(kptblarg->ent_tbl, kptblarg->ent_tbl_size + 1,
			sizeof(*new_ent), GFP_KERNEL | ___GFP_ZERO);
	if (new_ent == NULL) {
		rsp->op_ret_code = -ENOMEM;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: krealloc_array() failed!", __FUNCTION__);
		goto done;
	}
	rev_ref_list = kzalloc(sizeof(*rev_ref_list), GFP_KERNEL);
	if (!rev_ref_list) {
		rsp->op_ret_code = -ENOMEM;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	kptblarg->ent_tbl = new_ent;
	kptblarg->ent_tbl_size++;
	new_ent = &kptblarg->ent_tbl[kptblarg->ent_tbl_size - 1];
	new_ent->arg = arg->tbl_ent;
	mutex_init(&new_ent->mutex);
	new_ent->node_ref = knodearg;
	kref_get(&knodearg->refcount);
	rev_ref_list->ptr = new_ent;
	list_add(&rev_ref_list->list_node, &knodearg->ptblent_rev_ref_list);
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s ok", __FUNCTION__);

done:
	mutex_unlock(&kparser_config_lock);
	if (rsp->op_ret_code != 0) {
		if (new_ent)
			kfree(new_ent);
		if (rev_ref_list)
			kfree(rev_ref_list);
	}

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_add_node(const struct kparser_arg_node *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	struct kparser_proto *kptblarg = NULL;
	struct kparser_list *ptbllist = NULL;
	struct kparser_list *mdllist = NULL;
	struct kparser_mdl *kpmdlarg = NULL;
	struct kparser_node *karg = NULL;
	struct kparser_cmd_rsp_hdr *rsp;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	if (kparser_hkey_empty(&arg->key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Node Key missing", __FUNCTION__);
		goto done;
	}

	pr_debug("NODE Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("NODE type:%d\n", arg->type);

	rsp->op_ret_code = 0;
	rsp->key = arg->key;
	rsp->err_str_buf[0] = '\0';

	if (kparser_namespace_lookup(KPARSER_NS_INVALID, &arg->key) != NULL) {
		rsp->op_ret_code = -EEXIST;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Duplicate Node entry key!", __FUNCTION__);
		goto done;
	}

	pr_debug("NODE minlen:%u nxtoffset:%u nxtlength:%u\n",
			arg->minlen, arg->nxtoffset, arg->nxtlength);

	if (kparser_hkey_empty(&arg->mdl_key) == false) {
		// it has a valid mdl entry
		pr_debug("NODE MDL Key: {ID:%u Name:%s}\n",
				arg->mdl_key.id,
				arg->mdl_key.name);
		kpmdlarg = kparser_namespace_lookup(KPARSER_NS_INVALID,
				&arg->mdl_key);
		if (kpmdlarg == NULL) {
			rsp->op_ret_code = -ENOENT;
			(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
					"%s: Entry's MDL key not found!", __FUNCTION__);
			goto done;
		}
	}

	if (kparser_hkey_empty(&arg->prot_tbl_key) == false) {
		// it has a valid protocol table entry
		pr_debug("NODE PROTO Key: {ID:%u Name:%s}\n",
				arg->prot_tbl_key.id,
				arg->prot_tbl_key.name);

		kptblarg = kparser_namespace_lookup(KPARSER_NS_INVALID, 
				&arg->prot_tbl_key);
		if (kptblarg == NULL) {
			rsp->op_ret_code = -ENOENT;
			(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
					"%s: Entry's proto key not found!", __FUNCTION__);
			goto done;
		}
	}

	karg = kzalloc(sizeof(*karg), GFP_KERNEL);
	if (!karg) {
		rsp->op_ret_code = -ENOMEM;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	if (kptblarg) {
		ptbllist = kzalloc(sizeof(*ptbllist), GFP_KERNEL);
		if (!ptbllist) {
			rsp->op_ret_code = -ENOMEM;
			(void) snprintf(rsp->err_str_buf,
					sizeof(rsp->err_str_buf),
					"%s: kzalloc() failed", __FUNCTION__);
			goto done;
		}
	}

	if (kpmdlarg) {
		mdllist = kzalloc(sizeof(*mdllist), GFP_KERNEL);
		if (!mdllist) {
			rsp->op_ret_code = -ENOMEM;
			(void) snprintf(rsp->err_str_buf,
					sizeof(rsp->err_str_buf),
					"%s: kzalloc() failed", __FUNCTION__);
			goto done;
		}
	}

	karg->arg = *arg;
	rc = rhashtable_insert_fast(&g_tbl_node.tbl, &karg->ht_node,
			g_tbl_node.tbl_params);
	if (rc) {
		rsp->op_ret_code = rc;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: rhashtable_insert_fast() err",
				__FUNCTION__);
		goto done;
	}

	mutex_init(&karg->mutex);
	kref_init(&karg->refcount);
	INIT_LIST_HEAD(&karg->parser_rev_ref_list);
	INIT_LIST_HEAD(&karg->ptblent_rev_ref_list);

	if (kpmdlarg) {
		karg->mdl_ref = kpmdlarg;
		kref_get(&kpmdlarg->refcount);
		mdllist->ptr = karg;
		list_add(&mdllist->list_node, &kpmdlarg->node_rev_ref_list);
	}

	if (kptblarg) {
		karg->ptbl_ref = kptblarg;
		kref_get(&kptblarg->refcount);
		ptbllist->ptr = karg;
		list_add(&ptbllist->list_node, &kptblarg->node_rev_ref_list);
	}
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s ok", __FUNCTION__);
done:
	mutex_unlock(&kparser_config_lock);

	if (rsp->op_ret_code != 0) {
		if (karg)
			kfree(karg);
		if (mdllist)
			kfree(mdllist);
		if (ptbllist)
			kfree(ptbllist);
	}

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_md(const struct kparser_arg_md *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_mdl(const struct kparser_arg_mdl *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_proto_tbl(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_proto_tbl_ent(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_node(const struct kparser_arg_node *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_all(const void *arg,
		struct kparser_cmd_rsp_hdr **rspp, size_t *rsp_len)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	rhashtable_free_and_destroy(&g_tbl_proto.tbl,
			kparser_free_proto_tbl, NULL);
	rhashtable_free_and_destroy(&g_tbl_node.tbl,
			kparser_free_node_tbl, NULL);
	rhashtable_free_and_destroy(&g_tbl_mdl.tbl,
			kparser_free_mdl, NULL);
	rhashtable_free_and_destroy(&g_tbl_md.tbl,
			kparser_free_md, NULL);
	rhashtable_free_and_destroy(&g_tbl_parser.tbl,
			kparser_free_parser, NULL);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static __u8 pktbuf[] = {0x00,0x30,0x96,0xe6,0xfc,0x39,0x00,
			0x30,0x96,0x05,0x28,0x38,0x88,0x47,
			0x00,0x00,0x70,0xff,0x00,0x01,0x01,
			0xff,0x45,0x00,0x00,0x64,0x00,0x50,
			0x00,0x00,0xff,0x01,0xa7,0x06,0x0a,
			0x1f,0x00,0x01,0x0a,0x22,0x00,0x01,
			0x08,0x00,0xbd,0x11,0x0f,0x65,0x12,
			0xa0,0x00,0x00,0x00,0x00,0x00,0x53,
			0x9e,0xe0,0xab,0xcd,0xab,0xcd,0xab,
			0xcd,0xab,0xcd,0xab,0xcd,0xab,0xcd,
			0xab,0xcd,0xab,0xcd,0xab,0xcd,0xab,
			0xcd,0xab,0xcd,0xab,0xcd,0xab,0xcd,
			0xab,0xcd,0xab,0xcd,0xab,0xcd,0xab,
			0xcd,0xab,0xcd,0xab,0xcd,0xab,0xcd,
			0xab,0xcd,0xab,0xcd,0xab,0xcd,0xab,
			0xcd,0xab,0xcd,0xab,0xcd,0xab,0xcd,
			0xab,0xcd,0xab,0xcd,0xab,0xcd,0xab,
			0xcd,0xab,0xcd};


static void run_dummy_parser(const struct kparser_hkey *arg)
{
	int rc = 0;
	__u8 mdata[64];
	__u16 *frame_eth_proto;
	struct kparser_metadata *mdhdr = (struct kparser_metadata *) mdata;

	memset(mdhdr, 0, sizeof(*mdhdr));
	mdhdr->frame_size = sizeof(frame_eth_proto);
	mdhdr->max_frame_num = 3;

	pr_debug("%s:pktlen:%lu\n", __FUNCTION__, sizeof(pktbuf));
	rc = kparser_do_parse(arg, pktbuf, sizeof(pktbuf), NULL, mdata, sizeof(mdata));
	pr_debug("%s:rc:%d\n", __FUNCTION__, rc);
	if (rc <= KPARSER_OKAY && rc > KPARSER_STOP_FAIL) {
		printk("parser ok: %s\n", kparser_code_to_text(rc));
	}
	frame_eth_proto = (__u16 *) mdhdr->frame_data;
	pr_debug("parsed_mdata:%02x\n", *frame_eth_proto);
}

void kparser_ls_all(const struct kparser_hkey *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_proto_ent *pent = NULL;
	struct kparser_parser *karg = NULL;
	struct kparser_node *knode = NULL;
	struct kparser_node *pnode = NULL;
	struct kparser_proto *ptbl = NULL;
	struct kparser_mdl *mdl = NULL;
	struct kparser_md *md = NULL;
	u16 idx;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	rsp->op_ret_code = 0;

	if (kparser_hkey_empty(arg)) {
		// it has an invalid protocol table entry
		rsp->op_ret_code = -EINVAL;
		pr_debug("Parser Key Missing\n");
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: parser key missing!", __FUNCTION__);
		goto done;
	}

	pr_debug("Arg Parser Key: {ID:%u Name:%s}\n", arg->id, arg->name);

	karg = kparser_namespace_lookup(KPARSER_NS_INVALID, arg);
	if (karg == NULL) {
		rsp->op_ret_code = -ENOENT;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Parser Key not found", __FUNCTION__);
		goto done;
	}

	pr_debug("Parser Key:{%s:%u}\n", karg->arg.key.name, karg->arg.key.id);

	if (karg->rnode_ref == NULL) {
		rsp->op_ret_code = -ENOENT;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: root node missing!", __FUNCTION__);
		goto done;
	}
	knode = karg->rnode_ref;
	pr_debug("Root node Key:{%s:%u}\n", knode->arg.key.name,
			knode->arg.key.id);
	if (0) {
		// TODO:
		knode->arg.plen.src_off = knode->arg.nxtoffset;
		knode->arg.plen.size = knode->arg.nxtlength;
		knode->arg.plen.mask = 0xffffffff;
		knode->arg.plen.multiplier = 0x01;
	}

	ptbl = knode->ptbl_ref;
	if (ptbl) {
		pr_debug("PTBL Key:{%s:%u}, ents:%u\n",
				ptbl->arg.key.name, ptbl->arg.key.id,
				ptbl->ent_tbl_size);
		if (1) {
			ptbl->arg.pkeymap.src_off = knode->arg.nxtoffset;
			ptbl->arg.pkeymap.size = knode->arg.nxtlength;
			ptbl->arg.pkeymap.mask = 0xffff;
		}
		for (idx = 0; idx < ptbl->ent_tbl_size; idx++) {
			pent = &ptbl->ent_tbl[idx];
			pr_debug("pent[%d]: Key:{%s:%u} idx_map: %u\n",
					idx, pent->arg.key.name,
					pent->arg.key.id,
					pent->arg.idx_key_map);
			pnode = pent->node_ref;
			if (pnode == NULL)
				continue;
			pr_debug("pnode Key:{%s:%u}\n",
					pnode->arg.key.name,
					pnode->arg.key.id);
		}
	}
	
	mdl = knode->mdl_ref;
	if (mdl) {
		pr_debug("MDL Key:{%s:%u}\n",
				mdl->arg.key.name,
				mdl->arg.key.id);
		list_for_each_entry(md, &mdl->mdl, mdl_node) {
			pr_debug("MD Key:{%s:%u}:%u:%u:%lu\n",
					md->arg.key.name,
					md->arg.key.id,
					md->arg.soff,
					md->arg.doff,
					md->arg.len);

		}
	}
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	run_dummy_parser(arg);
}


#endif

int kparser_config_handler_add(const void *cmdarg, ssize_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, ssize_t *rsp_len)
{
	enum kparser_global_namespace_ids ns_id;
	const struct kparser_conf_cmd *conf;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	conf = cmdarg;
	if (!conf || cmdarglen < sizeof(*conf) || !rsp || *rsp || !rsp_len ||
			(*rsp_len != 0) ||
			(conf->namespace_id <= KPARSER_NS_INVALID) ||
			(conf->namespace_id >= KPARSER_NS_MAX)) {
		pr_debug("%s:%d:[%p %lu %p %p %p %lu %d]\n",
				__FUNCTION__, __LINE__,
				conf, cmdarglen, rsp, *rsp, rsp_len,
				*rsp_len, conf->namespace_id);
		return KPARSER_ATTR_UNSPEC;
	}

	ns_id = conf->namespace_id;
	
	if (!g_mod_namespaces[ns_id])
		return KPARSER_ATTR_UNSPEC;

	if (!g_mod_namespaces[ns_id]->create_handler)
		return KPARSER_ATTR_UNSPEC;

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	return g_mod_namespaces[ns_id]->create_handler(
			conf, cmdarglen, rsp, rsp_len);
}

int kparser_config_handler_update(const void *cmdarg, ssize_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, ssize_t *rsp_len)
{
	enum kparser_global_namespace_ids ns_id;
	const struct kparser_conf_cmd *conf;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	conf = cmdarg;
	if (!conf || cmdarglen < sizeof(*conf) || !rsp || *rsp || !rsp_len ||
			(*rsp_len != 0) ||
			(conf->namespace_id <= KPARSER_NS_INVALID) ||
			(conf->namespace_id >= KPARSER_NS_MAX)) {
		pr_debug("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	ns_id = conf->namespace_id;
	
	if (!g_mod_namespaces[ns_id])
		return KPARSER_ATTR_UNSPEC;

	if (!g_mod_namespaces[ns_id]->update_handler)
		return KPARSER_ATTR_UNSPEC;

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	return g_mod_namespaces[ns_id]->update_handler(
			conf, cmdarglen, rsp, rsp_len);
}

int kparser_config_handler_read(const void *cmdarg, ssize_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, ssize_t *rsp_len)
{
	enum kparser_global_namespace_ids ns_id;
	const struct kparser_conf_cmd *conf;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	conf = cmdarg;
	if (!conf || cmdarglen < sizeof(*conf) || !rsp || *rsp || !rsp_len ||
			(*rsp_len != 0) ||
			(conf->namespace_id <= KPARSER_NS_INVALID) ||
			(conf->namespace_id >= KPARSER_NS_MAX)) {
		pr_debug("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	ns_id = conf->namespace_id;
	
	if (!g_mod_namespaces[ns_id])
		return KPARSER_ATTR_UNSPEC;

	if (!g_mod_namespaces[ns_id]->read_handler)
		return KPARSER_ATTR_UNSPEC;

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	return g_mod_namespaces[ns_id]->read_handler(
			&conf->obj_key, rsp, rsp_len);
}

int kparser_config_handler_delete(const void *cmdarg, ssize_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, ssize_t *rsp_len)
{
	enum kparser_global_namespace_ids ns_id;
	const struct kparser_conf_cmd *conf;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	conf = cmdarg;
	if (!conf || cmdarglen < sizeof(*conf) || !rsp || *rsp || !rsp_len ||
			(*rsp_len != 0) ||
			(conf->namespace_id <= KPARSER_NS_INVALID) ||
			(conf->namespace_id >= KPARSER_NS_MAX)) {
		pr_debug("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	ns_id = conf->namespace_id;
	
	if (!g_mod_namespaces[ns_id])
		return KPARSER_ATTR_UNSPEC;

	if (!g_mod_namespaces[ns_id]->del_handler)
		return KPARSER_ATTR_UNSPEC;

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	return g_mod_namespaces[ns_id]->del_handler(
			&conf->obj_key, rsp, rsp_len);
}

#if 0
int kparser_create_parser(const struct kparser_conf_cmd *conf,
		ssize_t cmdarglen, struct kparser_cmd_rsp_hdr **rsp,
		ssize_t *rsp_len)
{
	int rc, ret = KPARSER_ATTR_RSP_PARSER;
	const struct kparser_arg_parser *arg;
	struct kparser_parser *parser = NULL;
	struct kparser_list *plist = NULL;
	struct kparser_node *rootnode;
	struct kparser_hkey key = {};

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!conf || cmdarglen < sizeof(*conf) || !rsp || *rsp || !rsp_len ||
			(*rsp_len != 0) ||
			(conf->namespace_id != KPARSER_NS_PARSER)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	mutex_lock(&kparser_config_lock);

	arg = &conf->parser_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = -EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate parser key",
				__FUNCTION__);
		goto done;
	}

	rootnode = kparser_namespace_lookup(conf->namespace_id,
					    &arg->root_node_key);
	if (!rootnode) {
		(*rsp)->op_ret_code = -ENOENT;
		(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
				"%s: Root node key: {%s:%u} not found!",
				__FUNCTION__, arg->root_node_key.name,
				arg->root_node_key.id);
		goto done;
	}

	pr_debug("PARSER Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("PARSER ROOT NODE Key: {ID:%u Name:%s}\n",
			arg->root_node_key.id, arg->root_node_key.name);

	parser = kzalloc(sizeof(*parser), GFP_KERNEL);
	if (!parser) {
		(*rsp)->op_ret_code = -ENOMEM;
		(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	plist = kzalloc(sizeof(*plist), GFP_KERNEL);
	if (!plist) {
		(*rsp)->op_ret_code = -ENOMEM;
		(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	parser->arg = *arg;
	parser->arg.key = key; 
	rc = kparser_namespace_insert(conf->namespace_id,
			&parser->ht_node, &parser->ht_node_id,
			&parser->ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	kref_init(&parser->refcount);
	parser->rnode_node = rcu_assign_pointer(rootnode); // TODO: take care of rcus
	kref_get(&rootnode->refcount);
	plist->ptr = parser;
	list_add(&plist->list_node, &rootnode->parser_rev_ref_list);
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s ok", __FUNCTION__);

	(*rsp)->object = *conf;
	(*rsp)->object.parser_conf = parser->arg;
done:
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (parser)
			kfree(parser);
		if (plist)
			kfree(plist);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return ret;
	return 0;
}

int kparser_read_parser(const struct kparser_hkey *key,
		struct kparser_cmd_rsp_hdr **rsp, ssize_t *rsp_len)
{
	const struct kparser_parser *parser = NULL;
	int ret = KPARSER_ATTR_RSP_PARSER;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!key || !rsp || *rsp || !rsp_len || (*rsp_len != 0)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	mutex_lock(&kparser_config_lock);

	parser = kparser_namespace_lookup(KPARSER_NS_PARSER, key);
	if (!parser) {
		(*rsp)->op_ret_code = -ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Key not found",
				__FUNCTION__);
		goto done;
	}

	(*rsp)->object.namespace_id = KPARSER_NS_PARSER;
	(*rsp)->object.parser_conf = parser->arg;
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"%s ok", __FUNCTION__);
done:
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	return ret;
	return 0;

}
#endif

int kparser_del_parser(const struct kparser_hkey *key,
		struct kparser_cmd_rsp_hdr **rsp, ssize_t *rsp_len)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_UNSPEC;
}

int kparser_create_node(const struct kparser_conf_cmd *conf,
		ssize_t cmdarglen, struct kparser_cmd_rsp_hdr **rsp,
		ssize_t *rsp_len)
{
#if 0
	int rc, ret = KPARSER_ATTR_RSP_PARSER;
	struct kparser_list *plist = NULL;
	struct kparser_arg_node *nodeconf;
	struct kparser_hkey key = {};

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!conf || cmdarglen < sizeof(*conf) || !rsp || *rsp || !rsp_len ||
			(*rsp_len != 0) ||
			(conf->namespace_id != KPARSER_NS_NODE)) {
		printk("%s: invalid args\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp\n", __FUNCTION__);
		return KPARSER_ATTR_UNSPEC;
	}

	mutex_lock(&kparser_config_lock);

	nodeconf = &conf->node_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &nodeconf->key,
				&key, *rsp)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = -EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate node key",
				__FUNCTION__);
		goto done;
	}

	switch (nodeconf->type) {
	case KPARSER_NODE_TYPE_PLAIN:
	case KPARSER_NODE_TYPE_TLVS:
		tlvs_node = kzalloc(sizeof(*tlvs_node),
				GFP_KERNEL);
		if (!flag_fields_node) {
			(*rsp)->op_ret_code = ENOMEM;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: kzalloc() failed", __FUNCTION__);
			goto done;
		}
		rc = create_tlvs_node(nodeconf, tlvs_node);
		break;

	case KPARSER_NODE_TYPE_FLAG_FIELDS:
		flag_fields_node = kzalloc(sizeof(*flag_fields_node),
				GFP_KERNEL);
		if (!flag_fields_node) {
			(*rsp)->op_ret_code = ENOMEM;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: kzalloc() failed", __FUNCTION__);
			goto done;
		}
		rc = create_flag_fields_node(nodeconf, flag_fields_node);
		break;

	case KPARSER_NODE_TYPE_PARSER:
		parse_node = kzalloc(sizeof(*parse_node), GFP_KERNEL);
		if (!parse_node) {
			(*rsp)->op_ret_code = ENOMEM;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: kzalloc() failed", __FUNCTION__);
			goto done;
		}
		rc = create_parse_node(nodeconf, parse_node);
		break;

	case KPARSER_NODE_TYPE_PROTO:
		proto_node = kzalloc(sizeof(*proto_node), GFP_KERNEL);
		if (!proto_node) {
			(*rsp)->op_ret_code = ENOMEM;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: kzalloc() failed", __FUNCTION__);
			goto done;
		}
		rc = create_proto_node(nodeconf, proto_node);
		break;

	default:
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Invalid node type:%d",
				__FUNCTION__, nodeconf->type);
		goto done;
	}

done:
	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);

	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (parser)
			kfree(parser);
		if (plist)
			kfree(plist);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

#endif
	return 0;
}
