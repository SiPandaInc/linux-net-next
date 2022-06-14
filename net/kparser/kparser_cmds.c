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
#include "kparser_metaextract.h"
#include <linux/rhashtable.h>
#include <linux/slab.h>

#define DEFINE_GLOBAL_DS(NAME_APPEND)						\
static struct kparser_tbl_##NAME_APPEND g_tbl_##NAME_APPEND =			\
{										\
	.tbl_params = {								\
		.head_offset = offsetof(struct kparser_##NAME_APPEND, ht_node),	\
		.key_offset = offsetof(struct kparser_##NAME_APPEND, arg.key), 	\
		.key_len = sizeof(struct kparser_hkey),				\
		.automatic_shrinking = true,					\
		.hashfn = kparser_gnric_hash_fn,				\
		.obj_hashfn = kparser_gnric_obj_hashfn,				\
		.obj_cmpfn = kparser_cmp_fn,					\
	}									\
};										\

#if 0
e.g.
DEFINE_GLOBAL_DS(parser); // g_tbl_parser
		||
		||
		VV
static struct kparser_tbl_parser_tbl g_tbl_parser =
{
	.tbl_params = {
		.head_offset = offsetof(struct kparser_parser, ht_node),
		.key_offset = offsetof(struct kparser_parser, arg.key),
		.key_len = sizeof_field(struct kparser_parser, arg.key),
		.automatic_shrinking = true,
	}
};
#endif

static DEFINE_MUTEX(kparser_management_lock);

DEFINE_GLOBAL_DS(md); // g_tbl_md
DEFINE_GLOBAL_DS(mdl); // g_tbl_mdl
DEFINE_GLOBAL_DS(node); // g_tbl_node
DEFINE_GLOBAL_DS(proto); // g_tbl_proto
DEFINE_GLOBAL_DS(parser); // g_tbl_parser

void * global_htbl_lookup(u16 htbl_id, const void *key)
{
	switch (htbl_id) {
	case KPARSER_HTBL_PARSER:
		return rhashtable_lookup(&g_tbl_parser.tbl,
			key, g_tbl_parser.tbl_params);
	case KPARSER_HTBL_PTBL:
		return rhashtable_lookup(&g_tbl_proto.tbl,
			key, g_tbl_proto.tbl_params);
	case KPARSER_HTBL_NODE:
		return rhashtable_lookup(&g_tbl_node.tbl,
			key, g_tbl_node.tbl_params);
	case KPARSER_HTBL_MDL:
		return rhashtable_lookup(&g_tbl_mdl.tbl,
			key, g_tbl_mdl.tbl_params);
	case KPARSER_HTBL_MD:
		return rhashtable_lookup(&g_tbl_md.tbl,
			key, g_tbl_md.tbl_params);
	default:
		break;
	}
	return NULL;
}

extern void rhashtable_destroy(struct rhashtable *ht);
extern void rhashtable_free_and_destroy(struct rhashtable *ht,
		void (*free_fn)(void *ptr, void *arg), void *arg);

s32 kparser_init(void)
{
	int err;

	err = rhashtable_init(&g_tbl_md.tbl, &g_tbl_md.tbl_params);
	if (err)
		goto rhashtable_init_err;

	err = rhashtable_init(&g_tbl_mdl.tbl, &g_tbl_mdl.tbl_params);
	if (err)
		goto mdl_init_err;

	// TODO: remove g_ prefix, add more names to mdl and md
	// table_metadata
	err = rhashtable_init(&g_tbl_node.tbl, &g_tbl_node.tbl_params);
	if (err)
		goto node_init_err;

	err = rhashtable_init(&g_tbl_proto.tbl, &g_tbl_proto.tbl_params);
	if (err)
		goto tbl_proto_init_err;

	err = rhashtable_init(&g_tbl_parser.tbl, &g_tbl_parser.tbl_params);
	if (err)
		goto parser_init_err;

	return 0;

parser_init_err:
	rhashtable_destroy(&g_tbl_proto.tbl);
tbl_proto_init_err:
	rhashtable_destroy(&g_tbl_node.tbl);
node_init_err:
	rhashtable_destroy(&g_tbl_mdl.tbl);
mdl_init_err:
	rhashtable_destroy(&g_tbl_md.tbl);

rhashtable_init_err:
	pr_debug("rhashtable_init() failed, err: %d\n", err);
	return err;
}

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
	struct kparser_list *tmp_rev_ref = NULL;
	struct kparser_list *rev_ref = NULL;
	struct kparser_node *knode = NULL;
	struct kparser_proto *karg = ptr;
	u32 refcnt, idx;

	mutex_lock(&kparser_management_lock);

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

	mutex_unlock(&kparser_management_lock);
}

static void kparser_free_node_tbl(void *ptr, void *arg)
{
	struct kparser_proto_ent *karg_ptbl_ent;
	struct kparser_list *tmp_rev_ref = NULL;
	struct kparser_list *rev_ref = NULL;
	struct kparser_parser *karg_parser;
	struct kparser_node *karg = ptr;
	struct kparser_proto *kptblarg;
	struct kparser_mdl *kmdlarg;
	u32 refcnt;

	mutex_lock(&kparser_management_lock);

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

	mutex_unlock(&kparser_management_lock);
}

static void kparser_free_mdl(void *ptr, void *arg)
{
	struct kparser_list *tmp_rev_ref = NULL;
	struct kparser_list *rev_ref = NULL;
	struct kparser_node *knode = NULL;
	struct kparser_mdl *karg = ptr;
	struct kparser_md *tmp_karg_md;
	struct kparser_md *karg_md;
	u32 refcnt;

	mutex_lock(&kparser_management_lock);

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
	mutex_unlock(&kparser_management_lock);
}

static void kparser_free_md(void *ptr, void *arg)
{
	struct kparser_md *karg = ptr;
	u32 refcnt;

	mutex_lock(&kparser_management_lock);

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

	mutex_unlock(&kparser_management_lock);
}

static void kparser_free_parser(void *ptr, void *arg)
{
	struct kparser_list *tmp_rev_ref = NULL;
	struct kparser_list *rev_ref = NULL;
	struct kparser_node *knode = NULL;
	struct kparser_parser *karg = ptr;
	u32 refcnt;

	mutex_lock(&kparser_management_lock);
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
	mutex_unlock(&kparser_management_lock);
}

s32 kparser_deinit(void)
{
#if 0
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
#endif
	return 0;
}

void kparser_add_md(const struct kparser_arg_md *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_md *karg = NULL;
	s32 rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	rsp->op_ret_code = 0;
	rsp->key = arg->key;
	rsp->err_str_buf[0] = '\0';

	mutex_lock(&kparser_management_lock);

	
	pr_debug("MD Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_hkey_empty(&arg->key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: MD Key missing", __FUNCTION__);
		goto done;
	}

	pr_debug("MD Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("MD:soff:%u doff:%u len:%lu \n", arg->soff, arg->doff, arg->len);

	if (global_htbl_lookup(KPARSER_HTBL_MD, &arg->key)) {
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

	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s ok", __FUNCTION__);

done:
	mutex_unlock(&kparser_management_lock);

	if (rsp->op_ret_code != 0)
		if (karg)
			kfree(karg);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_add_mdl(const struct kparser_arg_mdl *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_md *karg_mmd = NULL;
	struct kparser_md *karg_md = NULL;
	struct kparser_mdl *karg = NULL;
	u16 idx;
	s32 rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	rsp->op_ret_code = 0;
	rsp->key = arg->key;
	rsp->err_str_buf[0] = '\0';

	mutex_lock(&kparser_management_lock);

	if (kparser_hkey_empty(&arg->key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: MDL Key missing", __FUNCTION__);
		goto done;
	}

	pr_debug("MDL Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("MDL MMD Key: {ID:%u Name:%s}\n",
			arg->mdkey.id, arg->mdkey.name);

	if (global_htbl_lookup(KPARSER_HTBL_MDL, &arg->key)) {
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

	karg_mmd = global_htbl_lookup(KPARSER_HTBL_MD, &arg->mdkey);
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
		karg_md = global_htbl_lookup(KPARSER_HTBL_MD,
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
		karg_md = global_htbl_lookup(KPARSER_HTBL_MD,&arg->mdkeys[idx]);
		list_add(&karg_md->mdl_node, &karg->mdl);
		kref_get(&karg_md->refcount);
	}

	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s ok", __FUNCTION__);
done:
	mutex_unlock(&kparser_management_lock);

	if (rsp->op_ret_code != 0)
		if (karg)
			kfree(karg);


	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_add_proto_tbl(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_proto *karg = NULL;
	s32 rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	rsp->op_ret_code = 0;
	rsp->key = arg->key;
	rsp->err_str_buf[0] = '\0';

	mutex_lock(&kparser_management_lock);

	if (kparser_hkey_empty(&arg->key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Proto Tbl Key missing", __FUNCTION__);
		goto done;
	}

	pr_debug("PTBL Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("PTBL def_val:%d\n", arg->def_val);

	if (global_htbl_lookup(KPARSER_HTBL_PTBL, &arg->key)) {
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
	mutex_unlock(&kparser_management_lock);

	if (rsp->op_ret_code != 0)
		if (karg)
			kfree(karg);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_add_proto_tbl_ent(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_proto_ent *new_ent = NULL;
	struct kparser_list *rev_ref_list = NULL;
	struct kparser_proto *kptblarg = NULL;
	struct kparser_node *knodearg = NULL;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_management_lock);

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

	kptblarg = global_htbl_lookup(KPARSER_HTBL_PTBL, &arg->key);
	if (kptblarg == NULL) {
		rsp->op_ret_code = -ENOENT;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Proto Table key not found!", __FUNCTION__);
		goto done;
	}

	knodearg = global_htbl_lookup(KPARSER_HTBL_NODE,
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
	mutex_unlock(&kparser_management_lock);
	if (rsp->op_ret_code != 0) {
		if (new_ent)
			kfree(new_ent);
		if (rev_ref_list)
			kfree(rev_ref_list);
	}

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_add_node(const struct kparser_arg_node *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_proto *kptblarg = NULL;
	struct kparser_list *ptbllist = NULL;
	struct kparser_list *mdllist = NULL;
	struct kparser_mdl *kpmdlarg = NULL;
	struct kparser_node *karg = NULL;
	s32 rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_management_lock);

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

	if (global_htbl_lookup(KPARSER_HTBL_NODE, &arg->key) != NULL) {
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
		kpmdlarg = global_htbl_lookup(KPARSER_HTBL_MDL, &arg->mdl_key);
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

		kptblarg = global_htbl_lookup(KPARSER_HTBL_PTBL,
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
	mutex_unlock(&kparser_management_lock);

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

void kparser_add_parser(const struct kparser_arg_parser *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_node *knodearg = NULL;
	struct kparser_parser *karg = NULL; // TODO: rename to parser
	struct kparser_list *plist = NULL;
	s32 rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_management_lock);

	if (kparser_hkey_empty(&arg->key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Parser Key missing", __FUNCTION__);
		goto done;
	}

	if (kparser_hkey_empty(&arg->root_node_key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Root Node Key missing", __FUNCTION__);
		goto done;
	}

	pr_debug("PARSER Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);
	pr_debug("PARSER ROOT NODE Key: {ID:%u Name:%s}\n",
			arg->root_node_key.id, arg->root_node_key.name);

	rsp->op_ret_code = 0;
	rsp->key = arg->key;
	rsp->err_str_buf[0] = '\0';

	if (global_htbl_lookup(KPARSER_HTBL_PARSER, &arg->key)) {
		rsp->op_ret_code = -EEXIST;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Duplicate Key", __FUNCTION__);
		goto done;
	}

	knodearg = global_htbl_lookup(KPARSER_HTBL_NODE, &arg->root_node_key);
	if (knodearg == NULL) {
		rsp->op_ret_code = -ENOENT;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Root node key not found!", __FUNCTION__);
		goto done;
	}

	karg = kzalloc(sizeof(*karg), GFP_KERNEL);
	if (!karg) {
		rsp->op_ret_code = -ENOMEM;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	plist = kzalloc(sizeof(*plist), GFP_KERNEL);
	if (!plist) {
		rsp->op_ret_code = -ENOMEM;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	karg->arg = *arg;
	rc = rhashtable_insert_fast(&g_tbl_parser.tbl, &karg->ht_node,
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
	karg->rnode_ref = knodearg;
	kref_get(&knodearg->refcount);
	rsp->op_ret_code = 0;
	rsp->key = karg->arg.key;
	plist->ptr = karg;
	list_add(&plist->list_node, &knodearg->parser_rev_ref_list);
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s ok", __FUNCTION__);
done:
	mutex_unlock(&kparser_management_lock);

	if (rsp->op_ret_code != 0) {
		if (karg)
			kfree(karg);
		if (plist)
			kfree(plist);
	}

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_all(const void *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	rsp->op_ret_code = 0;
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
	if (rc <= PANDA_OKAY && rc > PANDA_STOP_FAIL) {
		printk("parser ok: %s\n", panda_parser_code_to_text(rc));
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

	mutex_lock(&kparser_management_lock);

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

	karg = global_htbl_lookup(KPARSER_HTBL_PARSER, arg);
	if (karg == NULL) {
		rsp->op_ret_code = -ENOENT;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s: Parser Key not found", __FUNCTION__);
		goto done;
	}

	pr_debug("Parser Key:{%s:%u}\n", karg->arg.key.name, karg->arg.key.id);

	if (1) {
		// TODO:
		karg->arg.config.flags = 0;
		karg->arg.config.max_nodes = 3;
		karg->arg.config.max_encaps = 3;
		karg->arg.config.type = kparser_generic;
	}

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

			if (1) {
				md->arg.config =
					panda_parser_metadata_make_byte_extract(
							md->arg.soff,
							md->arg.doff,
							md->arg.len,
							true);
			}
		}
	}
done:
	mutex_unlock(&kparser_management_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	run_dummy_parser(arg);
}

void kparser_del_md(const struct kparser_arg_md *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	rsp->op_ret_code = 0;
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s not implemented yet!", __FUNCTION__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_mdl(const struct kparser_arg_mdl *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	rsp->op_ret_code = 0;
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s not implemented yet!", __FUNCTION__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_proto_tbl(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	rsp->op_ret_code = 0;
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s not implemented yet!", __FUNCTION__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_proto_tbl_ent(const struct kparser_arg_proto_tbl *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	rsp->op_ret_code = 0;
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s not implemented yet!", __FUNCTION__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_node(const struct kparser_arg_node *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	rsp->op_ret_code = 0;
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s not implemented yet!", __FUNCTION__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

void kparser_del_parser(const struct kparser_arg_parser *arg,
		struct kparser_cmd_rsp_hdr *rsp)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	rsp->op_ret_code = 0;
	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s not implemented yet!", __FUNCTION__);
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}
