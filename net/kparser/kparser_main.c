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
#include <linux/errno.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/kparser.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <net/act_api.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>

static s32 kparser_cmd_handler(struct sk_buff *skb, struct genl_info *info);

static const struct nla_policy kparser_nl_policy[KPARSER_ATTR_MAX + 1] = {
	[KPARSER_ATTR_CREATE_MD] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_arg_md),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_arg_md)
	},
	[KPARSER_ATTR_CREATE_MD_RSP] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_cmd_rsp_hdr),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_cmd_rsp_hdr)
	},
	[KPARSER_ATTR_CREATE_MDL] = {
		.type = NLA_BINARY,
//		.len = sizeof(struct kparser_arg_mdl),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_arg_mdl)
	},
	[KPARSER_ATTR_CREATE_MDL_RSP] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_cmd_rsp_hdr),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_cmd_rsp_hdr)
	},
	[KPARSER_ATTR_CREATE_NODE] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_arg_node),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_arg_node)
	},
	[KPARSER_ATTR_CREATE_NODE_RSP] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_cmd_rsp_hdr),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_cmd_rsp_hdr)
	},
	[KPARSER_ATTR_CREATE_TBL] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_arg_proto_tbl),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_arg_proto_tbl)
	},
	[KPARSER_ATTR_CREATE_TBL_RSP] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_cmd_rsp_hdr),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_cmd_rsp_hdr)
	},
	[KPARSER_ATTR_CREATE_TBL_ENT] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_arg_proto_tbl),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_arg_proto_tbl)
	},
	[KPARSER_ATTR_CREATE_TBL_ENT_RSP] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_cmd_rsp_hdr),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_cmd_rsp_hdr)
	},
	[KPARSER_ATTR_CREATE_PARSER] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_arg_parser),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_arg_parser)
	},
	[KPARSER_ATTR_CREATE_PARSER_RSP] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_cmd_rsp_hdr),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_cmd_rsp_hdr)
	},
	[KPARSER_ATTR_DELL_ALL] = {
		.type = NLA_BINARY,
		.len = 0,
                .validation_type = NLA_VALIDATE_MIN,
                .min = 0
	},
	[KPARSER_ATTR_DELL_ALL_RSP] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_cmd_rsp_hdr),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_cmd_rsp_hdr)
	},
	[KPARSER_ATTR_LIST_PARSER] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_hkey),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_hkey)
	},
	[KPARSER_ATTR_LIST_PARSER_RSP] = {
		.type = NLA_BINARY,
		.len = sizeof(struct kparser_cmd_rsp_hdr),
                .validation_type = NLA_VALIDATE_MIN,
                .min = sizeof(struct kparser_cmd_rsp_hdr)
	},
};

static const struct genl_ops kparser_nl_ops[] = {
	{
		.cmd = KPARSER_CMD_ADD,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = kparser_cmd_handler,
		.flags = GENL_ADMIN_PERM,
	},
};

struct genl_family kparser_nl_family __ro_after_init = {
	.hdrsize	= 0,
	.name		= KPARSER_GENL_NAME,
	.version	= KPARSER_GENL_VERSION,
	.maxattr	= KPARSER_ATTR_MAX,
	.policy		= kparser_nl_policy,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.ops		= kparser_nl_ops,
	.n_ops		= ARRAY_SIZE(kparser_nl_ops),
};

static s32 kparser_send_cmd_rsp(s32 cmd, s32 attrtype,
		const struct kparser_cmd_rsp_hdr *rsp, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	s32 ret;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq, &kparser_nl_family,
			0, cmd);
	if (!hdr) {
		nlmsg_free(msg);
		return -ENOBUFS;
	}

	if (nla_put(msg, attrtype, sizeof(*rsp), rsp)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);
	ret = genlmsg_reply(msg, info);

	// pr_debug("genlmsg_reply() ret:%d\n", ret);

	return ret;
}

typedef s32 kparser_ops(const struct nlattr *, struct kparser_cmd_rsp_hdr *);

#define DEFINE_FUNCTION(suffix, arg_suffix, attr)			\
static s32 kparser_create_##suffix(const struct nlattr *nl_curr_attr,	\
		struct kparser_cmd_rsp_hdr *rsp)			\
{									\
	struct kparser_arg_##arg_suffix *cmd_arg = nla_data(nl_curr_attr);\
									\
	rsp->op_ret_code = 0;						\
	rsp->err_str_buf[0] = '\0';					\
	if (nla_len(nl_curr_attr) < sizeof(*cmd_arg) ) {		\
		(void) snprintf(rsp->err_str_buf,			\
				sizeof(rsp->err_str_buf),		\
				"%s: attr size %d is less than min cmd "\
				"arg size %lu", __FUNCTION__, 		\
				nla_len(nl_curr_attr),			\
				sizeof(*cmd_arg));			\
		rsp->op_ret_code = -EINVAL;				\
	} else {							\
		kparser_add_##suffix(cmd_arg, rsp);			\
	}								\
	return attr;							\
}									\

DEFINE_FUNCTION(md, md, KPARSER_ATTR_CREATE_MD_RSP);
DEFINE_FUNCTION(mdl, mdl, KPARSER_ATTR_CREATE_MDL_RSP);
DEFINE_FUNCTION(node, node, KPARSER_ATTR_CREATE_NODE_RSP);
DEFINE_FUNCTION(proto_tbl, proto_tbl, KPARSER_ATTR_CREATE_TBL_RSP);
DEFINE_FUNCTION(proto_tbl_ent, proto_tbl, KPARSER_ATTR_CREATE_TBL_ENT_RSP);
DEFINE_FUNCTION(parser, parser, KPARSER_ATTR_CREATE_PARSER_RSP);

static s32 kparser_dell_all(const struct nlattr *nl_curr_attr,
		struct kparser_cmd_rsp_hdr *rsp)
{
	rsp->op_ret_code = 0;
	rsp->err_str_buf[0] = '\0';

	kparser_del_all(NULL, rsp);

	return KPARSER_ATTR_DELL_ALL_RSP;
}

static s32 kparser_list_all(const struct nlattr *nl_curr_attr,
		struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_hkey *cmd_arg = nla_data(nl_curr_attr);

	rsp->op_ret_code = 0;
	rsp->err_str_buf[0] = '\0';

	if (nla_len(nl_curr_attr) < sizeof(*cmd_arg) ) {
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: attr size %d is less than min cmd "
				"arg size %lu", __FUNCTION__, 
				nla_len(nl_curr_attr),
				sizeof(*cmd_arg));
		rsp->op_ret_code = -EINVAL;
	} else {
		kparser_ls_all(cmd_arg, rsp);
	}

	return KPARSER_ATTR_LIST_PARSER_RSP;
}

static kparser_ops *kparser_op_handler[KPARSER_ATTR_MAX+1] = {
	NULL,
	kparser_create_md,
	NULL,
	kparser_create_mdl,
	NULL,
	kparser_create_node,
	NULL,
	kparser_create_proto_tbl,
	NULL,
	kparser_create_proto_tbl_ent,
	NULL,
	kparser_create_parser,
	NULL,
	kparser_dell_all,
	NULL,
	kparser_list_all,
	NULL,
};

static s32 kparser_cmd_handler(struct sk_buff *skb, struct genl_info *info)
{
	struct kparser_cmd_rsp_hdr rsp_buf;
	s32 ret_attr_id;
	s32 attr_idx;
	s32 rc;

	for (attr_idx = KPARSER_ATTR_UNSPEC+1; attr_idx < KPARSER_ATTR_MAX;
			attr_idx++) {
		if (info->attrs[attr_idx] && kparser_op_handler[attr_idx]) {
			ret_attr_id = kparser_op_handler[attr_idx](
					info->attrs[attr_idx], &rsp_buf);
			rc = kparser_send_cmd_rsp(KPARSER_CMD_ADD, ret_attr_id,
					&rsp_buf, info);
			if (rc) {
				printk("kparser_send_cmd_rsp() failed,"
						"attr:%d, rc:%d\n",
						attr_idx, rc);
			}
		}
	}

	return rc;
}

static int __init init_kparser(void)
{
	int ret;
	pr_debug("kparser init is started.\n");
	ret = genl_register_family(&kparser_nl_family);
	if (ret) {
		printk("genl_register_family failed\n");
		genl_unregister_family(&kparser_nl_family);
	}
	ret = kparser_init();
	if (ret != 0)
		printk("kparser_init() err:%d\n", ret);
	pr_debug("kparser init is done.\n");
	return 0;
}

static void __exit exit_kparser(void)
{
	s32 rc;
	pr_debug("kparser exit is started.\n");
	genl_unregister_family(&kparser_nl_family);
	rc = kparser_deinit();
	if (rc != 0)
		printk("kparser_deinit() err:%d\n", rc);
	pr_debug("kparser exit is done.\n");
}

module_init(init_kparser);
module_exit(exit_kparser);
MODULE_AUTHOR("Pratyush Khan <pratyush@sipanda.io>");
MODULE_AUTHOR("SiPanda Inc");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Configurable PANDA Parser in Kernel (KPARSER)");
