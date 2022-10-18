// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022-23 Aravind Kumar Buduri <aravind.buduri@gmail.com>
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include "metadata_def.h"
#define IPV6_FLOWINFO_MASK              cpu_to_be32(0x0FFFFFFF)
#define DEBUG 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} counter_map SEC(".maps");

u64 *counter;
u64 pkts;

void count_pkts(void)
{
	u32 key = 0;

	counter = bpf_map_lookup_elem(&counter_map, &key);
	if (counter) {
		*counter += 1;
		pkts = *counter;
	}
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct user_metadata);
} ctx_map SEC(".maps");

static __always_inline void xdp_update_ctx(const void *buffer, size_t len)
{
	const struct user_metadata *buf = buffer;
	__u32 key = 1;

	if (!buf || len < sizeof(*buf)) {
		bpf_printk("Insufficient buffer error\n");
		return;
	}
	bpf_map_update_elem(&ctx_map, &key, buf, BPF_ANY);
}

#define KPARSER_MAX_NAME                128

struct kparser_hkey {
	__u16 id;
	char name[KPARSER_MAX_NAME];
} __packed;

char arr1[512] = {0};

void key_config(char *arr)
{
	struct kparser_hkey key;

	__builtin_memset(&key, 0, sizeof(key));
	key.id = htons(0xFFFF);
	strcpy(key.name, "test_parser");
	memcpy(arr, &key, sizeof(key));
}

SEC("prog")
int xdp_parser_prog(struct xdp_md *ctx)
{
	struct kparser_hkey *keyptr;
	char arr[130] = {0};

	/* code for Kparser */
	key_config(arr);
	keyptr = (struct kparser_hkey *)arr;
#if DEBUG
	bpf_printk("\n keyptr->name = %s\n", keyptr->name);
	bpf_printk("\n keyptr->id = %d\n", keyptr->id);
#endif
	memset(arr1, 0xff, 256);
	bpf_xdp_kparser(ctx, arr, sizeof(arr), arr1, 256);
	xdp_update_ctx(arr1, sizeof(arr1));
	count_pkts();

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
