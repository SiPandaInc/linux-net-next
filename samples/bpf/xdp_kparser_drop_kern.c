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


#include "../../include/net/flow_dissector.h"

#define DEBUG 1

/*
struct bpf_map_def SEC("maps") counter_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 1,
};
*/

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

char arr1[512] = {0};
SEC("prog")
int xdp_parser_prog(struct xdp_md *ctx)
{

	/* 
	 * code for flow dissector 
	 * 2nd parameter differenciate flow dissector selection 
	 * 0 - basic key flow dissector
	 * 1 - big key flow dissector
	 */


	count_pkts();


	
        return XDP_DROP;
        //return XDP_PASS;

}

char _license[] SEC("license") = "GPL";
