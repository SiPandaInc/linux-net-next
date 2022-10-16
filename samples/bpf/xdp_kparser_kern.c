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

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xdp_tx_ports SEC(".maps");

struct k_struct {

	 	unsigned int src_ip;
		unsigned int dest_ip;
		unsigned short proto_id;
};
#if 1



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


#endif


struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 2);
        __type(key, __u32 );
        __type(value, struct user_metadata);
} ctx_map SEC(".maps");

static __always_inline void xdp_update_ctx(const void *buffer, size_t len)
{
       
       const struct user_metadata *buf = buffer;
      

        if (!buf || len < sizeof(*buf)) {
                bpf_printk("%s: Insufficient buffer\n", __FUNCTION__);
                return;
        }

        /* clang-10 has a bug if key == 0,
         * it generates bogus bytecodes.
         */
        __u32 key = 1;
	
	
	bpf_map_update_elem(&ctx_map, &key, buf, BPF_ANY);	
	       
}



#define KPARSER_MAX_NAME                128
//#define KPARSER_MAX_NAME                20


struct kparser_hkey {
        __u16 id;
        char name[KPARSER_MAX_NAME];
}__packed;


char arr1[512] = {0};
void key_config(char *arr)
{
	struct kparser_hkey key;

	__builtin_memset(&key, 0, sizeof(key));

	key.id = htons(0xFFFF);
#if 1
	strcpy(key.name, KPARSER_NAME);
#else
	strcpy(key.name, "");
#endif
	memcpy(arr,&key,sizeof(key));

}

//SEC("xdp_fwd")
SEC("prog")
int xdp_parser_prog(struct xdp_md *ctx)
{
	char arr[130] = {0};
	struct kparser_hkey *keyptr;

	/* code for Kparser */
#if 1 
	key_config(arr);
	keyptr= (struct kparser_hkey *)arr;

	//bpf_printk("\n keyptr->name = %s  \n",keyptr->name);
	//bpf_printk("\n keyptr->id = %d  \n",keyptr->id);
	//bpf_printk("\n key.name = %s  \n",key.name);
	//bpf_printk("\n key.id = %d  \n", key.id);
	

	memset(arr1, 0xff, 256);
	
	bpf_xdp_kparser(ctx,arr,sizeof(arr),arr1,256);
        //dump_parsed_user_buf(arr1,sizeof(arr1));	
        xdp_update_ctx(arr1,sizeof(arr1));	
#endif


	count_pkts();
	
       // return XDP_DROP;
        return XDP_PASS;

}

char _license[] SEC("license") = "GPL";
