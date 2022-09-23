// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022-23 Aravind Kumar Buduri <aravind.buduri@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>


struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xdp_tx_ports SEC(".maps");


#define MAX_ENCAP 3
#define CNTR_ARRAY_SIZE 2

struct user_metametadata {
	__u32 num_nodes;
	__u32 num_encaps;
	int ret_code;
	__u16 cntr;
	__u16 cntrs[CNTR_ARRAY_SIZE];
} __packed;

#define VLAN_COUNT_MAX 2

struct user_frame {
	__u16 fragment_bit_offset;
	__u16 src_ip_offset;
	__u16 dst_ip_offset;
	__u16 src_port_offset;
	__u16 dst_port_offset;
	__u16 mss_offset;
	__u32 tcp_ts_value;
	__u16 sack_left_edge_offset;
	__u16 sack_right_edge_offset;
	__u16 gre_flags;
	__u16 gre_seqno_offset;
	__u32 gre_seqno;
	__u16 vlan_cntr;
	__u16 vlantcis[VLAN_COUNT_MAX];
} __packed;

struct user_metadata {
	struct user_metametadata metametadata;
	struct user_frame frames[MAX_ENCAP];
} __packed;

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 2);
        __type(key, __u32 );
        __type(value, struct user_metadata);
} ctx_map SEC(".maps");

static __always_inline void xdp_update_ctx(const void *buffer, size_t len)
{
       
       const struct user_metadata *buf = buffer;
      

        bpf_printk("user_metametadata:%lu user_frame:%lu user_metadata:%lu\n",
                sizeof(struct user_metametadata),
                sizeof(struct user_frame),
                sizeof(struct user_metadata));

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


static inline void dump_parsed_user_buf(const void *buffer, size_t len)
{
	/* char (*__warn1)[sizeof(struct user_metadata)] = 1; */
	const struct user_metadata *buf = buffer;
	int i;

	bpf_printk("user_metametadata:%lu user_frame:%lu user_metadata:%lu\n",
		sizeof(struct user_metametadata),
		sizeof(struct user_frame),
		sizeof(struct user_metadata));

	if (!buf || len < sizeof(*buf)) {
		bpf_printk("%s: Insufficient buffer\n", __FUNCTION__);
		return;
	}

	bpf_printk("metametadata: num_nodes:%u\n", buf->metametadata.num_nodes);
	bpf_printk("metametadata: num_encaps:%u\n", buf->metametadata.num_encaps);
	bpf_printk("metametadata: ret_code:%d\n", buf->metametadata.ret_code);
	bpf_printk("metametadata: cntr:%u, addr: %p\n", buf->metametadata.cntr,
		&buf->metametadata.cntr);
/*	for (i = 0; i < CNTR_ARRAY_SIZE; i++) {
		bpf_printk("metametadata: cntrs[%d]:%u\n",
				i, buf->metametadata.cntrs[i]);
	}
*/
		bpf_printk("metametadata: cntrs[0]:%u\n",
				 buf->metametadata.cntrs[0]);
		i=0;
//	for (i = 0; i <= buf->metametadata.num_encaps; i++) {
		if (buf->frames[i].fragment_bit_offset != 0xffff)
			bpf_printk(
				"fragment_bit_offset[%d]:{doff:%lu value:%u}\n",
				i, offsetof(struct user_metadata,
					frames[i].fragment_bit_offset),
				buf->frames[i].fragment_bit_offset);
		if (buf->frames[i].src_ip_offset != 0xffff)
			bpf_printk("src_ip_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].src_ip_offset),
					buf->frames[i].src_ip_offset);
		if (buf->frames[i].dst_ip_offset != 0xffff)
			bpf_printk("dst_ip_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].dst_ip_offset),
					buf->frames[i].dst_ip_offset);
		if (buf->frames[i].src_port_offset != 0xffff)
			bpf_printk("src_port_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].src_port_offset),
					buf->frames[i].src_port_offset);
		if (buf->frames[i].dst_port_offset != 0xffff)
			bpf_printk("dst_port_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].dst_port_offset),
					buf->frames[i].dst_port_offset);
		if (buf->frames[i].mss_offset != 0xffff)
			bpf_printk("mss_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].mss_offset),
					buf->frames[i].mss_offset);
		/* below check to detect if field is set can be a bug */
		if (buf->frames[i].tcp_ts_value != 0xffffffff)
			bpf_printk("tcp_ts[%d]:{doff:%lu value:0x%04x}\n", i,
					offsetof(struct user_metadata,
						frames[i].tcp_ts_value),
					buf->frames[i].tcp_ts_value);
		if (buf->frames[i].sack_left_edge_offset != 0xffff)
			bpf_printk("sack_left_edge_offset[%d]:"
					"{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].
						sack_left_edge_offset),
					buf->frames[i].sack_left_edge_offset);
		if (buf->frames[i].sack_right_edge_offset != 0xffff)
			bpf_printk("sack_right_edge_offset[%d]:"
					"{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].
						sack_right_edge_offset),
					buf->frames[i].sack_right_edge_offset);
		if (buf->frames[i].gre_flags != 0xffff)
			bpf_printk("gre_flags[%d]:"
					"{doff:%lu value:0x%02x}\n", i,
					offsetof(struct user_metadata,
						frames[i].gre_flags),
					buf->frames[i].gre_flags);
		if (buf->frames[i].gre_seqno_offset != 0xffff)
			bpf_printk("gre_seqno_offset[%d]:"
					"{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].gre_seqno_offset),
					buf->frames[i].gre_seqno_offset);
		if (buf->frames[i].gre_seqno != 0xffffffff)
			bpf_printk("gre_seqno[%d]:"
					"{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].gre_seqno),
					buf->frames[i].gre_seqno);
		if (buf->frames[i].vlan_cntr != 0xffff)
			bpf_printk("vlan_cntr[%d]:"
					"{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].vlan_cntr),
					buf->frames[i].vlan_cntr);
		if (buf->frames[i].vlantcis[0] != 0xffff)
			bpf_printk("vlantcis[%d][0]:"
					"{doff:%lu value:0x%02x}\n", i,
					offsetof(struct user_metadata,
						frames[i].vlantcis[0]),
					buf->frames[i].vlantcis[0]);
		if (buf->frames[i].vlantcis[1] != 0xffff)
			bpf_printk("vlantcis[%d][1]:"
					"{doff:%lu value:0x%02x}\n", i,
					offsetof(struct user_metadata,
						frames[i].vlantcis[1]),
					buf->frames[i].vlantcis[1]);
//	}
}

#define KPARSER_MAX_NAME                128


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
	strcpy(key.name, "test_parser");
#else
	strcpy(key.name, "");
#endif
	memcpy(arr,&key,sizeof(key));

}

SEC("prog")
int xdp_parser_prog(struct xdp_md *ctx)
{
	char arr[130] = {0};
	struct kparser_hkey *keyptr;

 
	key_config(arr);
	keyptr= (struct kparser_hkey *)arr;

	bpf_printk("\n keyptr->name = %s  \n",keyptr->name);
	bpf_printk("\n keyptr->id = %d  \n",keyptr->id);
	//bpf_printk("\n key.name = %s  \n",key.name);
	//bpf_printk("\n key.id = %d  \n", key.id);
	

	
	bpf_xdp_kparser(ctx,arr,sizeof(arr),arr1,256);
	/* To print metadata using bpftool */
        //dump_parsed_user_buf(arr1,sizeof(arr1));A
	/* updating metadata into maps */
        xdp_update_ctx(arr1,sizeof(arr1));	

       // return XDP_DROP;
        return XDP_PASS;

}

char _license[] SEC("license") = "GPL";
