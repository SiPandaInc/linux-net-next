 /* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
// New
#ifndef __METADATA_DEF_H
#define __METADATA_DEF_H
#define STR_STR(x) #x
#define STR(x) STR_STR(x)
#define KPARSER_NAME STR(five_tuple_sample_parser)
#define KPARSER_ID 1

struct user_frame {
        unsigned short ipv4_ttl_offset;
        unsigned short ipv4_ipproto_offset;
        unsigned short ipv4_src_addr_offset;
        unsigned short ipv4_dst_addr_offset;
        unsigned short tcp_src_port_offset;
        unsigned short tcp_dst_port_offset;
        unsigned short is_tcp_proto_present;
} __packed;

struct user_metadata {
        struct user_frame frames;
} __packed;

#endif
