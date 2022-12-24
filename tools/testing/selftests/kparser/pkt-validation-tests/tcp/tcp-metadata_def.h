 /* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
// New
#ifndef __METADATA_DEF_H
#define __METADATA_DEF_H
#define STR_STR(x) #x
#define STR(x) STR_STR(x)
#define KPARSER_NAME STR(ipv4-tcp-opts-parser)
#define KPARSER_ID 1

struct user_metametadata {
	unsigned short okay_numencap;
	unsigned short okay_numnodes;
	unsigned short fail_numencap;
	unsigned short fail_numnodes;
};

struct user_frame {
        unsigned char mac_addrs[12];
        unsigned short ethtype;
        unsigned int src_ip_addr;
        unsigned int dst_ip_addr;
        unsigned char ip_protocol;
        unsigned short src_port;
        unsigned short dst_port;
} __packed;

struct user_metadata {
	struct user_metametadata metametadata;
        struct user_frame frames;
} __packed;

#endif
