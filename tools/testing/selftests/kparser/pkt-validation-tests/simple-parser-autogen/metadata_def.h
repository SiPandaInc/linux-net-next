 /* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
// New
#ifndef __METADATA_DEF_H
#define __METADATA_DEF_H
#define STR_STR(x) #x
#define STR(x) STR_STR(x)
#define KPARSER_NAME STR(sdpu_parser)
#define KPARSER_ID 0xffff

struct ipv4_node_metadata {
	unsigned char addr_type;
        unsigned char ip_protocol;
	unsigned char pad1;
	unsigned char pad2;
	unsigned int ports;
        unsigned long long addrs;
} __packed;

struct ipv6_node_metadata {
	unsigned char addr_type;
        unsigned char ip_protocol;
	unsigned char pad1;
	unsigned char pad2;
	unsigned int ports;
        unsigned long long addrs;
} __packed;

struct user_metametadata {
	union {
		struct ipv4_node_metadata ipv4_metadata;
		struct ipv6_node_metadata ipv6_metadata;
	} ipmetadata;
};

struct user_frame {
} __packed;

struct user_metadata {
	struct user_metametadata metametadata;
        struct user_frame frames;
} __packed;

#endif
