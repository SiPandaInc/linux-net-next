 /* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
// New
#ifndef __METADATA_DEF_H
#define __METADATA_DEF_H
#define STR_STR(x) #x
#define STR(x) STR_STR(x)
#define KPARSER_NAME STR(dual-vlan-parser)
#define KPARSER_ID 1
#define MAX_VLAN 2

struct user_frame {
	unsigned short vlan_cnt;
	unsigned short vlan_type_offsets[MAX_VLAN];
} __packed;

struct user_metadata {
        struct user_frame frames;
} __packed;

#endif
