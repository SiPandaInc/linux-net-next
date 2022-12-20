 /* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
// New
#ifndef __METADATA_DEF_H
#define __METADATA_DEF_H
#define STR_STR(x) #x
#define STR(x) STR_STR(x)
#define KPARSER_NAME STR(calc_parser)
#define KPARSER_ID 1
struct user_frame {
        unsigned short calc_dstAddr;
        unsigned short calc_srcAddr;
        unsigned short offset2;
        unsigned short offset3;
        unsigned short offset4;
        unsigned short offset5;
        unsigned short offset6;
        unsigned short offset7;
        unsigned short offset8;
} __packed;
struct user_metadata {
        struct user_frame frames;
} __packed;
#endif
