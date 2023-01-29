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
        unsigned short calc_etherType;
        unsigned short calc_p;
        unsigned short calc_four;
        unsigned short calc_ver;
        unsigned short calc_op;
        unsigned short calc_op_a;
        unsigned short calc_op_b;
        unsigned short calc_res;
        unsigned short calc_isValid;
} __packed;
struct user_metadata {
        struct user_frame frames;
} __packed;
#endif
