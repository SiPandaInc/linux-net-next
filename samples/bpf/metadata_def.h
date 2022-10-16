#define STR_STR(x) #x
#define STR(x) STR_STR(x)

#define KPARSER_PREFIX test_parser

#ifndef MDATA
#define MDATA  0
#define KPARSER_NAME STR(KPARSER_PREFIX) STR(MDATA)
struct user_frame {
	__u8 nnodes_u8;
	__u8 nencaps_u8;
	__u8 rcode_u8;
	__u8 hdata_u8;
	__u8 nibb_u8;
	__u8 hdlen_u8;
	__u8 cbyte_u8;
	__u8 hcbyte_u8;
	__u8 boffset_u8;
	__u8 offset_u8;
	__u8 tstamp_u8;
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;
#else 
#if MDATA == 1

#define KPARSER_NAME STR(KPARSER_PREFIX) STR(MDATA)
struct user_frame {
	__u16 nnodes_hw;
	__u16 nencaps_hw;
	__u16 rcode_hw;
	__u16 hdata_hw;
	__u16 nibb_hw;
	__u16 hdlen_hw;
	__u16 cbyte_hw;
	__u16 hcbyte_hw;
	__u16 boffset_hw;
	__u16 offset_hw;
	__u16 tstamp_hw;
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

#elif MDATA == 2

#define KPARSER_NAME STR(KPARSER_PREFIX) STR(MDATA)
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
        __u16 ipv4_ttl;
        __u16 ipproto_offset;
        __u16 src_ip_offset;
        __u16 dst_ip_offset;
        __u16 src_port_offset;
        __u16 dst_port_offset;
        __u16 udp_src_port;
        __u16 udp_dst_port;
} __packed;

struct user_metadata {
        struct user_metametadata metametadata;
        struct user_frame frames[MAX_ENCAP];
} __packed;

#elif MDATA == 3

#define KPARSER_NAME STR(KPARSER_PREFIX) STR(MDATA)
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
        __u16 ipv4_ttl;
        __u16 ipproto;
        __u32 src_ip;
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
        __u16 udp_src;
        __u16 udp_dst;
} __packed;

struct user_metadata {
        struct user_metametadata metametadata;
        struct user_frame frames[MAX_ENCAP];
} __packed;

#elif MDATA == 5

#define KPARSER_NAME STR(KPARSER_PREFIX) STR(MDATA)
#define MAX_ENCAP 1

struct user_frame {
        __u16 ipproto;
        __u32 src_ip;
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
        __u16 udp_src;
        __u16 udp_dst;
} __packed;

struct user_metadata {
        struct user_frame frames[MAX_ENCAP];
} __packed;

#else 
#define KPARSER_NAME STR(KPARSER_PREFIX) STR(' ')
struct user_frame {
	__u8 nnodes_b;
	__u8 nencaps_b;
	__u8 rcode_b;
	__u8 hdata_b;
	__u8 nibb_b;
	__u8 hdlen_b;
	__u8 cbyte_b;
	__u8 hcbyte_b;
	__u8 boffset_b;
	__u8 offset_b;
	__u8 tstamp_b;
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

#endif 
#endif 
