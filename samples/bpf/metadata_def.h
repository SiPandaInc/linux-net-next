#define STR_STR(x) #x
#define STR(x) STR_STR(x)

#define MAX_ENCAP 3
#define CNTR_ARRAY_SIZE 2
#define KPARSER_PREFIX test_parser

#ifndef MDATA
#define MDATA  0
#define KPARSER_NAME STR(tuple_parser)
#define KPARSER_ID 0
struct user_frame {
	unsigned short ip_offset;
	unsigned short l4_offset;
	unsigned int ipv4_addrs[2];
	unsigned short ports[2];
	unsigned short counter_value;
	unsigned short
		vlantcis[2];
} __packed;

struct user_metadata {
	struct user_frame frames;
} __packed;

#else 

#if MDATA > 100 && MDATA < 117 

#define KPARSER_NAME STR(KPARSER_PREFIX) STR(100)

#define MSIZE MDATA - 100 

#define KPARSER_ID MSIZE

struct user_frame {
	__u8 data[MSIZE];
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

#elif  MDATA  > 116  &&  MDATA < 133
#define MSIZE MDATA - 116 
#define KPARSER_ID MSIZE

struct user_frame {
	_u16 data[MSIZE];
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

#elif ( MDATA  > 132 ) && ( MDATA < 165) 
#define MSIZE MDATA - 132 
#define KPARSER_ID MSIZE

struct user_frame {
	_u16 data[MSIZE];
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

#elif MDATA == 208

#define KPARSER_NAME STR(KPARSER_PREFIX) STR(MDATA)
struct user_frame {
	__u8 nnodes_u208;
	__u8 nencaps_u208;
	__u8 rcode_u208;
	__u8 hdata_u208;
	__u8 nibb_u208;
	__u8 hdlen_u208;
	__u8 cbyte_u208;
	__u8
		hcbyte_u208;
	__u8
		boffset_u208;
	__u8
		offset_u208;
	__u8
		tstamp_u208;
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

#elif MDATA == 216

#define KPARSER_NAME STR(KPARSER_PREFIX) STR(MDATA)
struct user_frame {
	__u16 nnodes_u16;
	__u16 nencaps_u16;
	__u16 rcode_u16;
	__u16 hdata_u16;
	__u16 nibb_u16;
	__u16 hdlen_u16;
	__u16 cbyte_u16;
	__u16
		hcbyte_u16;
	__u16
		boffset_u16;
	__u16
		offset_u16;
	__u16
		tstamp_u16;
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

#elif MDATA == 132

#define KPARSER_NAME STR(KPARSER_PREFIX) STR(MDATA)
struct user_frame {
	__u32 nnodes_u32;
	__u32 nencaps_u32;
	__u32 rcode_u32;
	__u32 hdata_u32;
	__u32 nibb_u32;
	__u32 hdlen_u32;
	__u32 cbyte_u32;
	__u32
		hcbyte_u32;
	__u32
		boffset_u32;
	__u32
		offset_u32;
	__u32
		tstamp_u32;
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

#elif MDATA == 111

#define KPARSER_NAME STR(KPARSER_PREFIX) STR(MDATA)
struct user_frame {
	__u32 nnodes_u8_111;
	__u32 nencaps_u8_111;
	__u32 rcode_u8_111;
	__u8 hdata_u8[6]_111;
	__u8 nibb_u8_111;
	__u16 hdlen_u16_111;
	__u32
		cbyte_u32_111;
	__u32
		hcbyte_u32_111;
	__u16
		boffset_u16_111;
	__u32
		offset_u32_111;
	__u32
		tstamp_u32_111;
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
	__u16
		udp_src_port;
	__u16
		udp_dst_port;
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
	__u16
		udp_dst;
} __packed;

struct user_metadata {
	struct user_metametadata metametadata;
	struct user_frame frames[MAX_ENCAP];
} __packed;

#elif MDATA == 512
#define MAX_ENCAP 8
#define VLAN_COUNT_MAX 2
#define CNTR_ARRAY_SIZE 8

#define KPARSER_ID MDATA

struct user_metametadata {
	__u16 num_nodes;
	__u16 num_encaps;
	int ret_code;
	__u16 cntr;
	__u16 cntrs[CNTR_ARRAY_SIZE];
} __packed;

struct user_frame {
	__u16 fragment_bit;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u16 mss;
	__u32
		tcp_ts_value;
	__u16
		sack_left_edge;
	__u16
		sack_right_edge;
	__u16
		gre_flags;
	__u16
		gre_seqno0;
	__u32
		gre_seqno;
	__u16
		vlan_cntr;
	__u16
		vlantcis[VLAN_COUNT_MAX];
	__u16
		ipproto;
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
	__u8
		hcbyte_b;
	__u8
		boffset_b;
	__u8
		offset_b;
	__u8
		tstamp_b;
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

#endif 
#endif 
