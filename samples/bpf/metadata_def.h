struct user_frame {
	__u8 ip_proto;
	__u16 src_ip_offset;
	__u16 dst_ip_offset;
	__u32 src_ip_addr;
	__u32 dst_ip_addr;
	__u16 src_tcp_port;
	__u16 dst_tcp_port;
	__u16 src_udp_port;
	__u16 dst_udp_port;
	__u16 mss;
	__u32 tcp_ts;
	__u16 sack_left_edge;
	__u16 sack_right_edge;
	__u16 gre_flags;
	__u32 gre_seqno;
	__u16 vlan_cntr;
	__u16 vlantcis[2];
} __packed;

struct user_metadata {
	struct user_frame frame;
} __packed;

