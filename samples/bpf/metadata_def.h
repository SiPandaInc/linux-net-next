
#if 0
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
	__u16 ipproto_offset;
} __packed;

struct user_metadata {
	struct user_metametadata metametadata;
	struct user_frame frames[MAX_ENCAP];
} __packed;

static inline void dump_parsed_user_buf(const void *buffer, size_t len)
{
	/* char (*__warn1)[sizeof(struct user_metadata)] = 1; */
	const struct user_metadata *buf = buffer;
	int i, j;

	pr_debug("user_metametadata:%lu user_frame:%lu user_metadata:%lu\n",
			sizeof(struct user_metametadata),
			sizeof(struct user_frame),
			sizeof(struct user_metadata));

	if (!buf || len < sizeof(*buf)) {
		pr_debug("%s: Insufficient buffer\n", __FUNCTION__);
		return;
	}

	pr_debug("metametadata: num_nodes:%u\n", buf->metametadata.num_nodes);
	pr_debug("metametadata: num_encaps:%u\n", buf->metametadata.num_encaps);
	pr_debug("metametadata: ret_code:%d\n", buf->metametadata.ret_code);
	pr_debug("metametadata: cntr:%u\n", buf->metametadata.cntr);

	if (buf->metametadata.cntr >= CNTR_ARRAY_SIZE)
		printk("FATAL error, cntr:%u >= Max:%u\n",
				buf->metametadata.cntr, CNTR_ARRAY_SIZE);
	else
		for (i = 0; i < buf->metametadata.cntr; i++) 
			pr_debug("metametadata: cntrs[%d]:%u\n",
					i, buf->metametadata.cntrs[i]);

	for (i = 0; i <= buf->metametadata.num_encaps; i++) {
		pr_debug("dumping metadata for encap layer:%d\n", i);

		if (buf->frames[i].fragment_bit_offset != 0xffff)
			pr_debug("fragment_bit_offset[%d]:{doff:%lu value:%u}\n",
					i, offsetof(struct user_metadata,
						frames[i].fragment_bit_offset),
					buf->frames[i].fragment_bit_offset);
		if (buf->frames[i].src_ip_offset != 0xffff)
			pr_debug("src_ip_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].src_ip_offset),
					buf->frames[i].src_ip_offset);
		if (buf->frames[i].dst_ip_offset != 0xffff)
			pr_debug("dst_ip_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].dst_ip_offset),
					buf->frames[i].dst_ip_offset);
		if (buf->frames[i].src_port_offset != 0xffff)
			pr_debug("src_port_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].src_port_offset),
					buf->frames[i].src_port_offset);
		if (buf->frames[i].dst_port_offset != 0xffff)
			pr_debug("dst_port_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].dst_port_offset),
					buf->frames[i].dst_port_offset);
		if (buf->frames[i].mss_offset != 0xffff)
			pr_debug("mss_offset[%d]:{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].mss_offset),
					buf->frames[i].mss_offset);
		/* below check to detect if field is set can be a bug */
		if (buf->frames[i].tcp_ts_value != 0xffffffff)
			pr_debug("tcp_ts[%d]:{doff:%lu value:0x%04x}\n", i,
					offsetof(struct user_metadata,
						frames[i].tcp_ts_value),
					buf->frames[i].tcp_ts_value);
		if (buf->frames[i].sack_left_edge_offset != 0xffff)
			pr_debug("sack_left_edge_offset[%d]:"
					"{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].
						sack_left_edge_offset),
					buf->frames[i].sack_left_edge_offset);
		if (buf->frames[i].sack_right_edge_offset != 0xffff)
			pr_debug("sack_right_edge_offset[%d]:"
					"{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].
						sack_right_edge_offset),
					buf->frames[i].sack_right_edge_offset);
		if (buf->frames[i].gre_flags != 0xffff)
			pr_debug("gre_flags[%d]:"
					"{doff:%lu value:0x%02x}\n", i,
					offsetof(struct user_metadata,
						frames[i].gre_flags),
					buf->frames[i].gre_flags);
		if (buf->frames[i].gre_seqno_offset != 0xffff)
			pr_debug("gre_seqno_offset[%d]:"
					"{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].gre_seqno_offset),
					buf->frames[i].gre_seqno_offset);
		if (buf->frames[i].gre_seqno != 0xffffffff)
			pr_debug("gre_seqno[%d]:"
					"{doff:%lu value:%u}\n", i,
					offsetof(struct user_metadata,
						frames[i].gre_seqno),
					buf->frames[i].gre_seqno);

		if (buf->frames[i].ipproto_offset != 0xffff)
			pr_debug("ipproto_offset:%u\n",
					buf->frames[i].ipproto_offset);

		if (buf->frames[i].vlan_cntr == 0xffff)
			continue;

		pr_debug("vlan_cntr[%d]:"
				"{doff:%lu value:%u}\n", i,
				offsetof(struct user_metadata,
					frames[i].vlan_cntr),
				buf->frames[i].vlan_cntr);

		if (buf->frames[i].vlan_cntr > VLAN_COUNT_MAX) {
			printk("FATAL error, cntr:%u >= Max:%u\n",
					buf->frames[i].vlan_cntr,
					VLAN_COUNT_MAX);
			continue;
		}

		for (j = 0; j < buf->frames[i].vlan_cntr; j++)
			if (buf->frames[i].vlantcis[j] != 0xffff)
				pr_debug("vlantcis[%d][%d]:"
					"{doff:%lu value:0x%02x}\n", i, j,
					offsetof(struct user_metadata,
						frames[i].vlantcis[j]),
					buf->frames[i].vlantcis[j]);
	}
}

#endif
#if 0
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

static inline void dump_parsed_user_buf(const void *buffer, size_t len)
{
	/* char (*__warn1)[sizeof(struct user_metadata)] = 1; */
	const struct user_metadata *buf = buffer;

	pr_debug("user_metametadata:%lu user_frame:%lu user_metadata:%lu\n",
			sizeof(struct user_metametadata),
			sizeof(struct user_frame),
			sizeof(struct user_metadata));

	if (!buf || len < sizeof(*buf)) {
		pr_debug("%s: Insufficient buffer\n", __FUNCTION__);
		return;
	}

	pr_debug("metametadata: num_nodes:%u\n", buf->metametadata.num_nodes);
	pr_debug("metametadata: num_encaps:%u\n", buf->metametadata.num_encaps);
	pr_debug("metametadata: ret_code:%d\n", buf->metametadata.ret_code);
	pr_debug("metametadata: cntr:%u\n", buf->metametadata.cntr);


	if (buf->frames[0].ipproto_offset != 0xffff)
		pr_debug("ipproto_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frames[0].ipproto_offset),
				buf->frames[0].ipproto_offset);

	if (buf->frames[0].src_ip_offset != 0xffff)
		pr_debug("src_ip_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frames[0].src_ip_offset),
				buf->frames[0].src_ip_offset);

	if (buf->frames[0].dst_ip_offset != 0xffff)
		pr_debug("dst_ip_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frames[0].dst_ip_offset),
				buf->frames[0].dst_ip_offset);

	if (buf->frames[0].src_port_offset != 0xffff)
		pr_debug("src_port_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frames[0].src_port_offset),
				buf->frames[0].src_port_offset);

	if (buf->frames[0].dst_port_offset != 0xffff)
		pr_debug("dst_port_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frames[0].dst_port_offset),
				buf->frames[0].dst_port_offset);

	if (buf->frames[0].ipv4_ttl != 0xffff)
		pr_debug("ipv4_ttl:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frames[0].ipv4_ttl),
				buf->frames[0].ipv4_ttl);

	if (buf->frames[0].udp_src_port != 0xffff)
		pr_debug("udp_src_port:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frames[0].udp_src_port),
				buf->frames[0].udp_src_port);

	if (buf->frames[0].udp_dst_port != 0xffff)
		pr_debug("udp_dst_port:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frames[0].udp_dst_port),
				buf->frames[0].udp_dst_port);
}

#endif

#if 0

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
	struct user_frame frame;
} __packed;

static inline void dump_parsed_user_buf(const void *buffer, size_t len)
{
	/* char (*__warn1)[sizeof(struct user_metadata)] = 1; */
	const struct user_metadata *buf = buffer;

	pr_debug("MD1 user_metadata:%lu user_frame:%lu\n",
			sizeof(struct user_metadata),
			sizeof(struct user_frame));

	if (!buf || len < sizeof(*buf)) {
		pr_debug("%s: Insufficient buffer\n", __FUNCTION__);
		return;
	}

	if (buf->frame.ipproto_offset != 0xffff)
		pr_debug("ipproto_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frame.ipproto_offset),
				buf->frame.ipproto_offset);

	if (buf->frame.src_ip_offset != 0xffff)
		pr_debug("src_ip_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frame.src_ip_offset),
				buf->frame.src_ip_offset);

	if (buf->frame.dst_ip_offset != 0xffff)
		pr_debug("dst_ip_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frame.dst_ip_offset),
				buf->frame.dst_ip_offset);

	if (buf->frame.src_port_offset != 0xffff)
		pr_debug("src_port_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frame.src_port_offset),
				buf->frame.src_port_offset);

	if (buf->frame.dst_port_offset != 0xffff)
		pr_debug("dst_port_offset:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frame.dst_port_offset),
				buf->frame.dst_port_offset);

	if (buf->frame.ipv4_ttl != 0xffff)
		pr_debug("ipv4_ttl:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frame.ipv4_ttl),
				buf->frame.ipv4_ttl);

	if (buf->frame.udp_src_port != 0xffff)
		pr_debug("udp_src_port:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frame.udp_src_port),
				buf->frame.udp_src_port);

	if (buf->frame.udp_dst_port != 0xffff)
		pr_debug("udp_dst_port:{doff:%lu value:%u}\n",
				offsetof(struct user_metadata,
					frame.udp_dst_port),
				buf->frame.udp_dst_port);
}
#endif


#define MAX_ENCAP 1
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
       //j __u16 ipv4_ttl;
        __u8 ipproto;
        __u32 src_ip;
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
        __u16 udp_src;
        __u16 udp_dst;
} __packed;

struct user_metadata {
//        struct user_metametadata metametadata;
        struct user_frame frames[MAX_ENCAP];
} __packed;



