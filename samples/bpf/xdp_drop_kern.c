#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, __u64);
        __uint(max_entries, 1);
} counter_map SEC(".maps");


u64 *counter;
u64 pkts;
void count_pkts(void)
{
        u32 key = 0;
        counter = bpf_map_lookup_elem(&counter_map, &key);
        if (counter) {
                *counter += 1;
                pkts = *counter;
        }
}

int main()
{
		count_pkts();
	    return XDP_DROP;
}
