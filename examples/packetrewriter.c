#include <linux/if_ether.h>
#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") rewrite = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(packet),
    .value_size = 6, // eth_src
    .max_entries = 256,
};

uint64_t prog(struct packet *pkt)
{
    uint32_t *src;

    // Lookup the input packet src
    bpf_map_lookup_elem(&rewrte, pkt, &src) 

    pkt->eth.h_source = src;
}
char _license[] SEC("license") = "GPL";
