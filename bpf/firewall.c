// +build none
#define KBUILD_MODNAME "tsunderefw"
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "bpf.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#ifndef BLACKLIST_MAX_ENTRIES
#define BLACKLIST_MAX_ENTRIES 256
#endif

struct blacklist_key {
    __be32 banned_ip;
};

struct bpf_map_def SEC("maps") blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct blacklist_key),
    .value_size = sizeof(long long),
    .max_entries = BLACKLIST_MAX_ENTRIES,
};

__attribute__((__always_inline__))
static inline int update_drop_count(struct blacklist_key key, long long old_count) {
    long long new_count = old_count + 1;

    int ret = bpf_map_update_elem(&blacklist, &key, &new_count, BPF_ANY);
    if (ret != 0) {
        bpf_printk("failed to update drop count!: update_ret=%d", ret);
        return XDP_ABORTED;
    }

    return XDP_DROP;
}

__attribute__((__always_inline__))
static inline int drop_banned_packets(struct iphdr *ipv4) {
    struct blacklist_key key = {};
    key.banned_ip = bpf_htonl(ipv4->saddr);

    long *found = bpf_map_lookup_elem(&blacklist, &key);
    if (found) {
        bpf_printk("drop [banned]");
        return update_drop_count(key, *found);
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_prog_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    int ipsize = sizeof(*eth);
    struct iphdr *ip = data + ipsize;
    ipsize += sizeof(struct iphdr);
    if (data + ipsize > data_end) {
        bpf_printk("drop [data size check]");
        return XDP_DROP;
    }

    return drop_banned_packets(ip);
}

char _license[] SEC("license") = "GPL";