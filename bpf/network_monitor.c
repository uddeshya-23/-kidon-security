// +build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Map: Allowed IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32);
} allowed_ips SEC(".maps");

// Event struct - MUST be named exactly 'net_event' for bpf2go -type net_event
struct net_event {
    __u32 pid;
    __u32 dst_ip;
    char comm[16];
} __attribute__((packed));

// RingBuffer for blocked connection events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} network_events SEC(".maps");

// Hook: IPv4 Connect
SEC("cgroup/connect4")
int authorize_connect4(struct bpf_sock_addr *ctx) {
    if (ctx->user_family != AF_INET) {
        return 1;
    }

    __u32 dest_ip = ctx->user_ip4;

    __u32 *allowed = bpf_map_lookup_elem(&allowed_ips, &dest_ip);
    if (allowed) {
        return 1; // ALLOW
    }

    // BLOCK - emit event
    struct net_event *e;
    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->dst_ip = dest_ip;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return 0; // BLOCK
}

// Hook: IPv6 Connect (Always Block)
SEC("cgroup/connect6")
int authorize_connect6(struct bpf_sock_addr *ctx) {
    return 0;
}
