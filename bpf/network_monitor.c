// SPDX-License-Identifier: GPL-2.0
// Kidon Network Monitor - Titan Firewall
// Blocks connections to non-whitelisted IPs (ASI-02 Tool Misuse / Data Exfil)

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Event types for userspace alerting
#define EVENT_BLOCKED 1
#define EVENT_ALLOWED 2

// Alert event structure sent to userspace
struct net_event {
    __u32 pid;
    __u32 dest_ip;
    __u16 dest_port;
    __u8 action;  // 1=blocked, 2=allowed
    __u8 pad;
};

// Map: Allowed IPs (populated by userspace from kidon_policy.yaml)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // IPv4 address
    __type(value, __u8);   // Just a flag (1 = allowed)
} allowed_ips SEC(".maps");

// Map: Ring buffer for alerts to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

// Cgroup hook for IPv4 connect syscalls
SEC("cgroup/connect4")
int kidon_net_filter(struct bpf_sock_addr *ctx) {
    __u32 dest_ip = ctx->user_ip4;
    __u16 dest_port = bpf_ntohs(ctx->user_port);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Skip loopback (127.0.0.0/8)
    if ((dest_ip & 0xFF) == 127) {
        return 1; // Allow
    }
    
    // Lookup in allowlist
    __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &dest_ip);
    
    struct net_event *evt;
    evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
    if (!evt) {
        // If we can't log, default to block for safety
        return 0;
    }
    
    evt->pid = pid;
    evt->dest_ip = dest_ip;
    evt->dest_port = dest_port;
    
    if (allowed) {
        // IP is whitelisted - allow connection
        evt->action = EVENT_ALLOWED;
        bpf_ringbuf_submit(evt, 0);
        return 1;
    } else {
        // IP not in allowlist - BLOCK
        evt->action = EVENT_BLOCKED;
        bpf_ringbuf_submit(evt, 0);
        
        // Log to trace pipe
        bpf_printk("KIDON BLOCK: PID %d -> IP %pI4:%d", pid, &dest_ip, dest_port);
        
        return 0; // Block connection
    }
}

char LICENSE[] SEC("license") = "GPL";
