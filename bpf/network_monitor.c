// SPDX-License-Identifier: GPL-2.0
// Kidon Network Monitor v0.2.0 - Operation Iron Dome
// Fail-Safe Network Fortress: IPv4 filtering + IPv6 blocking

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Event types for userspace alerting
#define EVENT_BLOCKED_IPV4 1
#define EVENT_ALLOWED_IPV4 2
#define EVENT_BLOCKED_IPV6 3

// Alert event structure sent to userspace
struct net_event {
    __u32 pid;
    __u32 dest_ip;      // IPv4 address (0 for IPv6 blocks)
    __u16 dest_port;
    __u8 action;        // 1=blocked_ipv4, 2=allowed, 3=blocked_ipv6
    __u8 protocol;      // 4=IPv4, 6=IPv6
} __attribute__((packed));

// Map: Allowed IPs (populated by userspace from kidon_policy.yaml)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips SEC(".maps");

// Map: Ring buffer for alerts to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

// Simplified sock_addr structure
struct kidon_sock_addr {
    __u32 user_ip4;
    __u32 user_ip6[4];
    __u32 user_port;
};

// Helper to convert network byte order
static __always_inline __u16 bpf_ntohs(__u16 val) {
    return (val << 8) | (val >> 8);
}

static __always_inline __u32 bpf_htonl(__u32 val) {
    return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) | 
           ((val & 0xFF0000) >> 8) | ((val & 0xFF000000) >> 24);
}

// ============================================================================
// Hook 1: IPv4 Connect Filter (cgroup/connect4)
// Logic: Lookup in allowlist, block if not found
// ============================================================================
SEC("cgroup/connect4")
int kidon_ipv4_filter(struct bpf_sock_addr *ctx) {
    __u32 dest_ip;
    __u16 dest_port;
    __u32 pid;
    
    // Read context values
    bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &ctx->user_ip4);
    bpf_probe_read_kernel(&dest_port, sizeof(dest_port), &ctx->user_port);
    dest_port = bpf_ntohs(dest_port);
    pid = bpf_get_current_pid_tgid() >> 32;
    
    // Always allow loopback (127.0.0.0/8)
    __u8 first_octet = dest_ip & 0xFF;
    if (first_octet == 127) {
        return 1; // Allow
    }
    
    // Always allow private networks
    if (first_octet == 10) {
        return 1; // Allow 10.0.0.0/8
    }
    if (first_octet == 172) {
        __u8 second_octet = (dest_ip >> 8) & 0xFF;
        if (second_octet >= 16 && second_octet <= 31) {
            return 1; // Allow 172.16.0.0/12
        }
    }
    if (first_octet == 192) {
        __u8 second_octet = (dest_ip >> 8) & 0xFF;
        if (second_octet == 168) {
            return 1; // Allow 192.168.0.0/16
        }
    }
    
    // Lookup in allowlist
    __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &dest_ip);
    
    struct net_event *evt;
    evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
    if (!evt) {
        // Fail-safe: block if can't log
        return 0;
    }
    
    evt->pid = pid;
    evt->dest_ip = dest_ip;
    evt->dest_port = dest_port;
    evt->protocol = 4;
    
    if (allowed) {
        evt->action = EVENT_ALLOWED_IPV4;
        bpf_ringbuf_submit(evt, 0);
        return 1; // Allow
    } else {
        evt->action = EVENT_BLOCKED_IPV4;
        bpf_ringbuf_submit(evt, 0);
        bpf_printk("KIDON BLOCK: PID %d -> IP %x", pid, dest_ip);
        return 0; // Block
    }
}

// ============================================================================
// Hook 2: IPv6 Connect BLOCKER (cgroup/connect6)
// FAIL-SAFE: Block ALL IPv6 to prevent allowlist bypass attacks
// ============================================================================
SEC("cgroup/connect6")
int kidon_ipv6_blocker(struct bpf_sock_addr *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Block all IPv6 traffic
    struct net_event *evt;
    evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
    if (evt) {
        evt->pid = pid;
        evt->dest_ip = 0;
        evt->dest_port = 0;
        evt->action = EVENT_BLOCKED_IPV6;
        evt->protocol = 6;
        bpf_ringbuf_submit(evt, 0);
    }
    
    bpf_printk("KIDON BLOCK IPv6: PID %d", pid);
    return 0; // BLOCK all IPv6
}

char LICENSE[] SEC("license") = "GPL";
