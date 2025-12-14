// SPDX-License-Identifier: GPL-2.0
// Kidon Network Monitor v0.2.0 - Operation Iron Dome
// Fail-Safe Network Fortress: IPv4 filtering + IPv6 blocking

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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
};

// Map: Allowed IPs (populated by userspace from kidon_policy.yaml)
// Key: IPv4 address as uint32
// Value: 1 = allowed
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);  // Support up to 4K IPs
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips SEC(".maps");

// Map: Ring buffer for alerts to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

// ============================================================================
// Hook 1: IPv4 Connect Filter (cgroup/connect4)
// Logic: Lookup in allowlist, block if not found
// ============================================================================
SEC("cgroup/connect4")
int kidon_ipv4_filter(struct bpf_sock_addr *ctx) {
    __u32 dest_ip = ctx->user_ip4;
    __u16 dest_port = bpf_ntohs(ctx->user_port);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Always allow loopback (127.0.0.0/8)
    __u8 first_octet = dest_ip & 0xFF;
    if (first_octet == 127) {
        return 1; // Allow
    }
    
    // Always allow private networks (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
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
        // If we can't log, default to BLOCK for fail-safe security
        return 0;
    }
    
    evt->pid = pid;
    evt->dest_ip = dest_ip;
    evt->dest_port = dest_port;
    evt->protocol = 4;
    
    if (allowed) {
        // IP is whitelisted - ALLOW connection
        evt->action = EVENT_ALLOWED_IPV4;
        bpf_ringbuf_submit(evt, 0);
        return 1;
    } else {
        // IP not in allowlist - BLOCK
        evt->action = EVENT_BLOCKED_IPV4;
        bpf_ringbuf_submit(evt, 0);
        
        // Debug log
        bpf_printk("KIDON BLOCK IPv4: PID %d -> %pI4:%d", pid, &dest_ip, dest_port);
        
        return 0; // Block connection
    }
}

// ============================================================================
// Hook 2: IPv6 Connect BLOCKER (cgroup/connect6)
// FAIL-SAFE: Block ALL IPv6 to prevent allowlist bypass attacks
// Rationale: v0.2.0 does not implement IPv6 filtering, so we must block entirely
// ============================================================================
SEC("cgroup/connect6")
int kidon_ipv6_blocker(struct bpf_sock_addr *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u16 dest_port = bpf_ntohs(ctx->user_port);
    
    // Always allow loopback (::1)
    // user_ip6 is an array of 4 __u32s
    if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 && 
        ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1)) {
        return 1; // Allow ::1
    }
    
    // Block all other IPv6 traffic
    struct net_event *evt;
    evt = bpf_ringbuf_reserve(&net_events, sizeof(*evt), 0);
    if (evt) {
        evt->pid = pid;
        evt->dest_ip = 0;  // No IPv4 address for IPv6 blocks
        evt->dest_port = dest_port;
        evt->action = EVENT_BLOCKED_IPV6;
        evt->protocol = 6;
        bpf_ringbuf_submit(evt, 0);
    }
    
    bpf_printk("KIDON BLOCK IPv6: PID %d attempted IPv6 connection (DISABLED)", pid);
    
    return 0; // BLOCK all IPv6
}

char LICENSE[] SEC("license") = "GPL";
