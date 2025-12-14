//go:build ignore

// +build ignore

// SPDX-License-Identifier: GPL-2.0 OR MIT
// Kidon Process Monitor - eBPF Kernel Module
// Hooks sys_enter_execve to detect and block unauthorized process execution

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Define the data we want to send to Go (User Space)
struct event {
    __u32 pid;
    __u8  comm[16]; // Command name (e.g., "bash")
    __u8  blocked;  // 1 if blocked, 0 if allowed
} __attribute__((packed));

// Force BTF type emission for event struct
struct event *unused_event __attribute__((unused));

// Define the RingBuffer to send alerts
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// The Hook: This runs EVERY time a process starts on the machine
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    
    // 1. Get the command name (what is running?)
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 2. SAFETY CHECK: "Blacklist" Logic (Simplified for MVP)
    // If the process name is "bash" or "sh" -> KILL IT.
    // In a real app, we would check if the PARENT is the Agent first.
    
    // Simple string comparison for "bash" (b-a-s-h)
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h') {
        bpf_printk("KIDON BLOCK: Detected unauthorized bash shell!");
        
        // 3. The "Kill Switch" (Signal 9 = SIGKILL)
        bpf_send_signal(9);

        // 4. Alert User Space
        struct event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = pid;
            // Copy command name to event
            __builtin_memcpy(&e->comm, &comm, sizeof(e->comm));
            e->blocked = 1; // Blocked
            bpf_ringbuf_submit(e, 0);
        }
    }

    return 0;
}
