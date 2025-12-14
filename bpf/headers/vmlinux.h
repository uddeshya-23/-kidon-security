// vmlinux.h - Minimal kernel type definitions for eBPF CO-RE
// This file provides type definitions required for eBPF programs.
// In production, generate this with: bpftool btf dump file /sys/kernel/btf/vmlinux format c

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef _Bool bool;

enum {
	false = 0,
	true = 1,
};

// Tracepoint context for sys_enter events
struct trace_event_raw_sys_enter {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long int id;
	unsigned long args[6];
};

#endif /* __VMLINUX_H__ */
