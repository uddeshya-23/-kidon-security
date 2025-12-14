//go:build linux

package runtime

// Generate process monitor eBPF only for now
// Network monitor needs kernel-specific definitions that vary
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf ../../bpf/process_monitor.c -- -I../../bpf/headers
