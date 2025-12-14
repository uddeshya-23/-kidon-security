//go:build linux

package runtime

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf ../../bpf/process_monitor.c -- -I../../bpf/headers
