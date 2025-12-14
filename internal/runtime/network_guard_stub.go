//go:build !linux

package runtime

import "fmt"

// NetworkGuard stub for non-Linux platforms
type NetworkGuard struct{}

func NewNetworkGuard() *NetworkGuard {
	return &NetworkGuard{}
}

func (ng *NetworkGuard) AddAllowedIP(ip string) error {
	return fmt.Errorf("network guard requires Linux")
}

func (ng *NetworkGuard) AddAllowedDomain(domain string) error {
	return fmt.Errorf("network guard requires Linux")
}

func (ng *NetworkGuard) LoadDefaultPolicy() {}

func (ng *NetworkGuard) Start(cgroupPath string) error {
	fmt.Println("⚠️  ERROR: Network Guard requires Linux kernel with eBPF support.")
	fmt.Println("Run inside the Docker container:")
	fmt.Println("  docker build -f deploy/Dockerfile.kidon -t kidon-security .")
	fmt.Println("  docker run --privileged --pid=host kidon-security guard --network")
	return fmt.Errorf("not supported on this platform")
}

func (ng *NetworkGuard) MonitorEvents() {}

func (ng *NetworkGuard) Close() {}
