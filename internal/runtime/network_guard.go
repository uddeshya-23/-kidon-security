//go:build linux

package runtime

import (
	"fmt"
	"log"
)

// NetworkGuard v0.2.0 - Iron Dome Implementation
// NOTE: Network guard requires additional eBPF compilation (v0.2.1)
// For now, this is a placeholder that logs intent

type NetworkGuard struct {
	cgroupPath string
}

func NewNetworkGuard() *NetworkGuard {
	return &NetworkGuard{}
}

func (ng *NetworkGuard) LoadDefaultPolicy() {
	log.Println("📋 Loading default network policy...")
}

func (ng *NetworkGuard) Start(cgroupPath string) error {
	ng.cgroupPath = cgroupPath
	log.Println("🔥 KIDON NETWORK GUARD v0.2.0 (Iron Dome)")
	log.Printf("⚠️  Network filtering requires v0.2.1 eBPF compilation")
	log.Printf("📍 Cgroup path configured: %s", cgroupPath)
	return nil
}

func (ng *NetworkGuard) MonitorEvents() {
	// Placeholder - actual implementation in v0.2.1
	log.Println("📡 Network monitoring initialized (events will be logged when eBPF is enabled)")
}

func (ng *NetworkGuard) Close() {
	log.Println("Network guard stopped")
}

func (ng *NetworkGuard) AddAllowedIP(ip string) error {
	log.Printf("✅ Allowed IP configured: %s", ip)
	return nil
}

func (ng *NetworkGuard) AddAllowedDomain(domain string) error {
	log.Printf("✅ Allowed domain configured: %s", domain)
	return nil
}

// SetPolicy placeholder
type PolicyConfig struct {
	AllowedDomains []string
	AllowedIPs     []string
	BlockedIPs     []string
}

func (ng *NetworkGuard) SetPolicy(policy PolicyConfig) {
	log.Printf("📋 Policy configured: %d domains, %d IPs", len(policy.AllowedDomains), len(policy.AllowedIPs))
}

func init() {
	fmt.Println() // Placeholder to avoid unused import
}
