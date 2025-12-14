//go:build linux

package runtime

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event action constants (must match C code)
const (
	EventBlockedIPv4 = 1
	EventAllowedIPv4 = 2
	EventBlockedIPv6 = 3
)

// NetEvent matches the C struct
type NetEvent struct {
	PID      uint32
	DestIP   uint32
	DestPort uint16
	Action   uint8
	Protocol uint8
}

// PolicyConfig holds network policy from kidon_policy.yaml
type PolicyConfig struct {
	AllowedDomains []string
	AllowedIPs     []string
	BlockedIPs     []string
}

// NetworkGuard v0.2.0 - Iron Dome Implementation
type NetworkGuard struct {
	objs          *netObjects
	linkIPv4      link.Link
	linkIPv6      link.Link
	reader        *ringbuf.Reader
	policy        PolicyConfig
	resolvedIPs   map[string][]string // domain -> IPs cache
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	refreshTicker *time.Ticker
}

// NewNetworkGuard creates a new network guard instance
func NewNetworkGuard() *NetworkGuard {
	ctx, cancel := context.WithCancel(context.Background())
	return &NetworkGuard{
		resolvedIPs: make(map[string][]string),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// SetPolicy configures the network policy
func (ng *NetworkGuard) SetPolicy(policy PolicyConfig) {
	ng.mu.Lock()
	defer ng.mu.Unlock()
	ng.policy = policy
}

// LoadDefaultPolicy loads default allowed destinations
func (ng *NetworkGuard) LoadDefaultPolicy() {
	ng.policy = PolicyConfig{
		AllowedDomains: []string{
			"api.openai.com",
			"api.anthropic.com",
			"api.google.com",
			"localhost",
		},
		AllowedIPs: []string{
			"8.8.8.8",   // Google DNS
			"8.8.4.4",   // Google DNS
			"1.1.1.1",   // Cloudflare DNS
			"1.0.0.1",   // Cloudflare DNS
		},
	}
}

// AddAllowedIP adds an IP to the BPF map with error handling
func (ng *NetworkGuard) AddAllowedIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	ipv4 := parsed.To4()
	if ipv4 == nil {
		log.Printf("⚠️  Skipping IPv6 address: %s (blocked by default)", ip)
		return nil // Not an error, just skip
	}

	key := binary.LittleEndian.Uint32(ipv4)
	value := uint8(1)

	// Error handling for map overflow
	if err := ng.objs.AllowedIps.Put(key, value); err != nil {
		if err == ebpf.ErrKeyNotExist {
			log.Printf("⚠️  Map full, cannot add IP: %s", ip)
			return nil // Don't crash, just log
		}
		return fmt.Errorf("failed to add IP to map: %w", err)
	}

	return nil
}

// ResolveDomain resolves a domain to IPv4 addresses and adds to map
func (ng *NetworkGuard) ResolveDomain(domain string) error {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("DNS lookup failed for %s: %w", domain, err)
	}

	var resolved []string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipStr := ipv4.String()
			resolved = append(resolved, ipStr)
			if err := ng.AddAllowedIP(ipStr); err != nil {
				log.Printf("⚠️  Failed to add %s: %v", ipStr, err)
			}
		}
	}

	ng.mu.Lock()
	ng.resolvedIPs[domain] = resolved
	ng.mu.Unlock()

	if len(resolved) > 0 {
		log.Printf("✅ Resolved %s -> %v", domain, resolved)
	}

	return nil
}

// RefreshAllDomains re-resolves all domains (for dynamic cloud IPs)
func (ng *NetworkGuard) RefreshAllDomains() {
	ng.mu.RLock()
	domains := ng.policy.AllowedDomains
	ng.mu.RUnlock()

	for _, domain := range domains {
		if err := ng.ResolveDomain(domain); err != nil {
			log.Printf("⚠️  Refresh failed for %s: %v", domain, err)
		}
	}
}

// StartDNSTicker starts the 30-second DNS refresh loop
func (ng *NetworkGuard) StartDNSTicker() {
	ng.refreshTicker = time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ng.ctx.Done():
				return
			case <-ng.refreshTicker.C:
				log.Println("🔄 Refreshing DNS allowlist...")
				ng.RefreshAllDomains()
			}
		}
	}()
}

// Start loads the eBPF program and begins monitoring
func (ng *NetworkGuard) Start(cgroupPath string) error {
	// Remove memory lock limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load eBPF objects
	ng.objs = &netObjects{}
	if err := loadNetObjects(ng.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Attach IPv4 hook (cgroup/connect4)
	l4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: ng.objs.KidonIpv4Filter,
		Attach:  ebpf.AttachCGroupInet4Connect,
	})
	if err != nil {
		return fmt.Errorf("attaching IPv4 hook to cgroup: %w", err)
	}
	ng.linkIPv4 = l4

	// Attach IPv6 blocker (cgroup/connect6)
	l6, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: ng.objs.KidonIpv6Blocker,
		Attach:  ebpf.AttachCGroupInet6Connect,
	})
	if err != nil {
		log.Printf("⚠️  IPv6 blocker not attached (may not be supported): %v", err)
		// Continue without IPv6 blocking - not fatal
	} else {
		ng.linkIPv6 = l6
		log.Println("🔒 IPv6 BLOCKED (fail-safe mode)")
	}

	// Setup ring buffer reader
	reader, err := ringbuf.NewReader(ng.objs.NetEvents)
	if err != nil {
		return fmt.Errorf("creating ringbuf reader: %w", err)
	}
	ng.reader = reader

	// Load default policy if not set
	if len(ng.policy.AllowedDomains) == 0 && len(ng.policy.AllowedIPs) == 0 {
		ng.LoadDefaultPolicy()
	}

	// Add static IPs
	for _, ip := range ng.policy.AllowedIPs {
		if err := ng.AddAllowedIP(ip); err != nil {
			log.Printf("⚠️  Failed to add IP %s: %v", ip, err)
		}
	}

	// Initial DNS resolution
	ng.RefreshAllDomains()

	// Start DNS refresh ticker (30 seconds)
	ng.StartDNSTicker()

	log.Println("🔥 KIDON NETWORK GUARD v0.2.0 (Iron Dome)")
	log.Printf("📍 Monitoring cgroup: %s", cgroupPath)
	log.Printf("📋 Allowed domains: %d", len(ng.policy.AllowedDomains))
	log.Printf("📋 Static IPs: %d", len(ng.policy.AllowedIPs))

	return nil
}

// MonitorEvents reads and logs network events
func (ng *NetworkGuard) MonitorEvents() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			record, err := ng.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			if len(record.RawSample) < 12 {
				continue
			}

			evt := NetEvent{
				PID:      binary.LittleEndian.Uint32(record.RawSample[0:4]),
				DestIP:   binary.LittleEndian.Uint32(record.RawSample[4:8]),
				DestPort: binary.LittleEndian.Uint16(record.RawSample[8:10]),
				Action:   record.RawSample[10],
				Protocol: record.RawSample[11],
			}

			ipStr := uint32ToIP(evt.DestIP)

			switch evt.Action {
			case EventBlockedIPv4:
				log.Printf("🚨 BLOCKED IPv4: PID %d -> %s:%d", evt.PID, ipStr, evt.DestPort)
			case EventAllowedIPv4:
				// Only log in verbose mode to avoid spam
				// log.Printf("✅ ALLOWED: PID %d -> %s:%d", evt.PID, ipStr, evt.DestPort)
			case EventBlockedIPv6:
				log.Printf("🚨 BLOCKED IPv6: PID %d attempted IPv6 connection (DISABLED)", evt.PID)
			}
		}
	}()

	<-sig
	log.Println("Shutting down Network Guard...")
}

// Close cleans up all resources
func (ng *NetworkGuard) Close() {
	ng.cancel() // Stop the DNS ticker

	if ng.refreshTicker != nil {
		ng.refreshTicker.Stop()
	}
	if ng.reader != nil {
		ng.reader.Close()
	}
	if ng.linkIPv4 != nil {
		ng.linkIPv4.Close()
	}
	if ng.linkIPv6 != nil {
		ng.linkIPv6.Close()
	}
	if ng.objs != nil {
		ng.objs.Close()
	}
}

func uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF,
		(ip>>8)&0xFF,
		(ip>>16)&0xFF,
		(ip>>24)&0xFF)
}
