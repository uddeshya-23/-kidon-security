//go:build linux

package runtime

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// NetEvent matches the C struct
type NetEvent struct {
	PID      uint32
	DestIP   uint32
	DestPort uint16
	Action   uint8
	Pad      uint8
}

// NetworkGuard manages the network filtering eBPF program
type NetworkGuard struct {
	objs      *netObjects
	link      link.Link
	reader    *ringbuf.Reader
	allowedIPs map[string]bool
}

// NewNetworkGuard creates a new network guard instance
func NewNetworkGuard() *NetworkGuard {
	return &NetworkGuard{
		allowedIPs: make(map[string]bool),
	}
}

// AddAllowedIP adds an IP to the allowlist
func (ng *NetworkGuard) AddAllowedIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	
	// Convert to uint32 for BPF map
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return fmt.Errorf("IPv6 not supported: %s", ip)
	}
	
	key := binary.LittleEndian.Uint32(ipv4)
	value := uint8(1)
	
	if err := ng.objs.AllowedIps.Put(key, value); err != nil {
		return fmt.Errorf("failed to add IP to map: %w", err)
	}
	
	ng.allowedIPs[ip] = true
	log.Printf("✅ Allowed IP: %s", ip)
	return nil
}

// AddAllowedDomain resolves a domain and adds all IPs to allowlist
func (ng *NetworkGuard) AddAllowedDomain(domain string) error {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("DNS lookup failed for %s: %w", domain, err)
	}
	
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			if err := ng.AddAllowedIP(ipv4.String()); err != nil {
				log.Printf("⚠️ Failed to add %s: %v", ipv4, err)
			}
		}
	}
	return nil
}

// LoadDefaultPolicy loads common allowed destinations
func (ng *NetworkGuard) LoadDefaultPolicy() {
	// Always allow essential services
	defaults := []string{
		"127.0.0.1",    // Loopback
		"8.8.8.8",      // Google DNS
		"1.1.1.1",      // Cloudflare DNS
	}
	
	for _, ip := range defaults {
		ng.AddAllowedIP(ip)
	}
	
	// Resolve common AI API endpoints
	domains := []string{
		"api.openai.com",
		"api.anthropic.com",
		"localhost",
	}
	
	for _, domain := range domains {
		if err := ng.AddAllowedDomain(domain); err != nil {
			log.Printf("⚠️ Could not resolve %s: %v", domain, err)
		}
	}
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
	
	// Attach to cgroup
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: ng.objs.KidonNetFilter,
		Attach:  ebpf.AttachCGroupInet4Connect,
	})
	if err != nil {
		return fmt.Errorf("attaching to cgroup: %w", err)
	}
	ng.link = l
	
	// Setup ring buffer reader
	reader, err := ringbuf.NewReader(ng.objs.NetEvents)
	if err != nil {
		return fmt.Errorf("creating ringbuf reader: %w", err)
	}
	ng.reader = reader
	
	// Load default policy
	ng.LoadDefaultPolicy()
	
	log.Println("🔥 KIDON NETWORK GUARD ACTIVE (Titan Firewall)")
	log.Printf("📍 Monitoring cgroup: %s", cgroupPath)
	
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
				log.Printf("Error reading ringbuf: %v", err)
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
			}
			
			ipStr := uint32ToIP(evt.DestIP)
			
			if evt.Action == 1 { // Blocked
				log.Printf("🚨 BLOCKED: PID %d -> %s:%d", evt.PID, ipStr, evt.DestPort)
			} else {
				log.Printf("✅ ALLOWED: PID %d -> %s:%d", evt.PID, ipStr, evt.DestPort)
			}
		}
	}()
	
	<-sig
	log.Println("Shutting down Network Guard...")
}

// Close cleans up resources
func (ng *NetworkGuard) Close() {
	if ng.reader != nil {
		ng.reader.Close()
	}
	if ng.link != nil {
		ng.link.Close()
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
