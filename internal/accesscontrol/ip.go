// Package accesscontrol provides IP-based access control for Bifrost.
package accesscontrol

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// IPMatcher matches IP addresses against a list of IPs and CIDR ranges.
type IPMatcher struct {
	ips    map[string]bool
	cidrs  []*net.IPNet
	mu     sync.RWMutex
}

// NewIPMatcher creates a new IP matcher.
func NewIPMatcher() *IPMatcher {
	return &IPMatcher{
		ips: make(map[string]bool),
	}
}

// Add adds an IP or CIDR range to the matcher.
func (m *IPMatcher) Add(entry string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}

	// Check if it's a CIDR
	if strings.Contains(entry, "/") {
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("invalid CIDR: %s", entry)
		}
		m.cidrs = append(m.cidrs, ipNet)
		return nil
	}

	// Parse as IP
	ip := net.ParseIP(entry)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", entry)
	}
	m.ips[ip.String()] = true
	return nil
}

// AddAll adds multiple entries.
func (m *IPMatcher) AddAll(entries []string) error {
	for _, entry := range entries {
		if err := m.Add(entry); err != nil {
			return err
		}
	}
	return nil
}

// Match checks if an IP matches any entry.
func (m *IPMatcher) Match(ipStr string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check exact match
	if m.ips[ip.String()] {
		return true
	}

	// Check CIDR ranges
	for _, cidr := range m.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// Clear removes all entries.
func (m *IPMatcher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ips = make(map[string]bool)
	m.cidrs = nil
}

// Count returns the number of entries.
func (m *IPMatcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ips) + len(m.cidrs)
}
