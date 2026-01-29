package vpn

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// DNS Cache limits
const (
	// MaxDNSCacheEntries is the maximum number of DNS cache entries
	MaxDNSCacheEntries = 10000
)

// DNSCacheEntry represents a cached DNS response.
type DNSCacheEntry struct {
	Domain    string
	Addresses []netip.Addr
	TTL       time.Duration
	Expires   time.Time
	Created   time.Time
}

// DNSCache caches DNS responses and provides reverse lookup.
type DNSCache struct {
	// Forward cache: domain -> addresses
	forward map[string]*DNSCacheEntry

	// Reverse cache: address -> domains
	reverse map[netip.Addr][]string

	defaultTTL time.Duration
	maxEntries int

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu sync.RWMutex
}

// NewDNSCache creates a new DNS cache.
func NewDNSCache(defaultTTL time.Duration) *DNSCache {
	if defaultTTL == 0 {
		defaultTTL = 5 * time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())

	cache := &DNSCache{
		forward:    make(map[string]*DNSCacheEntry),
		reverse:    make(map[netip.Addr][]string),
		defaultTTL: defaultTTL,
		maxEntries: MaxDNSCacheEntries,
		ctx:        ctx,
		cancel:     cancel,
		done:       make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanupLoop()

	return cache
}

// Put stores a DNS response in the cache.
func (c *DNSCache) Put(domain string, addresses []netip.Addr, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	now := time.Now()
	entry := &DNSCacheEntry{
		Domain:    domain,
		Addresses: addresses,
		TTL:       ttl,
		Expires:   now.Add(ttl),
		Created:   now,
	}

	// Remove old entry if exists (for reverse cache cleanup)
	if old, ok := c.forward[domain]; ok {
		for _, addr := range old.Addresses {
			c.removeReverse(addr, domain)
		}
	}

	// Store in forward cache
	c.forward[domain] = entry

	// Store in reverse cache
	for _, addr := range addresses {
		c.addReverse(addr, domain)
	}

	// Evict if needed
	c.evictIfNeeded()
}

// Get retrieves a DNS response from the cache.
func (c *DNSCache) Get(domain string) ([]netip.Addr, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.forward[domain]
	if !ok {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.Expires) {
		return nil, false
	}

	// Return a copy of addresses
	addrs := make([]netip.Addr, len(entry.Addresses))
	copy(addrs, entry.Addresses)

	return addrs, true
}

// ReverseLookup returns domains associated with an IP address.
func (c *DNSCache) ReverseLookup(addr netip.Addr) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	domains, ok := c.reverse[addr]
	if !ok {
		return nil
	}

	// Return a copy and filter expired entries
	result := make([]string, 0, len(domains))
	now := time.Now()

	for _, domain := range domains {
		if entry, ok := c.forward[domain]; ok {
			if now.Before(entry.Expires) {
				result = append(result, domain)
			}
		}
	}

	return result
}

// Delete removes a domain from the cache.
func (c *DNSCache) Delete(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.forward[domain]; ok {
		for _, addr := range entry.Addresses {
			c.removeReverse(addr, domain)
		}
		delete(c.forward, domain)
	}
}

// Clear removes all entries from the cache.
func (c *DNSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.forward = make(map[string]*DNSCacheEntry)
	c.reverse = make(map[netip.Addr][]string)
}

// Size returns the number of entries in the cache.
func (c *DNSCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.forward)
}

// Stats returns cache statistics.
func (c *DNSCache) Stats() DNSCacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	stats := DNSCacheStats{
		TotalEntries: len(c.forward),
	}

	for _, entry := range c.forward {
		if now.Before(entry.Expires) {
			stats.ValidEntries++
		} else {
			stats.ExpiredEntries++
		}
	}

	stats.ReverseEntries = len(c.reverse)

	return stats
}

// DNSCacheStats contains cache statistics.
type DNSCacheStats struct {
	TotalEntries   int `json:"total_entries"`
	ValidEntries   int `json:"valid_entries"`
	ExpiredEntries int `json:"expired_entries"`
	ReverseEntries int `json:"reverse_entries"`
}

// addReverse adds a domain to the reverse cache for an address.
func (c *DNSCache) addReverse(addr netip.Addr, domain string) {
	domains := c.reverse[addr]

	// Check if already exists
	for _, d := range domains {
		if d == domain {
			return
		}
	}

	c.reverse[addr] = append(domains, domain)
}

// removeReverse removes a domain from the reverse cache for an address.
func (c *DNSCache) removeReverse(addr netip.Addr, domain string) {
	domains := c.reverse[addr]
	if len(domains) == 0 {
		return
	}

	newDomains := make([]string, 0, len(domains))
	for _, d := range domains {
		if d != domain {
			newDomains = append(newDomains, d)
		}
	}

	if len(newDomains) == 0 {
		delete(c.reverse, addr)
	} else {
		c.reverse[addr] = newDomains
	}
}

// evictIfNeeded removes excess entries when cache is full.
func (c *DNSCache) evictIfNeeded() {
	if len(c.forward) <= c.maxEntries {
		return
	}

	// Find and remove expired entries first
	now := time.Now()
	expired := make([]string, 0)

	for domain, entry := range c.forward {
		if now.After(entry.Expires) {
			expired = append(expired, domain)
		}
	}

	for _, domain := range expired {
		if entry, ok := c.forward[domain]; ok {
			for _, addr := range entry.Addresses {
				c.removeReverse(addr, domain)
			}
			delete(c.forward, domain)
		}
	}

	// If still over limit, remove oldest entries
	for len(c.forward) > c.maxEntries {
		var oldestDomain string
		var oldestTime time.Time

		for domain, entry := range c.forward {
			if oldestDomain == "" || entry.Created.Before(oldestTime) {
				oldestDomain = domain
				oldestTime = entry.Created
			}
		}

		if oldestDomain != "" {
			if entry, ok := c.forward[oldestDomain]; ok {
				for _, addr := range entry.Addresses {
					c.removeReverse(addr, oldestDomain)
				}
				delete(c.forward, oldestDomain)
			}
		}
	}
}

// cleanupLoop periodically removes expired entries.
func (c *DNSCache) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	defer close(c.done)

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// Close stops the cleanup goroutine and releases resources.
func (c *DNSCache) Close() {
	if c.cancel != nil {
		c.cancel()
	}
	// Wait for cleanup goroutine to finish
	if c.done != nil {
		<-c.done
	}
}

// cleanup removes expired entries.
func (c *DNSCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expired := make([]string, 0)

	for domain, entry := range c.forward {
		if now.After(entry.Expires) {
			expired = append(expired, domain)
		}
	}

	for _, domain := range expired {
		if entry, ok := c.forward[domain]; ok {
			for _, addr := range entry.Addresses {
				c.removeReverse(addr, domain)
			}
			delete(c.forward, domain)
		}
	}
}

// Entries returns all cache entries (for debugging/display).
func (c *DNSCache) Entries() []DNSCacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entries := make([]DNSCacheEntry, 0, len(c.forward))
	for _, entry := range c.forward {
		entries = append(entries, *entry)
	}
	return entries
}
