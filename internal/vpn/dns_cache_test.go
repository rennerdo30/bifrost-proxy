package vpn

import (
	"net/netip"
	"testing"
	"time"
)

func TestDNSCache(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)

	// Test Put and Get
	addr := netip.MustParseAddr("93.184.216.34")
	cache.Put("example.com", []netip.Addr{addr}, time.Minute)

	addrs, ok := cache.Get("example.com")
	if !ok {
		t.Fatal("expected to find example.com in cache")
	}
	if len(addrs) != 1 || addrs[0] != addr {
		t.Errorf("unexpected addresses: %v", addrs)
	}

	// Test miss
	_, ok = cache.Get("notfound.com")
	if ok {
		t.Error("expected miss for notfound.com")
	}

	// Test reverse lookup
	domains := cache.ReverseLookup(addr)
	if len(domains) != 1 || domains[0] != "example.com" {
		t.Errorf("unexpected reverse lookup: %v", domains)
	}
}

func TestDNSCacheExpiry(t *testing.T) {
	cache := NewDNSCache(100 * time.Millisecond)

	addr := netip.MustParseAddr("8.8.8.8")
	cache.Put("google.com", []netip.Addr{addr}, 50*time.Millisecond)

	// Should be found immediately
	_, ok := cache.Get("google.com")
	if !ok {
		t.Fatal("expected to find google.com in cache")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	_, ok = cache.Get("google.com")
	if ok {
		t.Error("expected google.com to be expired")
	}
}

func TestDNSCacheDelete(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)

	addr := netip.MustParseAddr("1.1.1.1")
	cache.Put("cloudflare.com", []netip.Addr{addr}, time.Minute)

	// Verify it's in cache
	_, ok := cache.Get("cloudflare.com")
	if !ok {
		t.Fatal("expected to find cloudflare.com in cache")
	}

	// Delete it
	cache.Delete("cloudflare.com")

	// Should be gone
	_, ok = cache.Get("cloudflare.com")
	if ok {
		t.Error("expected cloudflare.com to be deleted")
	}

	// Reverse lookup should also fail
	domains := cache.ReverseLookup(addr)
	if len(domains) != 0 {
		t.Errorf("expected no domains in reverse lookup, got %v", domains)
	}
}

func TestDNSCacheClear(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)

	addr1 := netip.MustParseAddr("8.8.8.8")
	addr2 := netip.MustParseAddr("1.1.1.1")

	cache.Put("google.com", []netip.Addr{addr1}, time.Minute)
	cache.Put("cloudflare.com", []netip.Addr{addr2}, time.Minute)

	if cache.Size() != 2 {
		t.Errorf("expected size 2, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", cache.Size())
	}
}

func TestDNSCacheStats(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)

	addr := netip.MustParseAddr("93.184.216.34")
	cache.Put("example.com", []netip.Addr{addr}, time.Minute)

	stats := cache.Stats()
	if stats.TotalEntries != 1 {
		t.Errorf("expected 1 total entry, got %d", stats.TotalEntries)
	}
	if stats.ValidEntries != 1 {
		t.Errorf("expected 1 valid entry, got %d", stats.ValidEntries)
	}
	if stats.ReverseEntries != 1 {
		t.Errorf("expected 1 reverse entry, got %d", stats.ReverseEntries)
	}
}

func TestDNSCacheMultipleAddresses(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)

	addrs := []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("93.184.216.35"),
		netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946"),
	}

	cache.Put("example.com", addrs, time.Minute)

	got, ok := cache.Get("example.com")
	if !ok {
		t.Fatal("expected to find example.com in cache")
	}
	if len(got) != 3 {
		t.Errorf("expected 3 addresses, got %d", len(got))
	}

	// All addresses should reverse lookup to example.com
	for _, addr := range addrs {
		domains := cache.ReverseLookup(addr)
		if len(domains) != 1 || domains[0] != "example.com" {
			t.Errorf("unexpected reverse lookup for %v: %v", addr, domains)
		}
	}
}

func TestDNSCacheUpdate(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)

	addr1 := netip.MustParseAddr("1.2.3.4")
	addr2 := netip.MustParseAddr("5.6.7.8")

	// Initial entry
	cache.Put("test.com", []netip.Addr{addr1}, time.Minute)

	// Update with different address
	cache.Put("test.com", []netip.Addr{addr2}, time.Minute)

	// Should return new address
	got, ok := cache.Get("test.com")
	if !ok || len(got) != 1 || got[0] != addr2 {
		t.Errorf("expected [%v], got %v", addr2, got)
	}

	// Old address should not reverse lookup
	domains := cache.ReverseLookup(addr1)
	if len(domains) != 0 {
		t.Errorf("expected no domains for old address, got %v", domains)
	}

	// New address should reverse lookup
	domains = cache.ReverseLookup(addr2)
	if len(domains) != 1 || domains[0] != "test.com" {
		t.Errorf("expected [test.com] for new address, got %v", domains)
	}
}
