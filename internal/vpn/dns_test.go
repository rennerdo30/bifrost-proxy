package vpn

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDNSServer tests creating a new DNS server
func TestNewDNSServer(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15353",
		Upstream: []string{"8.8.8.8", "1.1.1.1"},
		CacheTTL: 5 * time.Minute,
	}

	cache := NewDNSCache(5 * time.Minute)
	engine, _ := NewSplitTunnelEngine(SplitTunnelConfig{Mode: "exclude"}, cache)

	server := NewDNSServer(config, cache, engine)
	require.NotNil(t, server)
	assert.Equal(t, config.Listen, server.config.Listen)
	assert.Equal(t, config.Upstream, server.config.Upstream)
}

// TestDNSServerStats tests stats collection
func TestDNSServerStats(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15354",
		Upstream: []string{"8.8.8.8"},
		CacheTTL: 5 * time.Minute,
	}

	cache := NewDNSCache(5 * time.Minute)
	server := NewDNSServer(config, cache, nil)

	stats := server.Stats()
	assert.Equal(t, int64(0), stats.TotalQueries)
	assert.Equal(t, int64(0), stats.CacheHits)
	assert.Equal(t, int64(0), stats.CacheMisses)
	assert.Equal(t, int64(0), stats.UpstreamErrors)

	// Increment stats manually for testing
	server.totalQueries.Add(10)
	server.cacheHits.Add(5)
	server.cacheMisses.Add(3)
	server.upstreamErrors.Add(2)

	stats = server.Stats()
	assert.Equal(t, int64(10), stats.TotalQueries)
	assert.Equal(t, int64(5), stats.CacheHits)
	assert.Equal(t, int64(3), stats.CacheMisses)
	assert.Equal(t, int64(2), stats.UpstreamErrors)
}

// TestDNSServerCacheEntries tests cache entries retrieval
func TestDNSServerCacheEntries(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15355",
		Upstream: []string{"8.8.8.8"},
		CacheTTL: 5 * time.Minute,
	}

	cache := NewDNSCache(5 * time.Minute)
	server := NewDNSServer(config, cache, nil)

	// No entries initially
	entries := server.CacheEntries()
	assert.Len(t, entries, 0)

	// Add entry to cache
	cache.Put("example.com", []netip.Addr{netip.MustParseAddr("93.184.216.34")}, time.Minute)

	entries = server.CacheEntries()
	assert.Len(t, entries, 1)
	assert.Equal(t, "example.com", entries[0].Domain)
}

// TestDNSServerCacheEntriesNil tests cache entries with nil cache
func TestDNSServerCacheEntriesNil(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15356",
		Upstream: []string{"8.8.8.8"},
		CacheTTL: 5 * time.Minute,
	}

	server := NewDNSServer(config, nil, nil)
	entries := server.CacheEntries()
	assert.Nil(t, entries)
}

// TestDNSServerClearCache tests clearing cache
func TestDNSServerClearCache(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15357",
		Upstream: []string{"8.8.8.8"},
		CacheTTL: 5 * time.Minute,
	}

	cache := NewDNSCache(5 * time.Minute)
	server := NewDNSServer(config, cache, nil)

	// Add entry
	cache.Put("example.com", []netip.Addr{netip.MustParseAddr("93.184.216.34")}, time.Minute)
	assert.Equal(t, 1, cache.Size())

	server.ClearCache()
	assert.Equal(t, 0, cache.Size())
}

// TestDNSServerClearCacheNil tests clearing nil cache
func TestDNSServerClearCacheNil(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15358",
		Upstream: []string{"8.8.8.8"},
		CacheTTL: 5 * time.Minute,
	}

	server := NewDNSServer(config, nil, nil)
	// Should not panic
	server.ClearCache()
}

// TestDNSServerStartStop tests starting and stopping the server
func TestDNSServerStartStop(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15359",
		Upstream: []string{"8.8.8.8"},
		CacheTTL: 5 * time.Minute,
	}

	cache := NewDNSCache(5 * time.Minute)
	server := NewDNSServer(config, cache, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.Start(ctx)
	require.NoError(t, err)

	// Allow server to start
	time.Sleep(50 * time.Millisecond)

	err = server.Stop()
	assert.NoError(t, err)
}

// TestDNSServerStartInvalidAddress tests starting with invalid address
func TestDNSServerStartInvalidAddress(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "invalid:address:port",
		Upstream: []string{"8.8.8.8"},
		CacheTTL: 5 * time.Minute,
	}

	cache := NewDNSCache(5 * time.Minute)
	server := NewDNSServer(config, cache, nil)

	ctx := context.Background()
	err := server.Start(ctx)
	assert.Error(t, err)
}

// TestDNSServerStopWithoutStart tests stopping without starting
func TestDNSServerStopWithoutStart(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15360",
		Upstream: []string{"8.8.8.8"},
		CacheTTL: 5 * time.Minute,
	}

	cache := NewDNSCache(5 * time.Minute)
	server := NewDNSServer(config, cache, nil)

	// Should not panic
	err := server.Stop()
	assert.NoError(t, err)
}

// TestDNSServerQueryUpstreamNoServers tests upstream query with no servers
func TestDNSServerQueryUpstreamNoServers(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15361",
		Upstream: []string{}, // No upstream servers
		CacheTTL: 5 * time.Minute,
	}

	cache := NewDNSCache(5 * time.Minute)
	server := NewDNSServer(config, cache, nil)

	_, _, err := server.queryUpstream("example.com", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no upstream DNS servers configured")
}

// TestDNSServerResolve tests DNS resolution
func TestDNSServerResolve(t *testing.T) {
	config := DNSConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:15362",
		Upstream: []string{"8.8.8.8", "1.1.1.1"},
		CacheTTL: 5 * time.Minute,
	}

	cache := NewDNSCache(5 * time.Minute)
	server := NewDNSServer(config, cache, nil)

	// Pre-populate cache
	cache.Put("cached.example.com", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, time.Minute)

	// Should hit cache
	addrs, err := server.Resolve("cached.example.com")
	require.NoError(t, err)
	require.Len(t, addrs, 1)
	assert.Equal(t, netip.MustParseAddr("1.2.3.4"), addrs[0])
}

// TestDNSServerStatsStruct tests DNSServerStats struct
func TestDNSServerStatsStruct(t *testing.T) {
	stats := DNSServerStats{
		TotalQueries:   100,
		CacheHits:      80,
		CacheMisses:    20,
		UpstreamErrors: 5,
	}

	assert.Equal(t, int64(100), stats.TotalQueries)
	assert.Equal(t, int64(80), stats.CacheHits)
	assert.Equal(t, int64(20), stats.CacheMisses)
	assert.Equal(t, int64(5), stats.UpstreamErrors)
}
