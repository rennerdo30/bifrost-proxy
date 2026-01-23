package vpnprovider

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServerCache(t *testing.T) {
	t.Run("with valid TTL", func(t *testing.T) {
		cache := NewServerCache(1 * time.Hour)
		assert.NotNil(t, cache)
		assert.Equal(t, 1*time.Hour, cache.TTL())
	})

	t.Run("with zero TTL uses default", func(t *testing.T) {
		cache := NewServerCache(0)
		assert.Equal(t, DefaultCacheTTL, cache.TTL())
	})

	t.Run("with negative TTL uses default", func(t *testing.T) {
		cache := NewServerCache(-1 * time.Hour)
		assert.Equal(t, DefaultCacheTTL, cache.TTL())
	})
}

func TestServerCache_Servers(t *testing.T) {
	cache := NewServerCache(1 * time.Hour)

	t.Run("empty cache returns false", func(t *testing.T) {
		servers, ok := cache.GetServers()
		assert.False(t, ok)
		assert.Nil(t, servers)
	})

	t.Run("set and get servers", func(t *testing.T) {
		servers := []Server{
			{ID: "s1", Hostname: "server1.example.com", Country: "US", Load: 30},
			{ID: "s2", Hostname: "server2.example.com", Country: "DE", Load: 50},
		}
		cache.SetServers(servers)

		result, ok := cache.GetServers()
		assert.True(t, ok)
		require.Len(t, result, 2)
		assert.Equal(t, "s1", result[0].ID)
		assert.Equal(t, "s2", result[1].ID)
	})

	t.Run("returns copy not reference", func(t *testing.T) {
		servers := []Server{{ID: "s1", Hostname: "test"}}
		cache.SetServers(servers)

		result, _ := cache.GetServers()
		result[0].Hostname = "modified"

		// Original should be unchanged
		result2, _ := cache.GetServers()
		assert.Equal(t, "test", result2[0].Hostname)
	})
}

func TestServerCache_Countries(t *testing.T) {
	cache := NewServerCache(1 * time.Hour)

	t.Run("empty cache returns false", func(t *testing.T) {
		countries, ok := cache.GetCountries()
		assert.False(t, ok)
		assert.Nil(t, countries)
	})

	t.Run("set and get countries", func(t *testing.T) {
		// First set servers to update lastFetch
		cache.SetServers([]Server{{ID: "test"}})

		countries := []Country{
			{ID: 1, Code: "US", Name: "United States"},
			{ID: 2, Code: "DE", Name: "Germany"},
		}
		cache.SetCountries(countries)

		result, ok := cache.GetCountries()
		assert.True(t, ok)
		require.Len(t, result, 2)
		assert.Equal(t, "US", result[0].Code)
	})
}

func TestServerCache_Expiration(t *testing.T) {
	// Use very short TTL for testing
	cache := NewServerCache(50 * time.Millisecond)

	servers := []Server{{ID: "test"}}
	cache.SetServers(servers)

	// Should be valid immediately
	_, ok := cache.GetServers()
	assert.True(t, ok)
	assert.False(t, cache.IsExpired())

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	// Should be expired now
	assert.True(t, cache.IsExpired())
	_, ok = cache.GetServers()
	assert.False(t, ok)
}

func TestServerCache_Clear(t *testing.T) {
	cache := NewServerCache(1 * time.Hour)

	cache.SetServers([]Server{{ID: "test"}})
	cache.SetCountries([]Country{{Code: "US"}})

	cache.Clear()

	servers, ok := cache.GetServers()
	assert.False(t, ok)
	assert.Nil(t, servers)

	countries, ok := cache.GetCountries()
	assert.False(t, ok)
	assert.Nil(t, countries)

	assert.True(t, cache.LastFetch().IsZero())
}

func TestServerCache_ServerCount(t *testing.T) {
	cache := NewServerCache(1 * time.Hour)

	assert.Equal(t, 0, cache.ServerCount())

	cache.SetServers([]Server{{ID: "1"}, {ID: "2"}, {ID: "3"}})
	assert.Equal(t, 3, cache.ServerCount())
}

func TestServerCache_SetTTL(t *testing.T) {
	cache := NewServerCache(1 * time.Hour)

	cache.SetTTL(2 * time.Hour)
	assert.Equal(t, 2*time.Hour, cache.TTL())
}

func TestFilterServers(t *testing.T) {
	servers := []Server{
		{ID: "us1", Hostname: "us1.example.com", Country: "United States", CountryCode: "US", City: "New York", Load: 30, Features: []string{"p2p", "streaming"}, WireGuard: &WireGuardServer{PublicKey: "key1"}},
		{ID: "us2", Hostname: "us2.example.com", Country: "United States", CountryCode: "US", City: "Los Angeles", Load: 60, Features: []string{"standard"}, OpenVPN: &OpenVPNServer{Hostname: "ovpn.us2"}},
		{ID: "de1", Hostname: "de1.example.com", Country: "Germany", CountryCode: "DE", City: "Berlin", Load: 25, Features: []string{"p2p"}, WireGuard: &WireGuardServer{PublicKey: "key2"}},
		{ID: "de2", Hostname: "de2.example.com", Country: "Germany", CountryCode: "DE", City: "Frankfurt", Load: 80, Features: []string{"standard"}, WireGuard: &WireGuardServer{PublicKey: "key3"}},
	}

	t.Run("filter by country code", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{Country: "US"})
		assert.Len(t, result, 2)
	})

	t.Run("filter by country name", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{Country: "Germany"})
		assert.Len(t, result, 2)
	})

	t.Run("filter by city", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{City: "Berlin"})
		assert.Len(t, result, 1)
		assert.Equal(t, "de1", result[0].ID)
	})

	t.Run("filter by max load", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{MaxLoad: 50})
		assert.Len(t, result, 2) // us1 (30) and de1 (25)
	})

	t.Run("filter by protocol wireguard", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{Protocol: "wireguard"})
		assert.Len(t, result, 3)
	})

	t.Run("filter by protocol openvpn", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{Protocol: "openvpn"})
		assert.Len(t, result, 1)
		assert.Equal(t, "us2", result[0].ID)
	})

	t.Run("filter by features", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{Features: []string{"p2p"}})
		assert.Len(t, result, 2) // us1 and de1
	})

	t.Run("filter by server ID", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{ServerID: "de1"})
		assert.Len(t, result, 1)
		assert.Equal(t, "de1", result[0].ID)
	})

	t.Run("combined filters", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{
			Country:  "US",
			MaxLoad:  50,
			Protocol: "wireguard",
		})
		assert.Len(t, result, 1)
		assert.Equal(t, "us1", result[0].ID)
	})

	t.Run("fastest sorts by load", func(t *testing.T) {
		result := FilterServers(servers, ServerCriteria{Fastest: true})
		require.Len(t, result, 4)
		assert.Equal(t, "de1", result[0].ID) // Load 25
		assert.Equal(t, "us1", result[1].ID) // Load 30
	})
}

func TestSelectBestServer(t *testing.T) {
	servers := []Server{
		{ID: "s1", CountryCode: "US", Load: 50},
		{ID: "s2", CountryCode: "US", Load: 30},
		{ID: "s3", CountryCode: "DE", Load: 20},
	}

	t.Run("selects best by load", func(t *testing.T) {
		result := SelectBestServer(servers, ServerCriteria{Country: "US", Fastest: true})
		require.NotNil(t, result)
		assert.Equal(t, "s2", result.ID)
	})

	t.Run("returns nil for no matches", func(t *testing.T) {
		result := SelectBestServer(servers, ServerCriteria{Country: "JP"})
		assert.Nil(t, result)
	})
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"United States", "United States", true},
		{"United States", "united states", true},
		{"United States", "United", true},
		{"United States", "States", true},
		{"US", "us", true},
		{"US", "US", true},
		{"US", "usa", false},
		{"", "", true},
		{"test", "", true},
		{"", "test", false},
	}

	for _, tc := range tests {
		t.Run(tc.a+"_"+tc.b, func(t *testing.T) {
			assert.Equal(t, tc.expected, containsIgnoreCase(tc.a, tc.b))
		})
	}
}

func TestSortByLoad(t *testing.T) {
	servers := []Server{
		{ID: "s1", Load: 50},
		{ID: "s2", Load: 30},
		{ID: "s3", Load: 80},
		{ID: "s4", Load: 10},
	}

	sortByLoad(servers)

	assert.Equal(t, "s4", servers[0].ID) // Load 10
	assert.Equal(t, "s2", servers[1].ID) // Load 30
	assert.Equal(t, "s1", servers[2].ID) // Load 50
	assert.Equal(t, "s3", servers[3].ID) // Load 80
}
