package vpnprovider

import (
	"sync"
	"time"
)

// DefaultCacheTTL is the default time-to-live for cached server lists.
const DefaultCacheTTL = 6 * time.Hour

// ServerCache provides thread-safe caching for server lists.
type ServerCache struct {
	servers   []Server
	countries []Country
	lastFetch time.Time
	ttl       time.Duration
	mu        sync.RWMutex
}

// NewServerCache creates a new server cache with the specified TTL.
func NewServerCache(ttl time.Duration) *ServerCache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &ServerCache{
		ttl: ttl,
	}
}

// GetServers returns cached servers if still valid.
// Returns nil, false if cache is empty or expired.
func (c *ServerCache) GetServers() ([]Server, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.servers) == 0 || c.isExpiredLocked() {
		return nil, false
	}

	// Return a copy to prevent modification
	result := make([]Server, len(c.servers))
	copy(result, c.servers)
	return result, true
}

// SetServers updates the cache with new servers.
func (c *ServerCache) SetServers(servers []Server) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.servers = make([]Server, len(servers))
	copy(c.servers, servers)
	c.lastFetch = time.Now()
}

// GetCountries returns cached countries if still valid.
func (c *ServerCache) GetCountries() ([]Country, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.countries) == 0 || c.isExpiredLocked() {
		return nil, false
	}

	result := make([]Country, len(c.countries))
	copy(result, c.countries)
	return result, true
}

// SetCountries updates the cache with new countries.
func (c *ServerCache) SetCountries(countries []Country) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.countries = make([]Country, len(countries))
	copy(c.countries, countries)
}

// IsExpired checks if the cache needs refresh.
func (c *ServerCache) IsExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isExpiredLocked()
}

// isExpiredLocked checks expiration without locking (must hold lock).
func (c *ServerCache) isExpiredLocked() bool {
	return time.Since(c.lastFetch) > c.ttl
}

// Clear empties the cache.
func (c *ServerCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.servers = nil
	c.countries = nil
	c.lastFetch = time.Time{}
}

// LastFetch returns the time of the last cache update.
func (c *ServerCache) LastFetch() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastFetch
}

// TTL returns the cache time-to-live.
func (c *ServerCache) TTL() time.Duration {
	return c.ttl
}

// SetTTL updates the cache TTL.
func (c *ServerCache) SetTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
}

// ServerCount returns the number of cached servers.
func (c *ServerCache) ServerCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.servers)
}

// FilterServers returns servers matching the given criteria.
func FilterServers(servers []Server, criteria ServerCriteria) []Server {
	var result []Server //nolint:prealloc // Size unknown due to filtering

	for _, s := range servers {
		// Filter by specific server ID
		if criteria.ServerID != "" && s.ID != criteria.ServerID {
			continue
		}

		// Filter by country (case-insensitive)
		if criteria.Country != "" {
			if !matchesCountry(s, criteria.Country) {
				continue
			}
		}

		// Filter by city (case-insensitive)
		if criteria.City != "" {
			if !containsIgnoreCase(s.City, criteria.City) {
				continue
			}
		}

		// Filter by max load
		if criteria.MaxLoad > 0 && s.Load > criteria.MaxLoad {
			continue
		}

		// Filter by protocol support
		if criteria.Protocol == "wireguard" && s.WireGuard == nil {
			continue
		}
		if criteria.Protocol == "openvpn" && s.OpenVPN == nil {
			continue
		}

		// Filter by required features
		if len(criteria.Features) > 0 && !hasAllFeatures(s, criteria.Features) {
			continue
		}

		result = append(result, s)
	}

	// Sort by load if fastest is requested
	if criteria.Fastest && len(result) > 1 {
		sortByLoad(result)
	}

	return result
}

// matchesCountry checks if server matches country (code or name).
func matchesCountry(s Server, country string) bool {
	return containsIgnoreCase(s.CountryCode, country) ||
		containsIgnoreCase(s.Country, country)
}

// containsIgnoreCase checks if a contains b (case-insensitive).
func containsIgnoreCase(a, b string) bool {
	if len(a) < len(b) {
		return false
	}
	return equalFoldASCII(a, b) || containsFoldASCII(a, b)
}

// equalFoldASCII is a simple ASCII case-insensitive comparison.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// containsFoldASCII checks if a contains b (case-insensitive ASCII).
func containsFoldASCII(a, b string) bool {
	if len(b) == 0 {
		return true
	}
	if len(a) < len(b) {
		return false
	}
	for i := 0; i <= len(a)-len(b); i++ {
		if equalFoldASCII(a[i:i+len(b)], b) {
			return true
		}
	}
	return false
}

// hasAllFeatures checks if server has all required features.
func hasAllFeatures(s Server, features []string) bool {
	featureSet := make(map[string]bool)
	for _, f := range s.Features {
		featureSet[f] = true
	}
	for _, f := range features {
		if !featureSet[f] {
			return false
		}
	}
	return true
}

// sortByLoad sorts servers by load (ascending).
func sortByLoad(servers []Server) {
	// Simple insertion sort for typically small lists
	for i := 1; i < len(servers); i++ {
		j := i
		for j > 0 && servers[j].Load < servers[j-1].Load {
			servers[j], servers[j-1] = servers[j-1], servers[j]
			j--
		}
	}
}

// SelectBestServer selects the best server from a list based on criteria.
func SelectBestServer(servers []Server, criteria ServerCriteria) *Server {
	filtered := FilterServers(servers, criteria)
	if len(filtered) == 0 {
		return nil
	}
	// Return first (lowest load if sorted, or first match)
	return &filtered[0]
}
