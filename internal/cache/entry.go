// Package cache provides HTTP caching functionality for the Bifrost proxy.
// It supports tiered storage (memory + disk), domain-based caching rules,
// and is inspired by steamcache/lancache for game download caching.
package cache

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// Entry represents a cached HTTP response.
type Entry struct {
	// Metadata contains cache entry metadata.
	Metadata *Metadata

	// Body is the response body. For streaming large files, this is a reader
	// that streams from storage rather than loading into memory.
	Body io.ReadCloser
}

// Close closes the entry's body if it exists.
func (e *Entry) Close() error {
	if e.Body != nil {
		return e.Body.Close()
	}
	return nil
}

// Metadata holds cache entry metadata.
type Metadata struct {
	// Key is the unique cache key (SHA256 hash).
	Key string `json:"key"`

	// URL is the original request URL.
	URL string `json:"url"`

	// Host is the request host.
	Host string `json:"host"`

	// Method is the HTTP method (typically GET).
	Method string `json:"method"`

	// StatusCode is the HTTP response status code.
	StatusCode int `json:"status_code"`

	// Headers are the response headers to preserve.
	Headers http.Header `json:"headers"`

	// ContentLength is the total content length in bytes.
	ContentLength int64 `json:"content_length"`

	// ContentType is the MIME type of the content.
	ContentType string `json:"content_type"`

	// ETag is the entity tag for cache validation.
	ETag string `json:"etag,omitempty"`

	// LastModified is the last modification time from the origin.
	LastModified time.Time `json:"last_modified,omitempty"`

	// CacheControl contains parsed Cache-Control directives.
	CacheControl *CacheControl `json:"cache_control,omitempty"`

	// CreatedAt is when the entry was cached.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the entry should be considered stale.
	ExpiresAt time.Time `json:"expires_at"`

	// AccessedAt is the last access time (for LRU eviction).
	AccessedAt time.Time `json:"accessed_at"`

	// AccessCount is the number of times this entry was served.
	AccessCount int64 `json:"access_count"`

	// Size is the actual stored size in bytes.
	Size int64 `json:"size_bytes"`

	// Tier indicates which storage tier holds this entry (memory/disk).
	Tier string `json:"tier"`
}

// CacheControl represents parsed Cache-Control header directives.
type CacheControl struct {
	// MaxAge specifies the maximum age in seconds.
	MaxAge int `json:"max_age,omitempty"`

	// SMaxAge specifies the shared cache maximum age.
	SMaxAge int `json:"s_maxage,omitempty"`

	// NoCache indicates the response must be revalidated.
	NoCache bool `json:"no_cache,omitempty"`

	// NoStore indicates the response must not be stored.
	NoStore bool `json:"no_store,omitempty"`

	// MustRevalidate indicates stale responses must be revalidated.
	MustRevalidate bool `json:"must_revalidate,omitempty"`

	// Public indicates the response may be cached by any cache.
	Public bool `json:"public,omitempty"`

	// Private indicates the response is for a single user.
	Private bool `json:"private,omitempty"`

	// Immutable indicates the response will not change.
	Immutable bool `json:"immutable,omitempty"`
}

// ParseCacheControl parses a Cache-Control header value.
func ParseCacheControl(header string) *CacheControl {
	if header == "" {
		return nil
	}

	cc := &CacheControl{}
	directives := strings.Split(header, ",")

	for _, directive := range directives {
		directive = strings.TrimSpace(strings.ToLower(directive))

		switch {
		case directive == "no-cache":
			cc.NoCache = true
		case directive == "no-store":
			cc.NoStore = true
		case directive == "must-revalidate":
			cc.MustRevalidate = true
		case directive == "public":
			cc.Public = true
		case directive == "private":
			cc.Private = true
		case directive == "immutable":
			cc.Immutable = true
		case strings.HasPrefix(directive, "max-age="):
			var age int
			if _, err := parseDirectiveValue(directive, "max-age=", &age); err == nil {
				cc.MaxAge = age
			}
		case strings.HasPrefix(directive, "s-maxage="):
			var age int
			if _, err := parseDirectiveValue(directive, "s-maxage=", &age); err == nil {
				cc.SMaxAge = age
			}
		}
	}

	return cc
}

// parseDirectiveValue parses a directive value like "max-age=3600".
func parseDirectiveValue(directive, prefix string, value *int) (bool, error) {
	if !strings.HasPrefix(directive, prefix) {
		return false, nil
	}
	valueStr := strings.TrimPrefix(directive, prefix)
	var v int
	for _, c := range valueStr {
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + int(c-'0')
	}
	*value = v
	return true, nil
}

// IsCacheable checks if the metadata indicates a cacheable response.
func (m *Metadata) IsCacheable() bool {
	// Check Cache-Control directives
	if m.CacheControl != nil {
		if m.CacheControl.NoStore || m.CacheControl.Private {
			return false
		}
	}

	// Only cache successful responses
	if m.StatusCode != http.StatusOK && m.StatusCode != http.StatusPartialContent {
		return false
	}

	return true
}

// IsExpired checks if the entry has expired.
func (m *Metadata) IsExpired() bool {
	return time.Now().After(m.ExpiresAt)
}

// IsFresh checks if the entry is still fresh (not expired).
func (m *Metadata) IsFresh() bool {
	return !m.IsExpired()
}

// UpdateAccess updates the access time and count.
func (m *Metadata) UpdateAccess() {
	m.AccessedAt = time.Now()
	m.AccessCount++
}

// StorageStats holds storage statistics.
type StorageStats struct {
	// Entries is the number of cached entries.
	Entries int64 `json:"entries"`

	// TotalSize is the total size of all cached content in bytes.
	TotalSize int64 `json:"total_size_bytes"`

	// MaxSize is the maximum allowed size in bytes.
	MaxSize int64 `json:"max_size_bytes"`

	// UsedPercent is the percentage of storage used.
	UsedPercent float64 `json:"used_percent"`

	// HitCount is the total number of cache hits.
	HitCount int64 `json:"hit_count"`

	// MissCount is the total number of cache misses.
	MissCount int64 `json:"miss_count"`

	// EvictionCount is the total number of evictions.
	EvictionCount int64 `json:"eviction_count"`
}

// HitRate returns the cache hit rate (0.0 to 1.0).
func (s *StorageStats) HitRate() float64 {
	total := s.HitCount + s.MissCount
	if total == 0 {
		return 0.0
	}
	return float64(s.HitCount) / float64(total)
}

// truncateKey returns a truncated version of a cache key for logging.
func truncateKey(key string) string {
	if len(key) <= 16 {
		return key
	}
	return key[:16] + "..."
}
