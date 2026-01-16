package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// KeyGenerator generates cache keys from HTTP requests.
type KeyGenerator struct {
	// IgnoreQuery ignores query string in key generation (useful for CDNs).
	IgnoreQuery bool

	// IgnoreScheme ignores the scheme (http/https) in key generation.
	IgnoreScheme bool

	// SortQueryParams sorts query parameters for consistent keys.
	SortQueryParams bool

	// IncludeHeaders includes specific headers in key generation (for Vary support).
	IncludeHeaders []string
}

// DefaultKeyGenerator returns a key generator with sensible defaults.
func DefaultKeyGenerator() *KeyGenerator {
	return &KeyGenerator{
		IgnoreQuery:     false,
		IgnoreScheme:    true,
		SortQueryParams: true,
		IncludeHeaders:  nil,
	}
}

// GenerateKey creates a cache key from an HTTP request.
// The key is a SHA256 hash of the relevant request components.
func (kg *KeyGenerator) GenerateKey(req *http.Request) string {
	h := sha256.New()

	// Method
	h.Write([]byte(req.Method))
	h.Write([]byte{0}) // separator

	// Host
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	h.Write([]byte(strings.ToLower(host)))
	h.Write([]byte{0})

	// Path
	path := "/"
	if req.URL != nil && req.URL.Path != "" {
		path = req.URL.Path
	}
	h.Write([]byte(path))
	h.Write([]byte{0})

	// Query string (if not ignored)
	if !kg.IgnoreQuery && req.URL != nil && req.URL.RawQuery != "" {
		if kg.SortQueryParams {
			// Sort query params for consistent keys
			h.Write([]byte(kg.sortedQuery(req.URL.Query())))
		} else {
			h.Write([]byte(req.URL.RawQuery))
		}
	}
	h.Write([]byte{0})

	// Include specific headers if configured (for Vary support)
	if len(kg.IncludeHeaders) > 0 {
		for _, header := range kg.IncludeHeaders {
			value := req.Header.Get(header)
			if value != "" {
				h.Write([]byte(strings.ToLower(header)))
				h.Write([]byte{':'})
				h.Write([]byte(value))
				h.Write([]byte{0})
			}
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

// sortedQuery returns query parameters sorted by key for consistent hashing.
func (kg *KeyGenerator) sortedQuery(params url.Values) string {
	if len(params) == 0 {
		return ""
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		values := params[k]
		sort.Strings(values) // Sort values too for consistency
		for j, v := range values {
			if j > 0 {
				sb.WriteByte('&')
			}
			sb.WriteString(url.QueryEscape(k))
			sb.WriteByte('=')
			sb.WriteString(url.QueryEscape(v))
		}
	}
	return sb.String()
}

// GenerateKeyFromURL creates a cache key from a URL string.
// Useful for lookups when you don't have the full request.
func (kg *KeyGenerator) GenerateKeyFromURL(method, urlStr string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	req := &http.Request{
		Method: method,
		URL:    parsedURL,
		Host:   parsedURL.Host,
	}

	return kg.GenerateKey(req), nil
}

// GenerateSimpleKey creates a simple cache key from method, host, and path.
// This is a convenience function for quick lookups.
func GenerateSimpleKey(method, host, path string) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(host)))
	h.Write([]byte{0})
	h.Write([]byte(path))
	return hex.EncodeToString(h.Sum(nil))
}

// KeyPrefix returns the first n characters of a key for sharding.
// Used for organizing files in subdirectories on disk.
func KeyPrefix(key string, n int) string {
	if len(key) < n {
		return key
	}
	return key[:n]
}
