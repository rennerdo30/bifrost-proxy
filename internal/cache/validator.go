package cache

import (
	"net/http"
	"time"
)

// Validator handles HTTP cache validation.
type Validator struct{}

// NewValidator creates a new cache validator.
func NewValidator() *Validator {
	return &Validator{}
}

// IsFresh checks if a cached entry is still valid/fresh.
func (v *Validator) IsFresh(entry *Entry) bool {
	if entry == nil || entry.Metadata == nil {
		return false
	}

	meta := entry.Metadata

	// Check explicit expiration
	if time.Now().After(meta.ExpiresAt) {
		return false
	}

	// Check Cache-Control directives
	cc := meta.CacheControl
	if cc != nil {
		if cc.NoCache || cc.NoStore {
			return false
		}
		if cc.MaxAge > 0 {
			maxAge := time.Duration(cc.MaxAge) * time.Second
			if time.Since(meta.CreatedAt) > maxAge {
				return false
			}
		}
	}

	return true
}

// NeedsRevalidation checks if the entry should be revalidated with origin.
func (v *Validator) NeedsRevalidation(entry *Entry) bool {
	if entry == nil || entry.Metadata == nil {
		return true
	}

	cc := entry.Metadata.CacheControl
	if cc == nil {
		return false
	}

	// Must revalidate if explicitly set
	if cc.MustRevalidate {
		return entry.Metadata.IsExpired()
	}

	return false
}

// BuildConditionalRequest adds validation headers to a request.
// This allows the origin to respond with 304 Not Modified if the cached
// content is still valid.
func (v *Validator) BuildConditionalRequest(req *http.Request, entry *Entry) {
	if entry == nil || entry.Metadata == nil {
		return
	}

	meta := entry.Metadata

	// Add If-None-Match header if we have an ETag
	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}

	// Add If-Modified-Since header if we have Last-Modified
	if !meta.LastModified.IsZero() {
		req.Header.Set("If-Modified-Since", meta.LastModified.Format(http.TimeFormat))
	}
}

// HandleConditionalResponse processes a response that may be 304 Not Modified.
// Returns true if the cached entry is still valid and can be used.
func (v *Validator) HandleConditionalResponse(entry *Entry, resp *http.Response) bool {
	if resp.StatusCode != http.StatusNotModified {
		return false
	}

	// Update metadata from new response headers
	if entry != nil && entry.Metadata != nil {
		meta := entry.Metadata

		// Update access time
		meta.AccessedAt = time.Now()
		meta.AccessCount++

		// Update ETag if provided
		if etag := resp.Header.Get("ETag"); etag != "" {
			meta.ETag = etag
		}

		// Update expiry from new Cache-Control
		if cc := resp.Header.Get("Cache-Control"); cc != "" {
			meta.CacheControl = ParseCacheControl(cc)
			if meta.CacheControl != nil && meta.CacheControl.MaxAge > 0 {
				meta.ExpiresAt = time.Now().Add(time.Duration(meta.CacheControl.MaxAge) * time.Second)
			}
		}
	}

	return true
}

// ShouldCache determines if a response should be cached.
func (v *Validator) ShouldCache(req *http.Request, resp *http.Response) bool {
	// Only cache successful responses
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return false
	}

	// Only cache GET requests
	if req.Method != http.MethodGet {
		return false
	}

	// Check request Cache-Control
	if reqCC := req.Header.Get("Cache-Control"); reqCC != "" {
		cc := ParseCacheControl(reqCC)
		if cc != nil && cc.NoStore {
			return false
		}
	}

	// Check response Cache-Control
	if respCC := resp.Header.Get("Cache-Control"); respCC != "" {
		cc := ParseCacheControl(respCC)
		if cc != nil {
			if cc.NoStore || cc.Private {
				return false
			}
		}
	}

	// Don't cache responses with Authorization header in request
	if req.Header.Get("Authorization") != "" {
		// Unless response explicitly allows caching
		if respCC := resp.Header.Get("Cache-Control"); respCC != "" {
			cc := ParseCacheControl(respCC)
			if cc == nil || !cc.Public {
				return false
			}
		} else {
			return false
		}
	}

	// Don't cache responses with Set-Cookie
	if resp.Header.Get("Set-Cookie") != "" {
		return false
	}

	return true
}

// CalculateFreshness calculates how long an entry will remain fresh.
func (v *Validator) CalculateFreshness(entry *Entry) time.Duration {
	if entry == nil || entry.Metadata == nil {
		return 0
	}

	remaining := time.Until(entry.Metadata.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// CalculateAge calculates the age of a cached entry.
func (v *Validator) CalculateAge(entry *Entry) time.Duration {
	if entry == nil || entry.Metadata == nil {
		return 0
	}

	return time.Since(entry.Metadata.CreatedAt)
}

// IsStale checks if an entry is stale (expired but may still be usable).
func (v *Validator) IsStale(entry *Entry) bool {
	if entry == nil || entry.Metadata == nil {
		return true
	}

	return time.Now().After(entry.Metadata.ExpiresAt)
}

// CanServeStale checks if a stale entry can still be served.
// Some Cache-Control directives allow serving stale content.
func (v *Validator) CanServeStale(entry *Entry) bool {
	if entry == nil || entry.Metadata == nil || entry.Metadata.CacheControl == nil {
		return false
	}

	cc := entry.Metadata.CacheControl

	// Don't serve stale if must-revalidate is set
	if cc.MustRevalidate {
		return false
	}

	// Immutable content can be served stale
	if cc.Immutable {
		return true
	}

	return false
}
