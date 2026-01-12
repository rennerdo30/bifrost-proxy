// Package matcher provides domain pattern matching for routing rules.
package matcher

import (
	"strings"
	"sync"
)

// Matcher provides domain pattern matching functionality.
type Matcher struct {
	patterns []pattern
	mu       sync.RWMutex
}

type pattern struct {
	original string
	parts    []string
	isWild   bool // starts with *
	isSuffix bool // starts with .
}

// New creates a new Matcher with the given patterns.
func New(patterns []string) *Matcher {
	m := &Matcher{}
	for _, p := range patterns {
		m.AddPattern(p)
	}
	return m
}

// AddPattern adds a pattern to the matcher.
// Pattern formats:
//   - "example.com" - exact match
//   - "*.example.com" - wildcard subdomain match
//   - ".example.com" - suffix match (matches example.com and *.example.com)
//   - "*" - match all
func (m *Matcher) AddPattern(p string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return
	}

	pat := pattern{original: p}

	if p == "*" {
		pat.isWild = true
		m.patterns = append(m.patterns, pat)
		return
	}

	if strings.HasPrefix(p, "*.") {
		pat.isWild = true
		p = p[2:] // Remove "*."
	} else if strings.HasPrefix(p, ".") {
		pat.isSuffix = true
		p = p[1:] // Remove leading "."
	}

	pat.parts = strings.Split(p, ".")
	m.patterns = append(m.patterns, pat)
}

// Match checks if the given domain matches any pattern.
func (m *Matcher) Match(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	// Remove port if present
	if idx := strings.LastIndex(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	domainParts := strings.Split(domain, ".")

	for _, pat := range m.patterns {
		if matchPattern(pat, domainParts) {
			return true
		}
	}

	return false
}

// matchPattern checks if domain parts match a single pattern.
func matchPattern(pat pattern, domainParts []string) bool {
	// Universal wildcard
	if pat.isWild && len(pat.parts) == 0 {
		return true
	}

	// Suffix match (e.g., ".example.com" matches "example.com" and "sub.example.com")
	if pat.isSuffix {
		if len(domainParts) < len(pat.parts) {
			return false
		}
		// Check if domain ends with pattern
		offset := len(domainParts) - len(pat.parts)
		for i := 0; i < len(pat.parts); i++ {
			if domainParts[offset+i] != pat.parts[i] {
				return false
			}
		}
		return true
	}

	// Wildcard subdomain match (e.g., "*.example.com")
	if pat.isWild {
		if len(domainParts) <= len(pat.parts) {
			return false
		}
		// Check if domain ends with pattern (excluding the wildcard prefix)
		offset := len(domainParts) - len(pat.parts)
		for i := 0; i < len(pat.parts); i++ {
			if domainParts[offset+i] != pat.parts[i] {
				return false
			}
		}
		return true
	}

	// Exact match
	if len(domainParts) != len(pat.parts) {
		return false
	}
	for i := 0; i < len(pat.parts); i++ {
		if domainParts[i] != pat.parts[i] {
			return false
		}
	}
	return true
}

// Patterns returns all registered patterns.
func (m *Matcher) Patterns() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, len(m.patterns))
	for i, p := range m.patterns {
		result[i] = p.original
	}
	return result
}

// Clear removes all patterns.
func (m *Matcher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patterns = nil
}
