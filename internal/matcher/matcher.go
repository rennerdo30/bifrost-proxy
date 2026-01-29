// Package matcher provides domain pattern matching for routing rules.
package matcher

import (
	"errors"
	"strings"
	"sync"
)

// Matcher limits
const (
	// MaxPatterns is the maximum number of patterns
	MaxPatterns = 5000
)

// Matcher errors
var (
	ErrPatternsAtLimit = errors.New("matcher: patterns at maximum limit")
	ErrDuplicatePattern = errors.New("matcher: duplicate pattern")
)

// Matcher provides domain pattern matching functionality.
type Matcher struct {
	patterns []pattern
	mu       sync.RWMutex
}

type pattern struct {
	original string
	parts    []string
	isWild   bool // starts with *. (wildcard subdomain)
	isSuffix bool // starts with .
	hasGlob  bool // contains glob wildcards within parts (e.g., sf-*)
}

// New creates a new Matcher with the given patterns.
func New(patterns []string) *Matcher {
	m := &Matcher{}
	for _, p := range patterns {
		m.AddPattern(p)
	}
	return m
}

// AddPattern adds a pattern to the matcher. Returns error if duplicate or at limit.
// Pattern formats:
//   - "example.com" - exact match
//   - "*.example.com" - wildcard subdomain match
//   - ".example.com" - suffix match (matches example.com and *.example.com)
//   - "*" - match all
//   - "sf-*.example.com" - glob match (sf-* matches sf-abc, sf-xyz, etc.)
//   - "*-api.example.com" - glob match (*-api matches backend-api, frontend-api, etc.)
func (m *Matcher) AddPattern(p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return nil
	}

	// Check for duplicate
	for _, existing := range m.patterns {
		if existing.original == p {
			return ErrDuplicatePattern
		}
	}

	// Check limit
	if len(m.patterns) >= MaxPatterns {
		return ErrPatternsAtLimit
	}

	pat := pattern{original: p}

	if p == "*" {
		pat.isWild = true
		m.patterns = append(m.patterns, pat)
		return nil
	}

	if strings.HasPrefix(p, "*.") {
		pat.isWild = true
		p = p[2:] // Remove "*."
	} else if strings.HasPrefix(p, ".") {
		pat.isSuffix = true
		p = p[1:] // Remove leading "."
	}

	pat.parts = strings.Split(p, ".")

	// Check if any part contains a glob wildcard (but is not just "*")
	for _, part := range pat.parts {
		if strings.Contains(part, "*") {
			pat.hasGlob = true
			break
		}
	}

	m.patterns = append(m.patterns, pat)
	return nil
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

// matchGlobPart checks if a domain part matches a glob pattern part.
// Examples:
//   - "sf-*" matches "sf-abc", "sf-xyz"
//   - "*-api" matches "backend-api", "frontend-api"
//   - "pre-*-suf" matches "pre-middle-suf"
//   - "*" matches anything
func matchGlobPart(pattern, value string) bool {
	// No wildcard, exact match required
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}

	// Single wildcard matches anything
	if pattern == "*" {
		return true
	}

	// Split pattern by * and match each segment
	segments := strings.Split(pattern, "*")

	// Track position in value
	pos := 0

	for i, seg := range segments {
		if seg == "" {
			continue
		}

		// Find the segment in value starting from pos
		idx := strings.Index(value[pos:], seg)
		if idx == -1 {
			return false
		}

		// First segment must be at the beginning if pattern doesn't start with *
		if i == 0 && !strings.HasPrefix(pattern, "*") && idx != 0 {
			return false
		}

		// Move position past this segment
		pos += idx + len(seg)
	}

	// Last segment must be at the end if pattern doesn't end with *
	if !strings.HasSuffix(pattern, "*") {
		lastSeg := segments[len(segments)-1]
		if lastSeg != "" && !strings.HasSuffix(value, lastSeg) {
			return false
		}
	}

	return true
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
			if pat.hasGlob {
				if !matchGlobPart(pat.parts[i], domainParts[offset+i]) {
					return false
				}
			} else if domainParts[offset+i] != pat.parts[i] {
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
			if pat.hasGlob {
				if !matchGlobPart(pat.parts[i], domainParts[offset+i]) {
					return false
				}
			} else if domainParts[offset+i] != pat.parts[i] {
				return false
			}
		}
		return true
	}

	// Exact match (with potential glob parts)
	if len(domainParts) != len(pat.parts) {
		return false
	}
	for i := 0; i < len(pat.parts); i++ {
		if pat.hasGlob {
			if !matchGlobPart(pat.parts[i], domainParts[i]) {
				return false
			}
		} else if domainParts[i] != pat.parts[i] {
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

// RemovePattern removes a pattern from the matcher.
func (m *Matcher) RemovePattern(p string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return
	}

	patterns := make([]pattern, 0, len(m.patterns))
	for _, pat := range m.patterns {
		if pat.original != p {
			patterns = append(patterns, pat)
		}
	}
	m.patterns = patterns
}

// Clear removes all patterns.
func (m *Matcher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patterns = nil
}
