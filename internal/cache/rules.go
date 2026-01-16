package cache

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/matcher"
)

// Rule defines caching behavior for matching domains.
type Rule struct {
	// Name is the unique identifier for this rule.
	Name string

	// Domains are the original domain patterns (for API display).
	Domains []string

	// Matcher matches domains against this rule's patterns.
	Matcher *matcher.Matcher

	// Enabled indicates if this rule is active.
	Enabled bool

	// TTL is the time-to-live for cached entries.
	TTL time.Duration

	// MaxSize is the maximum file size to cache (0 = unlimited).
	MaxSize int64

	// Priority determines which rule applies when multiple match.
	// Higher priority rules take precedence.
	Priority int

	// Methods are HTTP methods to cache (empty = GET only).
	Methods []string

	// ContentTypes are MIME types to cache (empty = all).
	ContentTypes []string

	// IgnoreQuery ignores query string in cache key.
	IgnoreQuery bool

	// RespectCacheControl honors Cache-Control headers from origin.
	RespectCacheControl bool

	// StripHeaders are headers to remove before caching.
	StripHeaders []string

	// Preset is the preset name if this rule was created from a preset.
	Preset string
}

// RuleSet manages a collection of caching rules.
type RuleSet struct {
	mu    sync.RWMutex
	rules []*Rule
}

// NewRuleSet creates a new rule set.
func NewRuleSet() *RuleSet {
	return &RuleSet{
		rules: make([]*Rule, 0),
	}
}

// Add adds a rule to the set.
func (rs *RuleSet) Add(rule *Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Remove existing rule with same name
	for i, r := range rs.rules {
		if r.Name == rule.Name {
			rs.rules = append(rs.rules[:i], rs.rules[i+1:]...)
			break
		}
	}

	rs.rules = append(rs.rules, rule)

	// Sort by priority (highest first)
	sort.Slice(rs.rules, func(i, j int) bool {
		return rs.rules[i].Priority > rs.rules[j].Priority
	})
}

// Remove removes a rule by name.
func (rs *RuleSet) Remove(name string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	for i, r := range rs.rules {
		if r.Name == name {
			rs.rules = append(rs.rules[:i], rs.rules[i+1:]...)
			return true
		}
	}
	return false
}

// Get returns a rule by name.
func (rs *RuleSet) Get(name string) *Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	for _, r := range rs.rules {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// Match finds the best matching rule for a request.
// Returns nil if no rule matches.
func (rs *RuleSet) Match(req *http.Request) *Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	host = strings.ToLower(host)

	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	for _, rule := range rs.rules {
		if !rule.Enabled {
			continue
		}

		// Check domain match
		if rule.Matcher != nil && !rule.Matcher.Match(host) {
			continue
		}

		// Check method
		if !rule.MatchesMethod(method) {
			continue
		}

		return rule
	}

	return nil
}

// MatchHost finds the best matching rule for a host.
func (rs *RuleSet) MatchHost(host string) *Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	host = strings.ToLower(host)
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	for _, rule := range rs.rules {
		if !rule.Enabled {
			continue
		}
		if rule.Matcher != nil && rule.Matcher.Match(host) {
			return rule
		}
	}

	return nil
}

// All returns all rules.
func (rs *RuleSet) All() []*Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	result := make([]*Rule, len(rs.rules))
	copy(result, rs.rules)
	return result
}

// Clear removes all rules.
func (rs *RuleSet) Clear() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = make([]*Rule, 0)
}

// MatchesMethod checks if the rule matches the HTTP method.
func (r *Rule) MatchesMethod(method string) bool {
	if len(r.Methods) == 0 {
		// Default: only GET
		return method == "GET"
	}

	method = strings.ToUpper(method)
	for _, m := range r.Methods {
		if strings.ToUpper(m) == method {
			return true
		}
	}
	return false
}

// MatchesContentType checks if the rule matches the content type.
func (r *Rule) MatchesContentType(contentType string) bool {
	if len(r.ContentTypes) == 0 {
		return true // Match all
	}

	contentType = strings.ToLower(contentType)
	// Remove parameters (e.g., charset)
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = strings.TrimSpace(contentType[:idx])
	}

	for _, ct := range r.ContentTypes {
		ct = strings.ToLower(ct)
		if ct == contentType || ct == "*" || ct == "*/*" {
			return true
		}
		// Support wildcards like "application/*"
		if strings.HasSuffix(ct, "/*") {
			prefix := strings.TrimSuffix(ct, "/*")
			if strings.HasPrefix(contentType, prefix+"/") {
				return true
			}
		}
	}
	return false
}

// ShouldStripHeader checks if a header should be stripped before caching.
func (r *Rule) ShouldStripHeader(header string) bool {
	header = strings.ToLower(header)
	for _, h := range r.StripHeaders {
		if strings.ToLower(h) == header {
			return true
		}
	}
	return false
}

// NewRuleFromConfig creates a Rule from a RuleConfig.
func NewRuleFromConfig(cfg RuleConfig) (*Rule, error) {
	// Create matcher from domain patterns
	var m *matcher.Matcher
	if len(cfg.Domains) > 0 {
		m = matcher.New(cfg.Domains)
	}

	return &Rule{
		Name:                cfg.Name,
		Domains:             cfg.Domains,
		Matcher:             m,
		Enabled:             cfg.Enabled,
		TTL:                 cfg.TTL.Duration(),
		MaxSize:             cfg.MaxSize.Int64(),
		Priority:            cfg.Priority,
		Methods:             cfg.Methods,
		ContentTypes:        cfg.ContentTypes,
		IgnoreQuery:         cfg.IgnoreQuery,
		RespectCacheControl: cfg.RespectCacheControl,
		StripHeaders:        cfg.StripHeaders,
	}, nil
}

// LoadRulesFromConfig loads rules from a slice of RuleConfig.
func LoadRulesFromConfig(configs []RuleConfig) (*RuleSet, error) {
	rs := NewRuleSet()

	for _, cfg := range configs {
		rule, err := NewRuleFromConfig(cfg)
		if err != nil {
			return nil, err
		}
		rs.Add(rule)
	}

	return rs, nil
}
