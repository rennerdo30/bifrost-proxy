package vpn

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/rennerdo30/bifrost-proxy/internal/matcher"
)

// Split tunnel limits
const (
	// MaxAppRules is the maximum number of app rules
	MaxAppRules = 500
	// MaxIPRules is the maximum number of IP/CIDR rules
	MaxIPRules = 5000
	// MaxDomainPatterns is the maximum number of domain patterns
	MaxDomainPatterns = 5000
)

// Split tunnel errors
var (
	ErrAppRulesAtLimit    = errors.New("split tunnel: app rules at maximum limit")
	ErrIPRulesAtLimit     = errors.New("split tunnel: IP rules at maximum limit")
	ErrDomainPatternsAtLimit = errors.New("split tunnel: domain patterns at maximum limit")
	ErrDuplicateRule      = errors.New("split tunnel: duplicate rule")
)

// Action represents the split tunnel decision.
type Action string

const (
	// ActionTunnel means traffic should go through the VPN tunnel.
	ActionTunnel Action = "tunnel"
	// ActionBypass means traffic should bypass the VPN (direct connection).
	ActionBypass Action = "bypass"
)

// Decision represents a split tunnel routing decision.
type Decision struct {
	Action    Action // ActionTunnel or ActionBypass
	Reason    string // Human-readable reason for the decision
	MatchedBy string // What matched: "app", "domain", "ip", "always_bypass", "default"
}

// SplitTunnelConfig contains split tunnel configuration.
type SplitTunnelConfig struct {
	// Mode determines the split tunnel behavior.
	// "exclude": Traffic to listed items bypasses the VPN (default goes through VPN)
	// "include": Only traffic to listed items goes through VPN (default bypasses)
	Mode string `yaml:"mode"`

	// Apps lists applications to include/exclude from VPN.
	Apps []AppRule `yaml:"apps"`

	// Domains lists domain patterns to include/exclude.
	Domains []string `yaml:"domains"`

	// IPs lists IP addresses or CIDR ranges to include/exclude.
	IPs []string `yaml:"ips"`

	// AlwaysBypass lists destinations that always bypass the VPN.
	// These are checked before other rules (e.g., LAN, localhost).
	AlwaysBypass []string `yaml:"always_bypass"`
}

// AppRule defines a rule for matching applications.
type AppRule struct {
	Name string `yaml:"name"` // Process name (e.g., "slack", "zoom")
	Path string `yaml:"path"` // Full executable path (optional, more specific)
}

// Validate validates the split tunnel configuration.
func (c *SplitTunnelConfig) Validate() error {
	if c.Mode == "" {
		c.Mode = "exclude"
	}
	if c.Mode != "exclude" && c.Mode != "include" {
		return &ConfigError{Field: "split_tunnel.mode", Message: "must be 'exclude' or 'include'"}
	}
	return nil
}

// SplitTunnelEngine makes routing decisions for packets.
type SplitTunnelEngine struct {
	mode string // "exclude" or "include"

	// Matchers
	appMatcher       *AppMatcher
	domainMatcher    *matcher.Matcher
	ipMatcher        *IPMatcher
	alwaysBypassMatcher *IPMatcher

	// DNS cache for reverse lookups
	dnsCache *DNSCache

	mu sync.RWMutex
}

// NewSplitTunnelEngine creates a new split tunnel engine.
func NewSplitTunnelEngine(cfg SplitTunnelConfig, dnsCache *DNSCache) (*SplitTunnelEngine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	engine := &SplitTunnelEngine{
		mode:     cfg.Mode,
		dnsCache: dnsCache,
	}

	// Initialize app matcher
	engine.appMatcher = NewAppMatcher()
	for _, app := range cfg.Apps {
		engine.appMatcher.AddRule(app)
	}

	// Initialize domain matcher
	engine.domainMatcher = matcher.New(cfg.Domains)

	// Initialize IP matcher
	engine.ipMatcher = NewIPMatcher()
	for _, ip := range cfg.IPs {
		engine.ipMatcher.Add(ip)
	}

	// Initialize always-bypass matcher with common defaults
	engine.alwaysBypassMatcher = NewIPMatcher()

	// Add default bypass rules (localhost, link-local)
	defaultBypass := []string{
		"127.0.0.0/8",      // IPv4 loopback
		"::1/128",          // IPv6 loopback
		"169.254.0.0/16",   // IPv4 link-local
		"fe80::/10",        // IPv6 link-local
	}
	for _, cidr := range defaultBypass {
		engine.alwaysBypassMatcher.Add(cidr)
	}

	// Add user-configured always-bypass
	for _, cidr := range cfg.AlwaysBypass {
		engine.alwaysBypassMatcher.Add(cidr)
	}

	return engine, nil
}

// Decide makes a routing decision for a packet.
func (e *SplitTunnelEngine) Decide(packet *IPPacket, procInfo *ProcessInfo) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	dstIP := packet.DstIP

	// 1. Check always-bypass first (localhost, LAN, etc.)
	if e.alwaysBypassMatcher.Match(dstIP) {
		return Decision{
			Action:    ActionBypass,
			Reason:    "destination in always-bypass list",
			MatchedBy: "always_bypass",
		}
	}

	// 2. Check app rules if we have process info
	if procInfo != nil && e.appMatcher.Match(procInfo) {
		if e.mode == "exclude" {
			return Decision{
				Action:    ActionBypass,
				Reason:    "app in exclude list: " + procInfo.Name,
				MatchedBy: "app",
			}
		}
		return Decision{
			Action:    ActionTunnel,
			Reason:    "app in include list: " + procInfo.Name,
			MatchedBy: "app",
		}
	}

	// 3. Check IP rules
	if e.ipMatcher.Match(dstIP) {
		if e.mode == "exclude" {
			return Decision{
				Action:    ActionBypass,
				Reason:    "IP in exclude list: " + dstIP.String(),
				MatchedBy: "ip",
			}
		}
		return Decision{
			Action:    ActionTunnel,
			Reason:    "IP in include list: " + dstIP.String(),
			MatchedBy: "ip",
		}
	}

	// 4. Check domain rules (reverse DNS lookup)
	if e.dnsCache != nil {
		if domains := e.dnsCache.ReverseLookup(dstIP); len(domains) > 0 {
			for _, domain := range domains {
				if e.domainMatcher.Match(domain) {
					if e.mode == "exclude" {
						return Decision{
							Action:    ActionBypass,
							Reason:    "domain in exclude list: " + domain,
							MatchedBy: "domain",
						}
					}
					return Decision{
						Action:    ActionTunnel,
						Reason:    "domain in include list: " + domain,
						MatchedBy: "domain",
					}
				}
			}
		}
	}

	// 5. Default action based on mode
	if e.mode == "exclude" {
		// In exclude mode, default is to tunnel
		return Decision{
			Action:    ActionTunnel,
			Reason:    "default action (exclude mode)",
			MatchedBy: "default",
		}
	}

	// In include mode, default is to bypass
	return Decision{
		Action:    ActionBypass,
		Reason:    "default action (include mode)",
		MatchedBy: "default",
	}
}

// AddApp adds an app rule to the split tunnel.
func (e *SplitTunnelEngine) AddApp(app AppRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.appMatcher.AddRule(app)
}

// RemoveApp removes an app rule from the split tunnel.
func (e *SplitTunnelEngine) RemoveApp(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.appMatcher.RemoveRule(name)
}

// AddDomain adds a domain pattern to the split tunnel.
func (e *SplitTunnelEngine) AddDomain(pattern string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.domainMatcher.AddPattern(pattern)
}

// RemoveDomain removes a domain pattern from the split tunnel.
func (e *SplitTunnelEngine) RemoveDomain(pattern string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.domainMatcher.RemovePattern(pattern)
}

// AddIP adds an IP or CIDR to the split tunnel.
func (e *SplitTunnelEngine) AddIP(cidr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ipMatcher.Add(cidr)
}

// RemoveIP removes an IP or CIDR from the split tunnel.
func (e *SplitTunnelEngine) RemoveIP(cidr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ipMatcher.Remove(cidr)
}

// SetMode sets the split tunnel mode ("exclude" or "include").
func (e *SplitTunnelEngine) SetMode(mode string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = mode
}

// AppMatcher matches applications by name or path.
type AppMatcher struct {
	rules []AppRule
	mu    sync.RWMutex
}

// NewAppMatcher creates a new app matcher.
func NewAppMatcher() *AppMatcher {
	return &AppMatcher{
		rules: make([]AppRule, 0),
	}
}

// AddRule adds an app rule. Returns error if duplicate or at limit.
func (m *AppMatcher) AddRule(rule AppRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicates
	for _, existing := range m.rules {
		if strings.EqualFold(existing.Name, rule.Name) {
			return ErrDuplicateRule
		}
	}

	// Check limit
	if len(m.rules) >= MaxAppRules {
		return ErrAppRulesAtLimit
	}

	m.rules = append(m.rules, rule)
	return nil
}

// RemoveRule removes an app rule by name.
func (m *AppMatcher) RemoveRule(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rules := make([]AppRule, 0, len(m.rules))
	for _, rule := range m.rules {
		if !strings.EqualFold(rule.Name, name) {
			rules = append(rules, rule)
		}
	}
	m.rules = rules
}

// Match checks if a process matches any app rule.
func (m *AppMatcher) Match(proc *ProcessInfo) bool {
	if proc == nil {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, rule := range m.rules {
		// Check path first (more specific)
		if rule.Path != "" && strings.EqualFold(proc.Path, rule.Path) {
			return true
		}
		// Check name (case-insensitive)
		if rule.Name != "" && strings.EqualFold(proc.Name, rule.Name) {
			return true
		}
	}
	return false
}

// Rules returns a copy of all app rules.
func (m *AppMatcher) Rules() []AppRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rules := make([]AppRule, len(m.rules))
	copy(rules, m.rules)
	return rules
}

// IPMatcher matches IP addresses and CIDR ranges.
type IPMatcher struct {
	ips   map[netip.Addr]bool
	cidrs []netip.Prefix
	mu    sync.RWMutex
}

// NewIPMatcher creates a new IP matcher.
func NewIPMatcher() *IPMatcher {
	return &IPMatcher{
		ips:   make(map[netip.Addr]bool),
		cidrs: make([]netip.Prefix, 0),
	}
}

// Add adds an IP address or CIDR range. Returns error if duplicate or at limit.
func (m *IPMatcher) Add(entry string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check total limit
	totalEntries := len(m.ips) + len(m.cidrs)
	if totalEntries >= MaxIPRules {
		return ErrIPRulesAtLimit
	}

	// Try parsing as prefix (CIDR)
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		// Check for duplicate
		for _, existing := range m.cidrs {
			if existing == prefix {
				return ErrDuplicateRule
			}
		}
		m.cidrs = append(m.cidrs, prefix)
		return nil
	}

	// Try parsing as address
	if addr, err := netip.ParseAddr(entry); err == nil {
		// Check for duplicate
		if m.ips[addr] {
			return ErrDuplicateRule
		}
		m.ips[addr] = true
		return nil
	}

	// Try parsing as old net.IP format
	if ip := net.ParseIP(entry); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			// Check for duplicate
			if m.ips[addr] {
				return ErrDuplicateRule
			}
			m.ips[addr] = true
			return nil
		}
	}

	return nil
}

// Remove removes an IP address or CIDR range.
func (m *IPMatcher) Remove(entry string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Try as prefix
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		cidrs := make([]netip.Prefix, 0, len(m.cidrs))
		for _, p := range m.cidrs {
			if p != prefix {
				cidrs = append(cidrs, p)
			}
		}
		m.cidrs = cidrs
		return
	}

	// Try as address
	if addr, err := netip.ParseAddr(entry); err == nil {
		delete(m.ips, addr)
	}
}

// Match checks if an IP address matches any entry.
func (m *IPMatcher) Match(ip netip.Addr) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check exact match
	if m.ips[ip] {
		return true
	}

	// Check CIDR ranges
	for _, prefix := range m.cidrs {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

// Entries returns a list of all IP/CIDR entries.
func (m *IPMatcher) Entries() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entries := make([]string, 0, len(m.ips)+len(m.cidrs))

	for ip := range m.ips {
		entries = append(entries, ip.String())
	}
	for _, prefix := range m.cidrs {
		entries = append(entries, prefix.String())
	}

	return entries
}

// ConfigError represents a configuration error.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return "config error: " + e.Field + ": " + e.Message
}
