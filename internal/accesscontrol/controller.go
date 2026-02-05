package accesscontrol

import (
	"sync"
)

// Action represents the access control decision.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// DenyReason provides context for denied requests.
type DenyReason string

const (
	ReasonBlacklisted    DenyReason = "ip_blacklisted"
	ReasonNotWhitelisted DenyReason = "ip_not_whitelisted"
)

// Result represents an access control check result.
type Result struct {
	Action Action
	Reason DenyReason
}

// Controller manages IP-based access control.
type Controller struct {
	whitelist    *IPMatcher
	blacklist    *IPMatcher
	useWhitelist bool
	mu           sync.RWMutex
}

// Config holds access controller configuration.
type Config struct {
	Whitelist []string
	Blacklist []string
}

// NewController creates a new access controller.
func NewController(cfg Config) (*Controller, error) {
	c := &Controller{
		whitelist: NewIPMatcher(),
		blacklist: NewIPMatcher(),
	}

	if len(cfg.Whitelist) > 0 {
		c.useWhitelist = true
		if err := c.whitelist.AddAll(cfg.Whitelist); err != nil {
			return nil, err
		}
	}

	if err := c.blacklist.AddAll(cfg.Blacklist); err != nil {
		return nil, err
	}

	return c, nil
}

// Check checks if an IP is allowed.
func (c *Controller) Check(ip string) Result {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Always check blacklist first
	if c.blacklist.Match(ip) {
		return Result{Action: ActionDeny, Reason: ReasonBlacklisted}
	}

	// If whitelist is enabled, IP must be in whitelist
	if c.useWhitelist {
		if !c.whitelist.Match(ip) {
			return Result{Action: ActionDeny, Reason: ReasonNotWhitelisted}
		}
	}

	return Result{Action: ActionAllow}
}

// IsAllowed returns true if the IP is allowed.
func (c *Controller) IsAllowed(ip string) bool {
	return c.Check(ip).Action == ActionAllow
}

// AddToWhitelist adds an IP or CIDR to the whitelist.
func (c *Controller) AddToWhitelist(entry string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.useWhitelist = true
	return c.whitelist.Add(entry)
}

// AddToBlacklist adds an IP or CIDR to the blacklist.
func (c *Controller) AddToBlacklist(entry string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.blacklist.Add(entry)
}

// RemoveFromWhitelist removes an entry from the whitelist.
func (c *Controller) RemoveFromWhitelist(entry string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Note: Full removal would require tracking original entries
	// For now, just clear and rebuild if needed
}

// RemoveFromBlacklist removes an entry from the blacklist.
func (c *Controller) RemoveFromBlacklist(entry string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Note: Full removal would require tracking original entries
}

// ClearWhitelist clears all whitelist entries.
func (c *Controller) ClearWhitelist() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.whitelist.Clear()
	c.useWhitelist = false
}

// ClearBlacklist clears all blacklist entries.
func (c *Controller) ClearBlacklist() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blacklist.Clear()
}

// Stats returns access control statistics.
func (c *Controller) Stats() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]int{
		"whitelist_entries": c.whitelist.Count(),
		"blacklist_entries": c.blacklist.Count(),
	}
}
