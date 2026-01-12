package accesscontrol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPMatcher(t *testing.T) {
	m := NewIPMatcher()

	// Add individual IPs
	require.NoError(t, m.Add("192.168.1.1"))
	require.NoError(t, m.Add("10.0.0.1"))

	// Add CIDR ranges
	require.NoError(t, m.Add("172.16.0.0/16"))

	// Test matches
	assert.True(t, m.Match("192.168.1.1"))
	assert.True(t, m.Match("10.0.0.1"))
	assert.True(t, m.Match("172.16.1.1"))
	assert.True(t, m.Match("172.16.255.255"))

	// Test non-matches
	assert.False(t, m.Match("192.168.1.2"))
	assert.False(t, m.Match("8.8.8.8"))
	assert.False(t, m.Match("172.17.0.1"))
}

func TestIPMatcherIPv6(t *testing.T) {
	m := NewIPMatcher()

	require.NoError(t, m.Add("::1"))
	require.NoError(t, m.Add("2001:db8::/32"))

	assert.True(t, m.Match("::1"))
	assert.True(t, m.Match("2001:db8::1"))
	assert.True(t, m.Match("2001:db8:1234::5678"))

	assert.False(t, m.Match("2001:db9::1"))
	assert.False(t, m.Match("fe80::1"))
}

func TestController(t *testing.T) {
	tests := []struct {
		name      string
		whitelist []string
		blacklist []string
		ip        string
		allowed   bool
	}{
		{
			name:      "no lists - allow all",
			whitelist: nil,
			blacklist: nil,
			ip:        "192.168.1.1",
			allowed:   true,
		},
		{
			name:      "blacklisted IP",
			whitelist: nil,
			blacklist: []string{"192.168.1.1"},
			ip:        "192.168.1.1",
			allowed:   false,
		},
		{
			name:      "not blacklisted",
			whitelist: nil,
			blacklist: []string{"192.168.1.1"},
			ip:        "192.168.1.2",
			allowed:   true,
		},
		{
			name:      "whitelisted IP",
			whitelist: []string{"192.168.1.0/24"},
			blacklist: nil,
			ip:        "192.168.1.100",
			allowed:   true,
		},
		{
			name:      "not whitelisted",
			whitelist: []string{"192.168.1.0/24"},
			blacklist: nil,
			ip:        "10.0.0.1",
			allowed:   false,
		},
		{
			name:      "blacklist takes priority over whitelist",
			whitelist: []string{"192.168.0.0/16"},
			blacklist: []string{"192.168.1.1"},
			ip:        "192.168.1.1",
			allowed:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewController(Config{
				Whitelist: tt.whitelist,
				Blacklist: tt.blacklist,
			})
			require.NoError(t, err)

			result := c.Check(tt.ip)
			assert.Equal(t, tt.allowed, result.Action == ActionAllow)
		})
	}
}

func TestControllerDenyReasons(t *testing.T) {
	// Test blacklist reason
	c1, _ := NewController(Config{Blacklist: []string{"1.2.3.4"}})
	result := c1.Check("1.2.3.4")
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, ReasonBlacklisted, result.Reason)

	// Test whitelist reason
	c2, _ := NewController(Config{Whitelist: []string{"10.0.0.0/8"}})
	result = c2.Check("192.168.1.1")
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, ReasonNotWhitelisted, result.Reason)
}

func TestController_IsAllowed(t *testing.T) {
	c, err := NewController(Config{
		Blacklist: []string{"192.168.1.1"},
	})
	require.NoError(t, err)

	assert.False(t, c.IsAllowed("192.168.1.1"))
	assert.True(t, c.IsAllowed("192.168.1.2"))
}

func TestController_AddToWhitelist(t *testing.T) {
	c, err := NewController(Config{})
	require.NoError(t, err)

	// Initially all IPs allowed
	assert.True(t, c.IsAllowed("10.0.0.1"))

	// Add to whitelist - now only whitelisted IPs allowed
	err = c.AddToWhitelist("192.168.0.0/16")
	require.NoError(t, err)

	assert.True(t, c.IsAllowed("192.168.1.1"))
	assert.False(t, c.IsAllowed("10.0.0.1"))
}

func TestController_AddToBlacklist(t *testing.T) {
	c, err := NewController(Config{})
	require.NoError(t, err)

	// Initially all IPs allowed
	assert.True(t, c.IsAllowed("10.0.0.1"))

	// Add to blacklist
	err = c.AddToBlacklist("10.0.0.1")
	require.NoError(t, err)

	assert.False(t, c.IsAllowed("10.0.0.1"))
	assert.True(t, c.IsAllowed("10.0.0.2"))
}

func TestController_RemoveFromWhitelist(t *testing.T) {
	c, err := NewController(Config{
		Whitelist: []string{"192.168.0.0/16"},
	})
	require.NoError(t, err)

	// Call RemoveFromWhitelist (currently no-op but should not panic)
	c.RemoveFromWhitelist("192.168.0.0/16")
	// Should not panic
}

func TestController_RemoveFromBlacklist(t *testing.T) {
	c, err := NewController(Config{
		Blacklist: []string{"10.0.0.1"},
	})
	require.NoError(t, err)

	// Call RemoveFromBlacklist (currently no-op but should not panic)
	c.RemoveFromBlacklist("10.0.0.1")
	// Should not panic
}

func TestController_ClearWhitelist(t *testing.T) {
	c, err := NewController(Config{
		Whitelist: []string{"192.168.0.0/16"},
	})
	require.NoError(t, err)

	// Initially only whitelisted IPs allowed
	assert.False(t, c.IsAllowed("10.0.0.1"))

	// Clear whitelist - now all IPs allowed
	c.ClearWhitelist()
	assert.True(t, c.IsAllowed("10.0.0.1"))
}

func TestController_ClearBlacklist(t *testing.T) {
	c, err := NewController(Config{
		Blacklist: []string{"10.0.0.1"},
	})
	require.NoError(t, err)

	// Initially blacklisted IP denied
	assert.False(t, c.IsAllowed("10.0.0.1"))

	// Clear blacklist - now allowed
	c.ClearBlacklist()
	assert.True(t, c.IsAllowed("10.0.0.1"))
}

func TestController_Stats(t *testing.T) {
	c, err := NewController(Config{
		Whitelist: []string{"192.168.0.0/16", "10.0.0.0/8"},
		Blacklist: []string{"1.2.3.4"},
	})
	require.NoError(t, err)

	stats := c.Stats()
	assert.Equal(t, 2, stats["whitelist_entries"])
	assert.Equal(t, 1, stats["blacklist_entries"])
}

func TestIPMatcher_Clear(t *testing.T) {
	m := NewIPMatcher()

	require.NoError(t, m.Add("192.168.1.1"))
	require.NoError(t, m.Add("10.0.0.0/8"))
	assert.True(t, m.Match("192.168.1.1"))

	m.Clear()
	assert.False(t, m.Match("192.168.1.1"))
}

func TestIPMatcher_Count(t *testing.T) {
	m := NewIPMatcher()

	assert.Equal(t, 0, m.Count())

	require.NoError(t, m.Add("192.168.1.1"))
	assert.Equal(t, 1, m.Count())

	require.NoError(t, m.Add("10.0.0.0/8"))
	assert.Equal(t, 2, m.Count())
}

func TestIPMatcher_AddInvalid(t *testing.T) {
	m := NewIPMatcher()

	err := m.Add("invalid-ip")
	assert.Error(t, err)
}

func TestIPMatcher_AddAll_Invalid(t *testing.T) {
	m := NewIPMatcher()

	err := m.AddAll([]string{"192.168.1.1", "invalid-ip"})
	assert.Error(t, err)
}

func TestIPMatcher_MatchInvalidIP(t *testing.T) {
	m := NewIPMatcher()
	require.NoError(t, m.Add("192.168.1.1"))

	// Invalid IP should return false
	assert.False(t, m.Match("invalid-ip"))
}

func TestController_NewWithInvalidWhitelist(t *testing.T) {
	_, err := NewController(Config{
		Whitelist: []string{"invalid-entry"},
	})
	assert.Error(t, err)
}

func TestController_NewWithInvalidBlacklist(t *testing.T) {
	_, err := NewController(Config{
		Blacklist: []string{"invalid-entry"},
	})
	assert.Error(t, err)
}

// Test constants
func TestActionConstants(t *testing.T) {
	assert.Equal(t, Action("allow"), ActionAllow)
	assert.Equal(t, Action("deny"), ActionDeny)
}

func TestDenyReasonConstants(t *testing.T) {
	assert.Equal(t, DenyReason("ip_blacklisted"), ReasonBlacklisted)
	assert.Equal(t, DenyReason("ip_not_whitelisted"), ReasonNotWhitelisted)
}

func TestResult_Struct(t *testing.T) {
	r := Result{
		Action: ActionAllow,
		Reason: "",
	}
	assert.Equal(t, ActionAllow, r.Action)
	assert.Equal(t, DenyReason(""), r.Reason)
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		Whitelist: []string{"192.168.0.0/16"},
		Blacklist: []string{"10.0.0.1"},
	}
	assert.Len(t, cfg.Whitelist, 1)
	assert.Len(t, cfg.Blacklist, 1)
}
