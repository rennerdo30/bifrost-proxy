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
