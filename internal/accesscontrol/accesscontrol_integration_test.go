//go:build integration

package accesscontrol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestController_Integration(t *testing.T) {
	// Create controller with mixed whitelist and blacklist
	c, err := NewController(Config{
		Whitelist: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		Blacklist: []string{
			"10.0.0.1",           // Specific IP in whitelist range
			"192.168.1.0/24",     // Subnet in whitelist range
		},
	})
	require.NoError(t, err)

	tests := []struct {
		ip      string
		allowed bool
		reason  DenyReason
	}{
		// Allowed - in whitelist, not in blacklist
		{"10.0.0.2", true, ""},
		{"172.16.1.1", true, ""},
		{"192.168.2.1", true, ""},

		// Denied - specifically blacklisted
		{"10.0.0.1", false, ReasonBlacklisted},

		// Denied - in blacklisted subnet
		{"192.168.1.1", false, ReasonBlacklisted},
		{"192.168.1.254", false, ReasonBlacklisted},

		// Denied - not in whitelist
		{"8.8.8.8", false, ReasonNotWhitelisted},
		{"1.1.1.1", false, ReasonNotWhitelisted},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := c.Check(tt.ip)
			assert.Equal(t, tt.allowed, result.Action == ActionAllow, "IP: %s", tt.ip)
			if !tt.allowed {
				assert.Equal(t, tt.reason, result.Reason, "IP: %s", tt.ip)
			}
		})
	}
}
