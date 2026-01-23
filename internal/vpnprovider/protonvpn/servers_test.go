package protonvpn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogicalServerGetFeatures(t *testing.T) {
	tests := []struct {
		name     string
		features int
		expected []string
	}{
		{
			name:     "no features",
			features: 0,
			expected: nil,
		},
		{
			name:     "p2p only",
			features: FeatureP2P,
			expected: []string{"p2p"},
		},
		{
			name:     "secure core and streaming",
			features: FeatureSecureCore | FeatureStreaming,
			expected: []string{"secure_core", "streaming"},
		},
		{
			name:     "all features",
			features: FeatureSecureCore | FeatureTor | FeatureP2P | FeatureXOR | FeatureIPv6 | FeatureStreaming,
			expected: []string{"secure_core", "tor", "p2p", "xor", "ipv6", "streaming"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := &LogicalServer{Features: tt.features}
			features := ls.GetFeatures()

			if tt.expected == nil {
				assert.Empty(t, features)
			} else {
				for _, exp := range tt.expected {
					assert.Contains(t, features, exp)
				}
				assert.Len(t, features, len(tt.expected))
			}
		})
	}
}

func TestLogicalServerGetTierName(t *testing.T) {
	tests := []struct {
		tier     int
		expected string
	}{
		{TierFree, "free"},
		{TierBasic, "basic"},
		{TierPlus, "plus"},
		{99, "tier_99"},
	}

	for _, tt := range tests {
		ls := &LogicalServer{Tier: tt.tier}
		assert.Equal(t, tt.expected, ls.GetTierName())
	}
}

func TestLogicalServerIsOnline(t *testing.T) {
	online := &LogicalServer{Status: 1}
	offline := &LogicalServer{Status: 0}

	assert.True(t, online.IsOnline())
	assert.False(t, offline.IsOnline())
}

func TestLogicalServerHasFeature(t *testing.T) {
	ls := &LogicalServer{Features: FeatureP2P | FeatureStreaming}

	assert.True(t, ls.HasFeature(FeatureP2P))
	assert.True(t, ls.HasFeature(FeatureStreaming))
	assert.False(t, ls.HasFeature(FeatureSecureCore))
	assert.False(t, ls.HasFeature(FeatureTor))
}

func TestLogicalServerFeatureHelpers(t *testing.T) {
	secureCore := &LogicalServer{Features: FeatureSecureCore}
	p2p := &LogicalServer{Features: FeatureP2P}
	streaming := &LogicalServer{Features: FeatureStreaming}
	none := &LogicalServer{Features: 0}

	assert.True(t, secureCore.IsSecureCore())
	assert.False(t, p2p.IsSecureCore())

	assert.True(t, p2p.IsP2P())
	assert.False(t, secureCore.IsP2P())

	assert.True(t, streaming.IsStreaming())
	assert.False(t, none.IsStreaming())
}

func TestLogicalServerGetCity(t *testing.T) {
	city := "New York"
	withCity := &LogicalServer{City: &city}
	withoutCity := &LogicalServer{}

	assert.Equal(t, "New York", withCity.GetCity())
	assert.Equal(t, "", withoutCity.GetCity())
}

func TestLogicalServerGetRegion(t *testing.T) {
	region := "Northeast"
	withRegion := &LogicalServer{Region: &region}
	withoutRegion := &LogicalServer{}

	assert.Equal(t, "Northeast", withRegion.GetRegion())
	assert.Equal(t, "", withoutRegion.GetRegion())
}

func TestLogicalServerGetFirstOnlineServer(t *testing.T) {
	tests := []struct {
		name     string
		servers  []Server
		expected *Server
	}{
		{
			name:     "no servers",
			servers:  nil,
			expected: nil,
		},
		{
			name: "all offline",
			servers: []Server{
				{ID: "s1", Status: 0},
				{ID: "s2", Status: 0},
			},
			expected: nil,
		},
		{
			name: "first online",
			servers: []Server{
				{ID: "s1", Status: 1},
				{ID: "s2", Status: 1},
			},
			expected: &Server{ID: "s1", Status: 1},
		},
		{
			name: "second online",
			servers: []Server{
				{ID: "s1", Status: 0},
				{ID: "s2", Status: 1},
			},
			expected: &Server{ID: "s2", Status: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := &LogicalServer{Servers: tt.servers}
			result := ls.GetFirstOnlineServer()

			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.expected.ID, result.ID)
			}
		})
	}
}

func TestLogicalServerGetEntryIP(t *testing.T) {
	tests := []struct {
		name     string
		servers  []Server
		expected string
	}{
		{
			name:     "no servers",
			servers:  nil,
			expected: "",
		},
		{
			name: "online server",
			servers: []Server{
				{ID: "s1", EntryIP: "1.1.1.1", Status: 1},
			},
			expected: "1.1.1.1",
		},
		{
			name: "fallback to offline",
			servers: []Server{
				{ID: "s1", EntryIP: "2.2.2.2", Status: 0},
			},
			expected: "2.2.2.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := &LogicalServer{Servers: tt.servers}
			assert.Equal(t, tt.expected, ls.GetEntryIP())
		})
	}
}

func TestLogicalServerGetWireGuardPublicKey(t *testing.T) {
	tests := []struct {
		name     string
		servers  []Server
		expected string
	}{
		{
			name:     "no servers",
			servers:  nil,
			expected: "",
		},
		{
			name: "no wireguard key",
			servers: []Server{
				{ID: "s1", X25519PublicKey: ""},
			},
			expected: "",
		},
		{
			name: "with wireguard key",
			servers: []Server{
				{ID: "s1", X25519PublicKey: "pubkey123"},
			},
			expected: "pubkey123",
		},
		{
			name: "first server with key",
			servers: []Server{
				{ID: "s1", X25519PublicKey: ""},
				{ID: "s2", X25519PublicKey: "pubkey456"},
			},
			expected: "pubkey456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := &LogicalServer{Servers: tt.servers}
			assert.Equal(t, tt.expected, ls.GetWireGuardPublicKey())
		})
	}
}

func TestParseServerName(t *testing.T) {
	tests := []struct {
		name          string
		serverName    string
		expectCountry string
		expectNumber  int
		expectError   bool
	}{
		{
			name:          "valid US server",
			serverName:    "US#42",
			expectCountry: "US",
			expectNumber:  42,
			expectError:   false,
		},
		{
			name:          "valid DE server",
			serverName:    "de#1",
			expectCountry: "DE",
			expectNumber:  1,
			expectError:   false,
		},
		{
			name:        "missing hash",
			serverName:  "US42",
			expectError: true,
		},
		{
			name:        "invalid number",
			serverName:  "US#abc",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			country, number, err := ParseServerName(tt.serverName)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectCountry, country)
				assert.Equal(t, tt.expectNumber, number)
			}
		})
	}
}

func TestFormatServerName(t *testing.T) {
	assert.Equal(t, "US#42", FormatServerName("US", 42))
	assert.Equal(t, "DE#1", FormatServerName("de", 1))
	assert.Equal(t, "FR#100", FormatServerName("fr", 100))
}

func TestGetCountryName(t *testing.T) {
	assert.Equal(t, "United States", GetCountryName("US"))
	assert.Equal(t, "Germany", GetCountryName("DE"))
	assert.Equal(t, "United Kingdom", GetCountryName("gb")) // lowercase
	assert.Equal(t, "XX", GetCountryName("XX"))             // unknown
}
