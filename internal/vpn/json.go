package vpn

import "github.com/rennerdo30/bifrost-proxy/internal/jsoncompat"

// These structs shipped without json tags for several releases, so JSON
// exports from that era carry Go field names. encoding/json's case-insensitive
// matching covers the single-word fields, but multi-word names (SplitTunnel,
// CacheTTL, InterceptMode, AlwaysBypass) never match their snake_case tags and
// were silently dropped on import — which could invert split-tunnel behavior.
// Decoding accepts both spellings; output is always canonical snake_case.

// UnmarshalJSON accepts both canonical and legacy pre-tag key names.
func (c *Config) UnmarshalJSON(b []byte) error {
	type alias Config
	return jsoncompat.Unmarshal(b, (*alias)(c))
}

// UnmarshalJSON accepts both canonical and legacy pre-tag key names.
func (c *DNSConfig) UnmarshalJSON(b []byte) error {
	type alias DNSConfig
	return jsoncompat.Unmarshal(b, (*alias)(c))
}

// UnmarshalJSON accepts both canonical and legacy pre-tag key names.
func (c *SplitTunnelConfig) UnmarshalJSON(b []byte) error {
	type alias SplitTunnelConfig
	return jsoncompat.Unmarshal(b, (*alias)(c))
}
