package mesh

import "github.com/rennerdo30/bifrost-proxy/internal/jsoncompat"

// These structs shipped without json tags for several releases, so JSON
// exports from that era carry Go field names. encoding/json's case-insensitive
// matching covers the single-word fields, but multi-word names (NetworkID,
// HeartbeatInterval, KeepAliveInterval, ...) never match their snake_case tags
// and were silently dropped on import. Decoding accepts both spellings;
// output is always canonical snake_case.

// UnmarshalJSON accepts both canonical and legacy pre-tag key names.
func (c *Config) UnmarshalJSON(b []byte) error {
	type alias Config
	return jsoncompat.Unmarshal(b, (*alias)(c))
}

// UnmarshalJSON accepts both canonical and legacy pre-tag key names.
func (c *DeviceConfig) UnmarshalJSON(b []byte) error {
	type alias DeviceConfig
	return jsoncompat.Unmarshal(b, (*alias)(c))
}

// UnmarshalJSON accepts both canonical and legacy pre-tag key names.
func (c *DiscoveryConfig) UnmarshalJSON(b []byte) error {
	type alias DiscoveryConfig
	return jsoncompat.Unmarshal(b, (*alias)(c))
}

// UnmarshalJSON accepts both canonical and legacy pre-tag key names.
func (c *ConnectionConfig) UnmarshalJSON(b []byte) error {
	type alias ConnectionConfig
	return jsoncompat.Unmarshal(b, (*alias)(c))
}

// UnmarshalJSON accepts both canonical and legacy pre-tag key names.
func (c *SecurityConfig) UnmarshalJSON(b []byte) error {
	type alias SecurityConfig
	return jsoncompat.Unmarshal(b, (*alias)(c))
}
