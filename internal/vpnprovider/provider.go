// Package vpnprovider provides interfaces and utilities for VPN provider integrations.
package vpnprovider

import (
	"context"
	"time"
)

// Provider represents a VPN provider API client.
type Provider interface {
	// Name returns the provider name (e.g., "nordvpn", "mullvad", "pia").
	Name() string

	// FetchServers retrieves the server list from the provider API.
	FetchServers(ctx context.Context) ([]Server, error)

	// SelectServer selects the best server based on criteria.
	SelectServer(ctx context.Context, criteria ServerCriteria) (*Server, error)

	// GenerateWireGuardConfig generates WireGuard configuration for a server.
	GenerateWireGuardConfig(ctx context.Context, server *Server, creds Credentials) (*WireGuardConfig, error)

	// GenerateOpenVPNConfig generates OpenVPN configuration for a server.
	GenerateOpenVPNConfig(ctx context.Context, server *Server, creds Credentials) (*OpenVPNConfig, error)

	// SupportsWireGuard returns true if provider supports WireGuard.
	SupportsWireGuard() bool

	// SupportsOpenVPN returns true if provider supports OpenVPN.
	SupportsOpenVPN() bool
}

// Server represents a VPN server from a provider.
type Server struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Hostname  string            `json:"hostname"`
	Country   string            `json:"country"`
	CountryCode string          `json:"country_code"`
	City      string            `json:"city,omitempty"`
	Load      int               `json:"load"`               // 0-100 percentage
	Latency   time.Duration     `json:"latency,omitempty"`  // Measured latency
	Features  []string          `json:"features,omitempty"` // e.g., "p2p", "streaming", "double_vpn"
	IPs       []string          `json:"ips"`
	WireGuard *WireGuardServer  `json:"wireguard,omitempty"`
	OpenVPN   *OpenVPNServer    `json:"openvpn,omitempty"`
}

// WireGuardServer contains WireGuard-specific server info.
type WireGuardServer struct {
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"` // host:port
}

// OpenVPNServer contains OpenVPN-specific server info.
type OpenVPNServer struct {
	Hostname string `json:"hostname"`
	TCPPort  int    `json:"tcp_port"`
	UDPPort  int    `json:"udp_port"`
}

// ServerCriteria specifies server selection criteria.
type ServerCriteria struct {
	Country     string   `json:"country,omitempty"`      // ISO country code (e.g., "US", "DE")
	City        string   `json:"city,omitempty"`         // City name
	Protocol    string   `json:"protocol,omitempty"`     // "wireguard" or "openvpn"
	Features    []string `json:"features,omitempty"`     // Required features (e.g., "p2p")
	MaxLoad     int      `json:"max_load,omitempty"`     // Max acceptable load percentage (0-100)
	ServerID    string   `json:"server_id,omitempty"`    // Specific server ID
	Fastest     bool     `json:"fastest,omitempty"`      // Select server with lowest load
}

// Credentials holds provider-specific credentials.
type Credentials struct {
	// Username for providers that use username/password (PIA)
	Username string `json:"username,omitempty"`
	// Password for providers that use username/password (PIA)
	Password string `json:"password,omitempty"`
	// AccountID for providers that use account numbers (Mullvad)
	AccountID string `json:"account_id,omitempty"`
	// AccessToken for providers that use tokens
	AccessToken string `json:"access_token,omitempty"`
}

// WireGuardConfig is the generated WireGuard configuration.
type WireGuardConfig struct {
	PrivateKey string        `json:"private_key"`
	PublicKey  string        `json:"public_key"` // Client's public key
	Address    string        `json:"address"`    // Client IP (e.g., "10.0.0.2/32")
	DNS        []string      `json:"dns"`
	Peer       WireGuardPeer `json:"peer"`
}

// WireGuardPeer represents a WireGuard peer configuration.
type WireGuardPeer struct {
	PublicKey           string   `json:"public_key"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
}

// OpenVPNConfig is the generated OpenVPN configuration.
type OpenVPNConfig struct {
	ConfigContent string `json:"config_content"` // Full .ovpn file content
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
}

// Country represents a country with available VPN servers.
type Country struct {
	ID   int    `json:"id"`
	Code string `json:"code"` // ISO 3166-1 alpha-2
	Name string `json:"name"`
}

// City represents a city with available VPN servers.
type City struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Country string `json:"country"` // Country code
}
