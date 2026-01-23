// Package mullvad provides a VPN provider implementation for Mullvad VPN.
package mullvad

import (
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// MullvadRelay represents a relay server from the Mullvad API.
type MullvadRelay struct {
	Hostname    string `json:"hostname"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	CityCode    string `json:"city_code"`
	CityName    string `json:"city_name"`
	Active      bool   `json:"active"`
	Owned       bool   `json:"owned"`
	Provider    string `json:"provider"`
	IPv4AddrIn  string `json:"ipv4_addr_in"`
	IPv6AddrIn  string `json:"ipv6_addr_in,omitempty"`
	NetworkPort int    `json:"network_port_speed,omitempty"`
	// WireGuard specific fields
	Pubkey       string `json:"pubkey,omitempty"`
	MultihopPort int    `json:"multihop_port,omitempty"`
	// OpenVPN specific fields (if available)
	Daita bool `json:"daita,omitempty"`
	// Server type
	Type string `json:"type"` // "wireguard", "openvpn", "bridge"
}

// WireGuardKeyResponse represents the response from WireGuard key registration.
type WireGuardKeyResponse struct {
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address,omitempty"`
}

// AccountInfo represents Mullvad account information.
type AccountInfo struct {
	Account      string `json:"account"`
	ExpiryUnix   int64  `json:"expiry_unix"`
	PrettyExpiry string `json:"pretty_expiry"`
}

// mullvadRelayToServer converts a Mullvad relay to a vpnprovider.Server.
func mullvadRelayToServer(relay MullvadRelay) vpnprovider.Server {
	server := vpnprovider.Server{
		ID:          relay.Hostname,
		Name:        relay.Hostname,
		Hostname:    relay.Hostname + ".relays.mullvad.net",
		Country:     relay.CountryName,
		CountryCode: strings.ToUpper(relay.CountryCode),
		City:        relay.CityName,
		Load:        0, // Mullvad doesn't provide load info
		IPs:         []string{relay.IPv4AddrIn},
		Features:    []string{},
	}

	// Add IPv6 if available
	if relay.IPv6AddrIn != "" {
		server.IPs = append(server.IPs, relay.IPv6AddrIn)
	}

	// Add features based on relay properties
	if relay.Owned {
		server.Features = append(server.Features, "owned")
	}
	if relay.Daita {
		server.Features = append(server.Features, "daita")
	}
	if relay.MultihopPort > 0 {
		server.Features = append(server.Features, "multihop")
	}

	// Set protocol-specific info based on relay type
	switch relay.Type {
	case "wireguard":
		if relay.Pubkey != "" {
			endpoint := relay.IPv4AddrIn + ":51820"
			server.WireGuard = &vpnprovider.WireGuardServer{
				PublicKey: relay.Pubkey,
				Endpoint:  endpoint,
			}
		}
	case "openvpn":
		server.OpenVPN = &vpnprovider.OpenVPNServer{
			Hostname: relay.Hostname + ".relays.mullvad.net",
			TCPPort:  443,
			UDPPort:  1194,
		}
	case "bridge":
		// Bridge servers are typically OpenVPN
		server.OpenVPN = &vpnprovider.OpenVPNServer{
			Hostname: relay.Hostname + ".relays.mullvad.net",
			TCPPort:  443,
			UDPPort:  1194,
		}
		server.Features = append(server.Features, "bridge")
	}

	return server
}

// convertRelaysToServers converts a slice of Mullvad relays to vpnprovider.Server slice.
func convertRelaysToServers(relays []MullvadRelay) []vpnprovider.Server {
	servers := make([]vpnprovider.Server, 0, len(relays))

	for _, relay := range relays {
		// Only include active relays
		if !relay.Active {
			continue
		}

		server := mullvadRelayToServer(relay)
		servers = append(servers, server)
	}

	return servers
}

// extractCountries extracts unique countries from a list of servers.
func extractCountries(servers []vpnprovider.Server) []vpnprovider.Country {
	seen := make(map[string]bool)
	var countries []vpnprovider.Country
	id := 1

	for _, server := range servers {
		if !seen[server.CountryCode] {
			seen[server.CountryCode] = true
			countries = append(countries, vpnprovider.Country{
				ID:   id,
				Code: server.CountryCode,
				Name: server.Country,
			})
			id++
		}
	}

	return countries
}

// extractCities extracts unique cities from a list of servers.
func extractCities(servers []vpnprovider.Server) []vpnprovider.City {
	seen := make(map[string]bool)
	var cities []vpnprovider.City
	id := 1

	for _, server := range servers {
		key := server.CountryCode + ":" + server.City
		if !seen[key] && server.City != "" {
			seen[key] = true
			cities = append(cities, vpnprovider.City{
				ID:      id,
				Name:    server.City,
				Country: server.CountryCode,
			})
			id++
		}
	}

	return cities
}
