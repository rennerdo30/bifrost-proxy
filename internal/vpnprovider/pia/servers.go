// Package pia provides a client for the Private Internet Access VPN provider API.
package pia

import (
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// PIA API server list response structures.

// ServerListResponse represents the full PIA server list API response.
type ServerListResponse struct {
	Groups  map[string][]GroupServer `json:"groups"`
	Regions []Region                 `json:"regions"`
}

// GroupServer represents a server within a group (unused in current implementation).
type GroupServer struct {
	Name string `json:"name"`
}

// Region represents a PIA region with its servers.
type Region struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Country     string            `json:"country"`
	AutoRegion  bool              `json:"auto_region"`
	DNS         string            `json:"dns"`
	PortForward bool              `json:"port_forward"`
	Geo         bool              `json:"geo"`
	Offline     bool              `json:"offline"`
	Servers     RegionServers     `json:"servers"`
}

// RegionServers contains different server types for a region.
type RegionServers struct {
	WireGuard []WGServer   `json:"wg"`
	OpenVPN   []OVPNServer `json:"ovpnudp"`
	OpenVPNTC []OVPNServer `json:"ovpntcp"`
	Meta      []MetaServer `json:"meta"`
}

// WGServer represents a WireGuard server.
type WGServer struct {
	IP  string `json:"ip"`
	CN  string `json:"cn"` // Common name (hostname)
}

// OVPNServer represents an OpenVPN server.
type OVPNServer struct {
	IP  string `json:"ip"`
	CN  string `json:"cn"`
}

// MetaServer represents a metadata server (used for API endpoints).
type MetaServer struct {
	IP  string `json:"ip"`
	CN  string `json:"cn"`
}

// ToVPNProviderServer converts a PIA region to the common vpnprovider.Server format.
func (r *Region) ToVPNProviderServer() vpnprovider.Server {
	server := vpnprovider.Server{
		ID:          r.ID,
		Name:        r.Name,
		Country:     r.Country,
		CountryCode: extractCountryCode(r.Country),
		City:        extractCity(r.Name),
		Load:        0, // PIA doesn't provide load information
		Features:    buildFeatures(r),
		IPs:         collectIPs(r),
	}

	// Add WireGuard info if available
	if len(r.Servers.WireGuard) > 0 {
		wg := r.Servers.WireGuard[0]
		server.WireGuard = &vpnprovider.WireGuardServer{
			// PublicKey will be obtained during key registration
			Endpoint: wg.IP + ":" + DefaultWireGuardPort,
		}
	}

	// Add OpenVPN info if available
	if len(r.Servers.OpenVPN) > 0 || len(r.Servers.OpenVPNTC) > 0 {
		var udpPort, tcpPort int
		var hostname string

		if len(r.Servers.OpenVPN) > 0 {
			udpPort = DefaultOpenVPNUDPPort
			hostname = r.Servers.OpenVPN[0].CN
		}
		if len(r.Servers.OpenVPNTC) > 0 {
			tcpPort = DefaultOpenVPNTCPPort
			if hostname == "" {
				hostname = r.Servers.OpenVPNTC[0].CN
			}
		}

		server.OpenVPN = &vpnprovider.OpenVPNServer{
			Hostname: hostname,
			TCPPort:  tcpPort,
			UDPPort:  udpPort,
		}
	}

	return server
}

// extractCountryCode attempts to extract ISO country code from country name.
// PIA returns full country names, so we need to map them.
func extractCountryCode(country string) string {
	// Common country name to code mappings
	countryMap := map[string]string{
		"us":                   "US",
		"united states":        "US",
		"uk":                   "GB",
		"united kingdom":       "GB",
		"germany":              "DE",
		"france":               "FR",
		"netherlands":          "NL",
		"canada":               "CA",
		"australia":            "AU",
		"japan":                "JP",
		"singapore":            "SG",
		"sweden":               "SE",
		"switzerland":          "CH",
		"italy":                "IT",
		"spain":                "ES",
		"brazil":               "BR",
		"mexico":               "MX",
		"india":                "IN",
		"hong kong":            "HK",
		"south korea":          "KR",
		"ireland":              "IE",
		"austria":              "AT",
		"belgium":              "BE",
		"denmark":              "DK",
		"finland":              "FI",
		"norway":               "NO",
		"poland":               "PL",
		"czech republic":       "CZ",
		"romania":              "RO",
		"israel":               "IL",
		"united arab emirates": "AE",
		"new zealand":          "NZ",
		"argentina":            "AR",
	}

	lower := strings.ToLower(country)
	if code, ok := countryMap[lower]; ok {
		return code
	}

	// If country is already a 2-letter code, return it uppercased
	if len(country) == 2 {
		return strings.ToUpper(country)
	}

	return country
}

// extractCity attempts to extract city name from the region name.
// PIA names are like "US California", "UK London", etc.
func extractCity(name string) string {
	parts := strings.SplitN(name, " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return name
}

// buildFeatures returns a list of features for the region.
func buildFeatures(r *Region) []string {
	var features []string

	if r.PortForward {
		features = append(features, "port_forwarding")
	}

	if len(r.Servers.WireGuard) > 0 {
		features = append(features, "wireguard")
	}

	if len(r.Servers.OpenVPN) > 0 || len(r.Servers.OpenVPNTC) > 0 {
		features = append(features, "openvpn")
	}

	if r.Geo {
		features = append(features, "geo")
	}

	return features
}

// collectIPs gathers all server IPs for the region.
func collectIPs(r *Region) []string {
	ipSet := make(map[string]struct{})

	for _, s := range r.Servers.WireGuard {
		ipSet[s.IP] = struct{}{}
	}
	for _, s := range r.Servers.OpenVPN {
		ipSet[s.IP] = struct{}{}
	}
	for _, s := range r.Servers.OpenVPNTC {
		ipSet[s.IP] = struct{}{}
	}
	for _, s := range r.Servers.Meta {
		ipSet[s.IP] = struct{}{}
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	return ips
}

// GetMetaEndpoint returns the first meta server endpoint for API calls.
func (r *Region) GetMetaEndpoint() string {
	if len(r.Servers.Meta) > 0 {
		return r.Servers.Meta[0].IP
	}
	// Fallback to WireGuard server if no meta server
	if len(r.Servers.WireGuard) > 0 {
		return r.Servers.WireGuard[0].IP
	}
	return ""
}

// GetWireGuardEndpoint returns the first WireGuard server endpoint.
func (r *Region) GetWireGuardEndpoint() string {
	if len(r.Servers.WireGuard) > 0 {
		return r.Servers.WireGuard[0].IP
	}
	return ""
}
