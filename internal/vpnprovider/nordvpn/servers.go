// Package nordvpn implements the NordVPN provider for Bifrost Proxy.
package nordvpn

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// Technology identifiers from NordVPN API.
const (
	TechOpenVPNUDP      = "openvpn_udp"
	TechOpenVPNTCP      = "openvpn_tcp"
	TechWireGuard       = "wireguard_udp"
	TechNordLynx        = "nordlynx" // NordVPN's WireGuard implementation
	TechIKEv2           = "ikev2"
	TechHTTPProxy       = "proxy"
	TechHTTPSProxy      = "proxy_ssl"
	TechSOCKS5Proxy     = "socks"
	TechHTTPCyberSec    = "proxy_cybersec"
	TechHTTPSSLCyberSec = "proxy_ssl_cybersec"
)

// Group identifiers from NordVPN API.
const (
	GroupStandardVPN  = "legacy_standard"
	GroupP2P          = "legacy_p2p"
	GroupDoubleVPN    = "legacy_double_vpn"
	GroupOnionOverVPN = "legacy_onion_over_vpn"
	GroupDedicatedIP  = "legacy_dedicated_ip"
	GroupObfuscated   = "legacy_obfuscated_servers"
	GroupAntiDDoS     = "legacy_anti_ddos"
)

// Default ports for NordVPN services.
const (
	DefaultOpenVPNUDPPort = 1194
	DefaultOpenVPNTCPPort = 443
	DefaultWireGuardPort  = 51820
)

// APIServer represents a server from the NordVPN API.
type APIServer struct {
	ID           int             `json:"id"`
	Name         string          `json:"name"`
	Station      string          `json:"station"` // IP address
	Hostname     string          `json:"hostname"`
	Load         int             `json:"load"`
	Status       string          `json:"status"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
	Locations    []APILocation   `json:"locations"`
	Services     []APIService    `json:"services"`
	Technologies []APITechnology `json:"technologies"`
	Groups       []APIGroup      `json:"groups"`
	Specs        []APISpec       `json:"specifications"`
	IPs          []APIIP         `json:"ips"`
}

// APILocation represents a server location.
type APILocation struct {
	ID        int        `json:"id"`
	Latitude  float64    `json:"latitude"`
	Longitude float64    `json:"longitude"`
	Country   APICountry `json:"country"`
}

// APICountry represents country information.
type APICountry struct {
	ID   int     `json:"id"`
	Name string  `json:"name"`
	Code string  `json:"code"`
	City APICity `json:"city"`
}

// APICity represents city information.
type APICity struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	DNSName   string  `json:"dns_name"`
	HubScore  int     `json:"hub_score"`
}

// APIService represents a service offered by the server.
type APIService struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
}

// APITechnology represents a technology/protocol supported by the server.
type APITechnology struct {
	ID         int               `json:"id"`
	Name       string            `json:"name"`
	Identifier string            `json:"identifier"`
	Pivot      APITechPivot      `json:"pivot"`
	Metadata   []APITechMetadata `json:"metadata"`
}

// APITechPivot contains the status of a technology on a server.
type APITechPivot struct {
	TechnologyID int    `json:"technology_id"`
	ServerID     int    `json:"server_id"`
	Status       string `json:"status"`
}

// APITechMetadata contains technology-specific metadata.
type APITechMetadata struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// APIGroup represents a server group/category.
type APIGroup struct {
	ID         int          `json:"id"`
	Title      string       `json:"title"`
	Identifier string       `json:"identifier"`
	Type       APIGroupType `json:"type"`
}

// APIGroupType represents the type of a group.
type APIGroupType struct {
	ID         int    `json:"id"`
	Title      string `json:"title"`
	Identifier string `json:"identifier"`
}

// APISpec represents a server specification.
type APISpec struct {
	ID         int          `json:"id"`
	Title      string       `json:"title"`
	Identifier string       `json:"identifier"`
	Values     []APISpecVal `json:"values"`
}

// APISpecVal represents a specification value.
type APISpecVal struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

// APIIP represents an IP address entry.
type APIIP struct {
	ID       int       `json:"id"`
	ServerID int       `json:"server_id"`
	IPID     int       `json:"ip_id"`
	Type     string    `json:"type"`
	Version  int       `json:"version"`
	IP       APIIPAddr `json:"ip"`
}

// APIIPAddr contains the actual IP address.
type APIIPAddr struct {
	ID      int    `json:"id"`
	IP      string `json:"ip"`
	Version int    `json:"version"`
}

// APICountryInfo represents a country from the countries endpoint.
type APICountryInfo struct {
	ID          int           `json:"id"`
	Name        string        `json:"name"`
	Code        string        `json:"code"`
	ServerCount int           `json:"serverCount"`
	Cities      []APICityInfo `json:"cities"`
}

// APICityInfo represents a city from the countries endpoint.
type APICityInfo struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	DNSName     string  `json:"dns_name"`
	HubScore    int     `json:"hub_score"`
	ServerCount int     `json:"serverCount"`
}

// RecommendationFilter represents filter parameters for server recommendations.
type RecommendationFilter struct {
	CountryID    int `json:"country_id,omitempty"`
	CityID       int `json:"city_id,omitempty"`
	GroupID      int `json:"group_id,omitempty"`
	TechnologyID int `json:"technology_id,omitempty"`
	Limit        int `json:"limit,omitempty"`
}

// ToServer converts an API server to the common Server format.
func (s *APIServer) ToServer() vpnprovider.Server {
	server := vpnprovider.Server{
		ID:       strconv.Itoa(s.ID),
		Name:     s.Name,
		Hostname: s.Hostname,
		Load:     s.Load,
	}

	// Extract location info
	if len(s.Locations) > 0 {
		loc := s.Locations[0]
		server.Country = loc.Country.Name
		server.CountryCode = loc.Country.Code
		server.City = loc.Country.City.Name
	}

	// Extract IPs
	for _, ip := range s.IPs {
		if ip.IP.Version == 4 {
			server.IPs = append(server.IPs, ip.IP.IP)
		}
	}

	// If no IPs from the IPs array, use the station IP
	if len(server.IPs) == 0 && s.Station != "" {
		server.IPs = []string{s.Station}
	}

	// Extract features from groups
	server.Features = s.extractFeatures()

	// Extract WireGuard info
	server.WireGuard = s.extractWireGuard()

	// Extract OpenVPN info
	server.OpenVPN = s.extractOpenVPN()

	return server
}

// extractFeatures converts NordVPN groups to feature flags.
func (s *APIServer) extractFeatures() []string {
	var features []string
	featureMap := map[string]string{
		GroupP2P:          "p2p",
		GroupDoubleVPN:    "double_vpn",
		GroupOnionOverVPN: "onion_over_vpn",
		GroupDedicatedIP:  "dedicated_ip",
		GroupObfuscated:   "obfuscated",
		GroupAntiDDoS:     "anti_ddos",
	}

	for _, group := range s.Groups {
		if feature, ok := featureMap[group.Identifier]; ok {
			features = append(features, feature)
		}
	}

	return features
}

// extractWireGuard extracts WireGuard configuration if available.
func (s *APIServer) extractWireGuard() *vpnprovider.WireGuardServer {
	for _, tech := range s.Technologies {
		if tech.Identifier == TechNordLynx || tech.Identifier == TechWireGuard {
			if tech.Pivot.Status != "online" {
				continue
			}

			wg := &vpnprovider.WireGuardServer{}

			// Extract public key from metadata
			for _, meta := range tech.Metadata {
				if meta.Name == "public_key" {
					wg.PublicKey = meta.Value
				}
			}

			// Build endpoint
			if wg.PublicKey != "" {
				wg.Endpoint = fmt.Sprintf("%s:%d", s.Hostname, DefaultWireGuardPort)
				return wg
			}
		}
	}
	return nil
}

// extractOpenVPN extracts OpenVPN configuration if available.
func (s *APIServer) extractOpenVPN() *vpnprovider.OpenVPNServer {
	hasUDP := false
	hasTCP := false

	for _, tech := range s.Technologies {
		if tech.Pivot.Status != "online" {
			continue
		}

		switch tech.Identifier {
		case TechOpenVPNUDP:
			hasUDP = true
		case TechOpenVPNTCP:
			hasTCP = true
		}
	}

	if !hasUDP && !hasTCP {
		return nil
	}

	ovpn := &vpnprovider.OpenVPNServer{
		Hostname: s.Hostname,
	}

	if hasUDP {
		ovpn.UDPPort = DefaultOpenVPNUDPPort
	}
	if hasTCP {
		ovpn.TCPPort = DefaultOpenVPNTCPPort
	}

	return ovpn
}

// HasTechnology checks if the server supports a specific technology.
func (s *APIServer) HasTechnology(identifier string) bool {
	for _, tech := range s.Technologies {
		if tech.Identifier == identifier && tech.Pivot.Status == "online" {
			return true
		}
	}
	return false
}

// HasGroup checks if the server belongs to a specific group.
func (s *APIServer) HasGroup(identifier string) bool {
	for _, group := range s.Groups {
		if group.Identifier == identifier {
			return true
		}
	}
	return false
}

// GetTechnologyMetadata retrieves metadata for a specific technology.
func (s *APIServer) GetTechnologyMetadata(techIdentifier, metaName string) (string, bool) {
	for _, tech := range s.Technologies {
		if tech.Identifier == techIdentifier {
			for _, meta := range tech.Metadata {
				if meta.Name == metaName {
					return meta.Value, true
				}
			}
		}
	}
	return "", false
}

// IsOnline returns true if the server status indicates it's available.
func (s *APIServer) IsOnline() bool {
	return strings.EqualFold(s.Status, "online")
}

// ToCountry converts an API country to the common Country format.
func (c *APICountryInfo) ToCountry() vpnprovider.Country {
	return vpnprovider.Country{
		ID:   c.ID,
		Code: c.Code,
		Name: c.Name,
	}
}
