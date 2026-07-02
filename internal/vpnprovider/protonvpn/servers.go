// Package protonvpn provides a VPN provider implementation for ProtonVPN.
package protonvpn

import (
	"fmt"
	"strconv"
	"strings"
)

// LogicalServerResponse represents the ProtonVPN API response for /vpn/logicals.
type LogicalServerResponse struct {
	Code           int             `json:"Code"`
	LogicalServers []LogicalServer `json:"LogicalServers"`
}

// LogicalServer represents a ProtonVPN logical server.
// A logical server is a collection of physical servers that share the same
// hostname and geographic location.
type LogicalServer struct {
	ID           string   `json:"ID"`
	Name         string   `json:"Name"`
	Domain       string   `json:"Domain"`
	EntryCountry string   `json:"EntryCountry"`
	ExitCountry  string   `json:"ExitCountry"`
	Tier         int      `json:"Tier"`     // 0=free, 1=basic, 2=plus
	Features     int      `json:"Features"` // Bitmask of features
	Region       *string  `json:"Region"`   // May be nil
	City         *string  `json:"City"`     // May be nil
	Score        float64  `json:"Score"`    // Lower is better
	HostCountry  string   `json:"HostCountry"`
	Load         int      `json:"Load"`    // 0-100
	Status       int      `json:"Status"`  // 1 = online
	Servers      []Server `json:"Servers"` // Physical servers
	Location     Location `json:"Location"`
}

// Server represents a physical ProtonVPN server.
type Server struct {
	ID                 string  `json:"ID"`
	EntryIP            string  `json:"EntryIP"`
	ExitIP             string  `json:"ExitIP"`
	Domain             string  `json:"Domain"`
	Status             int     `json:"Status"`
	Label              string  `json:"Label"`
	X25519PublicKey    string  `json:"X25519PublicKey,omitempty"` // WireGuard public key
	Generation         int     `json:"Generation"`
	ServicesDownReason *string `json:"ServicesDownReason"`
}

// Location represents the geographic location of a server.
type Location struct {
	Lat  float64 `json:"Lat"`
	Long float64 `json:"Long"`
}

// ProtonVPN Feature flags (bitmask).
const (
	FeatureSecureCore = 1 << 0 // Secure Core server (multi-hop)
	FeatureTor        = 1 << 1 // TOR exit server
	FeatureP2P        = 1 << 2 // P2P/file-sharing allowed
	FeatureXOR        = 1 << 3 // XOR obfuscation
	FeatureIPv6       = 1 << 4 // IPv6 support
	FeatureStreaming  = 1 << 5 // Streaming optimized
)

// FeatureMap maps feature flags to feature names.
var FeatureMap = map[int]string{
	FeatureSecureCore: "secure_core",
	FeatureTor:        "tor",
	FeatureP2P:        "p2p",
	FeatureXOR:        "xor",
	FeatureIPv6:       "ipv6",
	FeatureStreaming:  "streaming",
}

// Tier constants.
const (
	TierFree  = 0
	TierBasic = 1
	TierPlus  = 2
)

// TierNames maps tier numbers to names.
var TierNames = map[int]string{
	TierFree:  "free",
	TierBasic: "basic",
	TierPlus:  "plus",
}

// GetFeatures converts the feature bitmask to a slice of feature names.
func (ls *LogicalServer) GetFeatures() []string {
	var features []string
	for flag, name := range FeatureMap {
		if ls.Features&flag != 0 {
			features = append(features, name)
		}
	}
	return features
}

// GetTierName returns the human-readable tier name.
func (ls *LogicalServer) GetTierName() string {
	if name, ok := TierNames[ls.Tier]; ok {
		return name
	}
	return fmt.Sprintf("tier_%d", ls.Tier)
}

// IsOnline returns true if the server is online.
func (ls *LogicalServer) IsOnline() bool {
	return ls.Status == 1
}

// HasFeature checks if the server has a specific feature.
func (ls *LogicalServer) HasFeature(flag int) bool {
	return ls.Features&flag != 0
}

// IsSecureCore returns true if this is a Secure Core server.
func (ls *LogicalServer) IsSecureCore() bool {
	return ls.HasFeature(FeatureSecureCore)
}

// IsP2P returns true if P2P is allowed on this server.
func (ls *LogicalServer) IsP2P() bool {
	return ls.HasFeature(FeatureP2P)
}

// IsStreaming returns true if this is a streaming-optimized server.
func (ls *LogicalServer) IsStreaming() bool {
	return ls.HasFeature(FeatureStreaming)
}

// GetCity returns the city name or empty string if not set.
func (ls *LogicalServer) GetCity() string {
	if ls.City != nil {
		return *ls.City
	}
	return ""
}

// GetRegion returns the region name or empty string if not set.
func (ls *LogicalServer) GetRegion() string {
	if ls.Region != nil {
		return *ls.Region
	}
	return ""
}

// GetFirstOnlineServer returns the first online physical server.
func (ls *LogicalServer) GetFirstOnlineServer() *Server {
	for i := range ls.Servers {
		if ls.Servers[i].Status == 1 {
			return &ls.Servers[i]
		}
	}
	return nil
}

// GetEntryIP returns the entry IP of the first online server.
func (ls *LogicalServer) GetEntryIP() string {
	if server := ls.GetFirstOnlineServer(); server != nil {
		return server.EntryIP
	}
	if len(ls.Servers) > 0 {
		return ls.Servers[0].EntryIP
	}
	return ""
}

// GetWireGuardPublicKey returns the WireGuard public key from the first available server.
func (ls *LogicalServer) GetWireGuardPublicKey() string {
	for _, server := range ls.Servers {
		if server.X25519PublicKey != "" {
			return server.X25519PublicKey
		}
	}
	return ""
}

// SessionResponse represents the ProtonVPN session info response.
type SessionResponse struct {
	Code         int    `json:"Code"`
	UID          string `json:"UID"`
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
	Scope        string `json:"Scope"`
	LocalID      int    `json:"LocalID"`
}

// VPNInfoResponse represents the VPN info response.
type VPNInfoResponse struct {
	Code int     `json:"Code"`
	VPN  VPNInfo `json:"VPN"`
}

// VPNInfo contains VPN-specific account information.
type VPNInfo struct {
	Status         int    `json:"Status"`
	ExpirationTime int64  `json:"ExpirationTime"`
	PlanName       string `json:"PlanName"`
	MaxConnect     int    `json:"MaxConnect"`
	MaxTier        int    `json:"MaxTier"`
	Services       int    `json:"Services"`
	GroupID        string `json:"GroupID"`
	Name           string `json:"Name"`
}

// NOTE: ProtonVPN OpenVPN CA / tls-auth material is intentionally NOT embedded
// here. The values previously hard-coded in this file were unusable: the CA
// certificate failed x509 parsing ("malformed certificate") and the tls-auth
// block was fabricated (repeating placeholder lines), which would have produced
// an .ovpn that either refuses to start or, worse, silently disables server
// verification. Embedding placeholder or hand-rolled crypto material is unsafe.
//
// The CA certificate (and optional tls-auth key) must be supplied by the
// operator via configuration (Credentials.CACert / Credentials.TLSAuthKey) and
// is validated fail-closed at OpenVPN config-generation time. See the
// generateOpenVPNConfigContent method in client.go.

// OpenVPN ports for ProtonVPN.
const (
	OpenVPNTCPPort = 443
	OpenVPNUDPPort = 1194
)

// WireGuard port for ProtonVPN.
const WireGuardPort = 51820

// ParseServerName parses a ProtonVPN server name to extract country and number.
// Format: "XX#N" where XX is country code and N is server number.
// Example: "US#42" -> ("US", 42)
func ParseServerName(name string) (country string, number int, err error) {
	parts := strings.SplitN(name, "#", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid server name format: %s", name)
	}

	country = strings.ToUpper(parts[0])
	number, err = strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid server number in %s: %w", name, err)
	}

	return country, number, nil
}

// FormatServerName creates a ProtonVPN server name from country and number.
func FormatServerName(country string, number int) string {
	return fmt.Sprintf("%s#%d", strings.ToUpper(country), number)
}

// CountryCodeToName maps ISO country codes to full names for common VPN locations.
var CountryCodeToName = map[string]string{
	"US": "United States",
	"GB": "United Kingdom",
	"DE": "Germany",
	"FR": "France",
	"NL": "Netherlands",
	"CH": "Switzerland",
	"SE": "Sweden",
	"NO": "Norway",
	"DK": "Denmark",
	"FI": "Finland",
	"JP": "Japan",
	"SG": "Singapore",
	"AU": "Australia",
	"CA": "Canada",
	"IT": "Italy",
	"ES": "Spain",
	"BE": "Belgium",
	"AT": "Austria",
	"PL": "Poland",
	"CZ": "Czech Republic",
	"HU": "Hungary",
	"RO": "Romania",
	"PT": "Portugal",
	"IE": "Ireland",
	"LU": "Luxembourg",
	"IS": "Iceland",
	"BR": "Brazil",
	"AR": "Argentina",
	"MX": "Mexico",
	"CL": "Chile",
	"CO": "Colombia",
	"HK": "Hong Kong",
	"TW": "Taiwan",
	"KR": "South Korea",
	"IN": "India",
	"ZA": "South Africa",
	"AE": "United Arab Emirates",
	"IL": "Israel",
	"TR": "Turkey",
	"RU": "Russia",
	"UA": "Ukraine",
	"NZ": "New Zealand",
}

// GetCountryName returns the full country name for a code, or the code if unknown.
func GetCountryName(code string) string {
	if name, ok := CountryCodeToName[strings.ToUpper(code)]; ok {
		return name
	}
	return code
}
