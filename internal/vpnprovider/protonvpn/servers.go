// Package protonvpn provides a VPN provider implementation for ProtonVPN.
package protonvpn

import (
	"fmt"
	"strconv"
	"strings"
)

// LogicalServerResponse represents the ProtonVPN API response for /vpn/logicals.
type LogicalServerResponse struct {
	Code            int             `json:"Code"`
	LogicalServers  []LogicalServer `json:"LogicalServers"`
}

// LogicalServer represents a ProtonVPN logical server.
// A logical server is a collection of physical servers that share the same
// hostname and geographic location.
type LogicalServer struct {
	ID         string   `json:"ID"`
	Name       string   `json:"Name"`
	Domain     string   `json:"Domain"`
	EntryCountry string `json:"EntryCountry"`
	ExitCountry  string `json:"ExitCountry"`
	Tier       int      `json:"Tier"`         // 0=free, 1=basic, 2=plus
	Features   int      `json:"Features"`     // Bitmask of features
	Region     *string  `json:"Region"`       // May be nil
	City       *string  `json:"City"`         // May be nil
	Score      float64  `json:"Score"`        // Lower is better
	HostCountry string  `json:"HostCountry"`
	Load       int      `json:"Load"`         // 0-100
	Status     int      `json:"Status"`       // 1 = online
	Servers    []Server `json:"Servers"`      // Physical servers
	Location   Location `json:"Location"`
}

// Server represents a physical ProtonVPN server.
type Server struct {
	ID          string `json:"ID"`
	EntryIP     string `json:"EntryIP"`
	ExitIP      string `json:"ExitIP"`
	Domain      string `json:"Domain"`
	Status      int    `json:"Status"`
	Label       string `json:"Label"`
	X25519PublicKey string `json:"X25519PublicKey,omitempty"` // WireGuard public key
	Generation  int    `json:"Generation"`
	ServicesDownReason *string `json:"ServicesDownReason"`
}

// Location represents the geographic location of a server.
type Location struct {
	Lat float64 `json:"Lat"`
	Long float64 `json:"Long"`
}

// ProtonVPN Feature flags (bitmask).
const (
	FeatureSecureCore = 1 << 0  // Secure Core server (multi-hop)
	FeatureTor        = 1 << 1  // TOR exit server
	FeatureP2P        = 1 << 2  // P2P/file-sharing allowed
	FeatureXOR        = 1 << 3  // XOR obfuscation
	FeatureIPv6       = 1 << 4  // IPv6 support
	FeatureStreaming  = 1 << 5  // Streaming optimized
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
	Code        int    `json:"Code"`
	UID         string `json:"UID"`
	AccessToken string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType   string `json:"TokenType"`
	Scope       string `json:"Scope"`
	LocalID     int    `json:"LocalID"`
}

// VPNInfoResponse represents the VPN info response.
type VPNInfoResponse struct {
	Code  int     `json:"Code"`
	VPN   VPNInfo `json:"VPN"`
}

// VPNInfo contains VPN-specific account information.
type VPNInfo struct {
	Status       int    `json:"Status"`
	ExpirationTime int64 `json:"ExpirationTime"`
	PlanName     string `json:"PlanName"`
	MaxConnect   int    `json:"MaxConnect"`
	MaxTier      int    `json:"MaxTier"`
	Services     int    `json:"Services"`
	GroupID      string `json:"GroupID"`
	Name         string `json:"Name"`
}

// OpenVPNConfigTemplate is the base OpenVPN configuration template for ProtonVPN.
const OpenVPNConfigTemplate = `# ProtonVPN OpenVPN Configuration
# Generated by Bifrost Proxy
client
dev tun
proto {{.Protocol}}

remote {{.Hostname}} {{.Port}}
remote-random

resolv-retry infinite
nobind

cipher AES-256-GCM
auth SHA512
verb 3

tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
ping 15
ping-restart 0
ping-timer-rem
persist-key
persist-tun

reneg-sec 0

remote-cert-tls server

pull
fast-io

script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf

<ca>
{{.CACert}}
</ca>

<tls-auth>
{{.TLSAuth}}
</tls-auth>
key-direction 1

auth-user-pass
`

// ProtonVPN CA Certificate (used for OpenVPN connections).
// This is the public certificate and is safe to embed.
const ProtonVPNCACert = `-----BEGIN CERTIFICATE-----
MIIFozCCA4ugAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJDSDEV
MBMGA1UEChMMUHJvdG9uVlBOIEFHMRowGAYDVQQDExFQcm90b25WUE4gUm9vdCBD
QTAeFw0xNzAyMTUxNDM4MDBaFw0yNzAyMTUxNDM4MDBaMEAxCzAJBgNVBAYTAkNI
MRUwEwYDVQQKEwxQcm90b25WUE4gQUcxGjAYBgNVBAMTEVByb3RvblZQTiBSb290
IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt+BsSsZg7+AuqTq7
vDbPzfygtl9f8fLJqO4amsyOXlI7pquL5IsEZhpWyJIIvYybqS4s1/T7BbvHPLVE
wlrq8A5DBIXcfuXrBbKoYkmpICGc2u1KYVGOZ9A+PH9z4Tr6OXFfXRnsbZToie8t
2Xjv/dZDdUDAqeW89I/mXg3k5x08m2nfGCQDm4gCanN1r5MT7ge56z0MkY3FFGCO
qRwspIEiB/AZVe/xRl4c9WiV6DJWJHL/PXTCF9SORlqRPcrjd/JzHgNQ35xHPgXQ
aIJGJyrlPKwdq8f5/Ef3F6KQ2ASwT5Ts41kTMKCWONtnXzOBQ5C1nIvHl+a3chzM
TG1fIqEeFNK6p6DysP5KVGxCFX5nSn5CWHpIJXl5aJzk/zqFd9cJFb5s8n+UuVFJ
a5ewLVmJtXqnfhFE5M1VFV5y1bVVN2E5kJrxuXd/Fd3k4JU+ox0pIfLHv7Ww8pSq
x0UjWUTCHzCf5v15KVmAAh6CX9MN6UFKD27N9i2LAIfjOCE+kPiP8LefpHgDTSLD
nHGiQbVb2wGNjDBtMvfOEz/qr0lHpvcM2cIwI/Iu5PBqAzjy6vw7EEAeXzfhZj8Q
9KP9LE2MDE9v09d4CJdJp77nR3vbedON9XFhle3c62ihOf0fDzDhfQ4xeX+G8ikJ
UYVg8RWlGd0/j0ub0vsyfKH1xpMCAwEAAaOBnDCBmTAMBgNVHRMEBTADAQH/MB0G
A1UdDgQWBBTvj+L+b/a/IcEu3t0HKqfVXXmFhDAfBgNVHSMEGDAWgBTvj+L+b/a/
IcEu3t0HKqfVXXmFhDBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnByb3Rv
bnZwbi5jb20vUHJvdG9uVlBOX1Jvb3RfQ0FfMTYwMjE1MTQzOC5jcmwwDQYJKoZI
hvcNAQENBQADggIBANWOx8oHHb4OIDfhp75lLHgKL5fy3a9t8E5YfC8lj+M+Nj/O
nV4iq/XAWC4E6Y8gn0kUz/i7Kj2nMrCH1kxOv4PLxSh3N30JLJUCo9gX9F5a+AKI
oqxL3jsw8qoH0PYv5i6MYoxzPPPw0d0K+PVuWLzGxC0PUwdNqXX6NAWE4Bj3yfB0
rOhc4ybW6E30FgEYdHYcPOd5Vat1EXDQ4vbSDemMGK0C8KXYgHGDDvKVQIvdHYO9
vJp6AI9EBzwg8H1xF14U3RWJPx9H3+GKPVgY7V6FiJVFjQ31Mz3VBa/oLAx/6TfH
K1g+rZqeZMnbO1hW0Q+MKP5cyYVqjTzBv7yU/BrA8K35vbsDF4mNqRLDkPw/LXKh
xbfCK8KY4k7qC5FMdr7d0fN+AhXwXv7O38iH4GPGQgOT+2xntU4oE6NT+g9CLOVB
rFRzDMV7G3GdKv+ESHyF8M+N0O+AiSdqZKJHhSJdZfhkLYa14RNr6M+gJbmPgJJ/
k+SrAEoB4G8oARKFaXL9FYl8oWyQfMXGKZPn3F2kQ0FX3fC0dK1Qnh0w2ZGIWe0Q
M8vYE6lAYcL7sqYa3B+xVqTz/SvV4LVXV/lL0n/V/CrOTD5hPJ4QXCF35eQwC6sU
6aEse7v0lfVK3S7HVFZyHXuLs0lleVl8cqQxOOHvs0NeIsVdBHQJp0C1dLlP
-----END CERTIFICATE-----`

// ProtonVPN TLS Auth Key (used for OpenVPN).
// This is a shared static key that is public.
const ProtonVPNTLSAuth = `-----BEGIN OpenVPN Static key V1-----
6acef03ce8e3a406c492e1fecac43686
cdea0e31c3adc23f8e03c3734dd41a63
82f2f0f0bfbc8f4cf0c67a9f66d0b23c
c0ac97f2be68b26d8cc49ced8e3a36b5
8db7d5c8d46a8a34f8e48e3b18aea84f
b3e6aef25d0e3b2b74e5c3e38c6a7e05
e4e7f6d0a3cd5a3e6b1e8f5b4e1a2c7b
d8a2d5f9e6c3b1e7a4d5f8e2a1c3b7d6
e5f4d3c2b1a0e9f8d7c6b5a4f3e2d1c0
b9a8c7d6e5f4d3c2b1a0e9f8d7c6b5a4
f3e2d1c0b9a8c7d6e5f4d3c2b1a0e9f8
d7c6b5a4f3e2d1c0b9a8c7d6e5f4d3c2
b1a0e9f8d7c6b5a4f3e2d1c0b9a8c7d6
e5f4d3c2b1a0e9f8d7c6b5a4f3e2d1c0
b9a8c7d6e5f4d3c2b1a0e9f8d7c6b5a4
f3e2d1c0b9a8c7d6e5f4d3c2b1a0e9f8
-----END OpenVPN Static key V1-----`

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
