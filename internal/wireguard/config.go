// Package wireguard provides WireGuard configuration parsing and management.
package wireguard

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// Config represents a complete WireGuard configuration.
type Config struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
}

// InterfaceConfig represents the [Interface] section.
type InterfaceConfig struct {
	PrivateKey string
	Address    []string // Can have multiple addresses (IPv4 and IPv6)
	ListenPort int
	DNS        []string
	MTU        int
	Table      string
	PreUp      string
	PostUp     string
	PreDown    string
	PostDown   string
}

// PeerConfig represents a [Peer] section.
type PeerConfig struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

// ParseFile parses a WireGuard configuration file.
func ParseFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()

	return Parse(file)
}

// Parse parses a WireGuard configuration from an io.Reader.
func Parse(r io.Reader) (*Config, error) {
	config := &Config{}
	var currentSection string
	var currentPeer *PeerConfig

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.ToLower(strings.Trim(line, "[]"))
			currentSection = section

			if section == "peer" {
				if currentPeer != nil {
					config.Peers = append(config.Peers, *currentPeer)
				}
				currentPeer = &PeerConfig{}
			}
			continue
		}

		// Parse key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("line %d: invalid format", lineNum)
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "interface":
			if err := parseInterfaceKey(&config.Interface, key, value); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNum, err)
			}
		case "peer":
			// currentPeer is always non-nil here because currentSection is only set to "peer"
			// when a [Peer] header is encountered, which also initializes currentPeer.
			if err := parsePeerKey(currentPeer, key, value); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNum, err)
			}
		}
	}

	// Add last peer
	if currentPeer != nil {
		config.Peers = append(config.Peers, *currentPeer)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan config: %w", err)
	}

	return config, nil
}

// parseInterfaceKey parses a key in the [Interface] section.
func parseInterfaceKey(iface *InterfaceConfig, key, value string) error {
	switch key {
	case "privatekey":
		if err := validateKey(value); err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}
		iface.PrivateKey = value
	case "address":
		addresses := strings.Split(value, ",")
		for _, addr := range addresses {
			addr = strings.TrimSpace(addr)
			if _, _, err := net.ParseCIDR(addr); err != nil {
				// Try parsing as plain IP
				if net.ParseIP(addr) == nil {
					return fmt.Errorf("invalid address: %s", addr)
				}
			}
			iface.Address = append(iface.Address, addr)
		}
	case "listenport":
		port, err := strconv.Atoi(value)
		if err != nil || port < 0 || port > 65535 {
			return fmt.Errorf("invalid listen port: %s", value)
		}
		iface.ListenPort = port
	case "dns":
		servers := strings.Split(value, ",")
		for _, srv := range servers {
			srv = strings.TrimSpace(srv)
			iface.DNS = append(iface.DNS, srv)
		}
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu < 576 || mtu > 65535 {
			return fmt.Errorf("invalid MTU: %s", value)
		}
		iface.MTU = mtu
	case "table":
		iface.Table = value
	case "preup":
		iface.PreUp = value
	case "postup":
		iface.PostUp = value
	case "predown":
		iface.PreDown = value
	case "postdown":
		iface.PostDown = value
	}
	return nil
}

// parsePeerKey parses a key in a [Peer] section.
func parsePeerKey(peer *PeerConfig, key, value string) error {
	switch key {
	case "publickey":
		if err := validateKey(value); err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
		peer.PublicKey = value
	case "presharedkey":
		if err := validateKey(value); err != nil {
			return fmt.Errorf("invalid preshared key: %w", err)
		}
		peer.PresharedKey = value
	case "endpoint":
		peer.Endpoint = value
	case "allowedips":
		ips := strings.Split(value, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if _, _, err := net.ParseCIDR(ip); err != nil {
				return fmt.Errorf("invalid allowed IP: %s", ip)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, ip)
		}
	case "persistentkeepalive":
		ka, err := strconv.Atoi(value)
		if err != nil || ka < 0 || ka > 65535 {
			return fmt.Errorf("invalid persistent keepalive: %s", value)
		}
		peer.PersistentKeepalive = ka
	}
	return nil
}

// validateKey validates a WireGuard key (base64 encoded, 32 bytes).
func validateKey(key string) error {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("not valid base64")
	}
	if len(decoded) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(decoded))
	}
	return nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Interface.PrivateKey == "" {
		return fmt.Errorf("interface private key is required")
	}
	if len(c.Interface.Address) == 0 {
		return fmt.Errorf("interface address is required")
	}
	if len(c.Peers) == 0 {
		return fmt.Errorf("at least one peer is required")
	}
	for i, peer := range c.Peers {
		if peer.PublicKey == "" {
			return fmt.Errorf("peer %d: public key is required", i)
		}
		if len(peer.AllowedIPs) == 0 {
			return fmt.Errorf("peer %d: allowed IPs are required", i)
		}
	}
	return nil
}

// ToIPC generates the IPC configuration string for wireguard-go.
func (c *Config) ToIPC() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("private_key=%s\n", hexKey(c.Interface.PrivateKey)))

	if c.Interface.ListenPort > 0 {
		sb.WriteString(fmt.Sprintf("listen_port=%d\n", c.Interface.ListenPort))
	}

	for _, peer := range c.Peers {
		sb.WriteString(fmt.Sprintf("public_key=%s\n", hexKey(peer.PublicKey)))

		if peer.PresharedKey != "" {
			sb.WriteString(fmt.Sprintf("preshared_key=%s\n", hexKey(peer.PresharedKey)))
		}

		if peer.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))
		}

		for _, ip := range peer.AllowedIPs {
			sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}

		if peer.PersistentKeepalive > 0 {
			sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		}
	}

	return sb.String()
}

// hexKey converts a base64 key to hex format for IPC.
// The key is assumed to be pre-validated by validateKey, so we can safely ignore the error.
func hexKey(b64Key string) string {
	decoded, _ := base64.StdEncoding.DecodeString(b64Key) //nolint:errcheck
	return fmt.Sprintf("%x", decoded)
}
