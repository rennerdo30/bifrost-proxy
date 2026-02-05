// Package openvpn provides OpenVPN configuration and process management.
package openvpn

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config represents OpenVPN configuration options.
type Config struct {
	ConfigFile string
	AuthFile   string // Path to auth-user-pass file

	// Parsed values from config file
	Remote     []RemoteServer
	Protocol   string // udp, tcp
	Port       int
	Dev        string // tun, tap
	Cipher     string
	Auth       string
	TLSAuth    string
	CA         string
	Cert       string
	Key        string
	Compress   string
	Verb       int
	Management ManagementConfig
}

// RemoteServer represents a remote server entry.
type RemoteServer struct {
	Host     string
	Port     int
	Protocol string
}

// ManagementConfig represents management interface settings.
type ManagementConfig struct {
	Address  string
	Port     int
	Password string
}

// ParseConfigFile parses an OpenVPN configuration file.
func ParseConfigFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()

	config := &Config{
		ConfigFile: path,
		Protocol:   "udp",
		Dev:        "tun",
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		directive := strings.ToLower(parts[0])
		args := parts[1:]

		switch directive {
		case "remote":
			if len(args) >= 1 {
				remote := RemoteServer{Host: args[0], Port: 1194, Protocol: config.Protocol}
				if len(args) >= 2 {
					_, _ = fmt.Sscanf(args[1], "%d", &remote.Port) //nolint:errcheck // Default used if parse fails
				}
				if len(args) >= 3 {
					remote.Protocol = args[2]
				}
				config.Remote = append(config.Remote, remote)
			}
		case "proto":
			if len(args) >= 1 {
				config.Protocol = args[0]
			}
		case "port":
			if len(args) >= 1 {
				_, _ = fmt.Sscanf(args[0], "%d", &config.Port) //nolint:errcheck // Default used if parse fails
			}
		case "dev":
			if len(args) >= 1 {
				config.Dev = args[0]
			}
		case "cipher":
			if len(args) >= 1 {
				config.Cipher = args[0]
			}
		case "auth":
			if len(args) >= 1 {
				config.Auth = args[0]
			}
		case "tls-auth":
			if len(args) >= 1 {
				config.TLSAuth = args[0]
			}
		case "ca":
			if len(args) >= 1 {
				config.CA = args[0]
			}
		case "cert":
			if len(args) >= 1 {
				config.Cert = args[0]
			}
		case "key":
			if len(args) >= 1 {
				config.Key = args[0]
			}
		case "compress":
			if len(args) >= 1 {
				config.Compress = args[0]
			} else {
				config.Compress = "lzo"
			}
		case "comp-lzo":
			config.Compress = "lzo"
		case "verb":
			if len(args) >= 1 {
				_, _ = fmt.Sscanf(args[0], "%d", &config.Verb) //nolint:errcheck // Default used if parse fails
			}
		case "management":
			if len(args) >= 2 {
				config.Management.Address = args[0]
				_, _ = fmt.Sscanf(args[1], "%d", &config.Management.Port) //nolint:errcheck // Default used if parse fails
				if len(args) >= 3 {
					config.Management.Password = args[2]
				}
			}
		case "auth-user-pass":
			if len(args) >= 1 {
				config.AuthFile = args[0]
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan config: %w", err)
	}

	return config, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.ConfigFile == "" {
		return fmt.Errorf("config file path is required")
	}

	if _, err := os.Stat(c.ConfigFile); err != nil {
		return fmt.Errorf("config file not accessible: %w", err)
	}

	return nil
}

// GetPrimaryRemote returns the first remote server or empty if none.
func (c *Config) GetPrimaryRemote() string {
	if len(c.Remote) == 0 {
		return ""
	}
	r := c.Remote[0]
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}
