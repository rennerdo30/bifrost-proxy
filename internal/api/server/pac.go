package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// PACGenerator generates PAC (Proxy Auto-Configuration) files.
type PACGenerator struct {
	getConfig   func() *config.ServerConfig
	proxyHost   string
	proxyPort   string
	socks5Port  string
}

// NewPACGenerator creates a new PAC generator.
func NewPACGenerator(getConfig func() *config.ServerConfig, proxyHost, proxyPort, socks5Port string) *PACGenerator {
	return &PACGenerator{
		getConfig:  getConfig,
		proxyHost:  proxyHost,
		proxyPort:  proxyPort,
		socks5Port: socks5Port,
	}
}

// HandlePAC serves the PAC file.
func (p *PACGenerator) HandlePAC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Content-Disposition", "inline; filename=\"proxy.pac\"")

	pac := p.Generate(r.Host)
	w.Write([]byte(pac))
}

// Generate creates a PAC file based on the current routes configuration.
func (p *PACGenerator) Generate(requestHost string) string {
	cfg := p.getConfig()

	// Determine proxy host - use request host if not configured
	proxyHost := p.proxyHost
	if proxyHost == "" {
		// Extract host without port
		proxyHost = requestHost
		if idx := strings.LastIndex(proxyHost, ":"); idx != -1 {
			proxyHost = proxyHost[:idx]
		}
	}

	// Build the PAC file
	var sb strings.Builder

	sb.WriteString(`// Bifrost Proxy Auto-Configuration (PAC) File
// Generated automatically from server routes configuration

function FindProxyForURL(url, host) {
    // Helper function for wildcard matching
    function wildcardMatch(str, pattern) {
        if (pattern === "*") return true;
        if (pattern.startsWith("*.")) {
            var suffix = pattern.substring(1);
            return str.endsWith(suffix) || str === pattern.substring(2);
        }
        return str === pattern || shExpMatch(str, pattern);
    }

`)

	// Group routes by backend for cleaner output
	// Process routes in priority order (higher priority first)
	routes := cfg.Routes

	// Generate conditions for each route
	for i, route := range routes {
		if len(route.Domains) == 0 {
			continue
		}

		// Check if this is a catch-all route
		isCatchAll := false
		for _, domain := range route.Domains {
			if domain == "*" {
				isCatchAll = true
				break
			}
		}

		if isCatchAll {
			// Catch-all routes go at the end
			continue
		}

		// Build condition for this route
		var conditions []string
		for _, domain := range route.Domains {
			if domain == "*" {
				continue
			}
			// Convert domain pattern to PAC condition
			conditions = append(conditions, fmt.Sprintf(`wildcardMatch(host, "%s")`, escapeJS(domain)))
		}

		if len(conditions) > 0 {
			condition := strings.Join(conditions, " || ")
			sb.WriteString(fmt.Sprintf("    // Route %d: %s -> %s\n", i+1, strings.Join(route.Domains, ", "), route.Backend))
			sb.WriteString(fmt.Sprintf("    if (%s) {\n", condition))
			sb.WriteString(fmt.Sprintf("        return \"PROXY %s:%s; SOCKS5 %s:%s; DIRECT\";\n", proxyHost, p.proxyPort, proxyHost, p.socks5Port))
			sb.WriteString("    }\n\n")
		}
	}

	// Check if there's a catch-all route
	hasCatchAll := false
	for _, route := range routes {
		for _, domain := range route.Domains {
			if domain == "*" {
				hasCatchAll = true
				break
			}
		}
	}

	// Default behavior
	sb.WriteString("    // Default\n")
	if hasCatchAll {
		sb.WriteString(fmt.Sprintf("    return \"PROXY %s:%s; SOCKS5 %s:%s; DIRECT\";\n", proxyHost, p.proxyPort, proxyHost, p.socks5Port))
	} else {
		sb.WriteString("    return \"DIRECT\";\n")
	}

	sb.WriteString("}\n")

	return sb.String()
}

// escapeJS escapes a string for use in JavaScript.
func escapeJS(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "'", "\\'")
	return s
}
