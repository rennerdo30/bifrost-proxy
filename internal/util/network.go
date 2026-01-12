package util

import (
	"net"
	"strconv"
	"strings"
)

// SplitHostPort splits a network address into host and port.
// Unlike net.SplitHostPort, this handles addresses without ports.
func SplitHostPort(addr string) (host string, port int, err error) {
	// Try standard split first
	h, p, splitErr := net.SplitHostPort(addr)
	if splitErr == nil {
		portNum, parseErr := strconv.Atoi(p)
		if parseErr != nil {
			return "", 0, parseErr
		}
		return h, portNum, nil
	}

	// If no port, return the address as host with port 0
	if strings.Contains(splitErr.Error(), "missing port") {
		return addr, 0, nil
	}

	return "", 0, splitErr
}

// JoinHostPort joins a host and port into a network address.
func JoinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// IsLocalAddress checks if an address is a local/loopback address.
func IsLocalAddress(addr string) bool {
	host, _, _ := SplitHostPort(addr)
	if host == "" {
		host = addr
	}

	// Check common local hostnames
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}

	// Parse as IP and check
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsLoopback() || ip.IsUnspecified()
}

// GetOutboundIP returns the preferred outbound IP of this machine.
func GetOutboundIP() (net.IP, error) {
	// Use UDP dial to find the preferred outbound IP
	// This doesn't actually connect but determines the interface
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

// ParseCIDR parses a CIDR string and returns the network.
func ParseCIDR(cidr string) (*net.IPNet, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try parsing as a single IP
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, err
		}
		// Create a /32 or /128 network
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	return network, nil
}

// IPInNetworks checks if an IP is in any of the given networks.
func IPInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// GetHostFromRequest extracts the host from an HTTP Host header or URL.
func GetHostFromRequest(host string) string {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Check if this is IPv6 (has brackets)
		if strings.HasPrefix(host, "[") {
			if bracketIdx := strings.Index(host, "]:"); bracketIdx != -1 {
				host = host[1:bracketIdx]
			} else if strings.HasSuffix(host, "]") {
				host = host[1 : len(host)-1]
			}
		} else {
			host = host[:idx]
		}
	}
	return strings.ToLower(host)
}
