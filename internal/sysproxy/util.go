package sysproxy

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// darwinCommandTimeout bounds external command execution on platforms that shell
// out to OS utilities (macOS networksetup, Linux gsettings).
const darwinCommandTimeout = 10 * time.Second

// splitHostPort parses a "host:port" proxy address into its host and port
// components, validating that both are present and the port is numeric. It
// accepts IPv6 literals in bracket form (e.g. "[::1]:8080").
func splitHostPort(address string) (host, port string, err error) {
	if address == "" {
		return "", "", fmt.Errorf("proxy address is empty")
	}
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		return "", "", fmt.Errorf("invalid proxy address %q: %w", address, err)
	}
	if host == "" {
		return "", "", fmt.Errorf("invalid proxy address %q: missing host", address)
	}
	if _, perr := strconv.Atoi(port); perr != nil {
		return "", "", fmt.Errorf("invalid proxy address %q: non-numeric port", address)
	}
	return host, port, nil
}
