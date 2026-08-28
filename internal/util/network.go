package util

import (
	"strings"
)

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
