//go:build darwin

package sysproxy

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// runner abstracts command execution so the logic can be unit tested without
// invoking the real networksetup binary.
type runner interface {
	run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type darwinManager struct {
	run runner

	mu sync.Mutex
	// configuredService is the network service SetProxy last configured, so
	// ClearProxy can disable the proxy on the same service even if active-
	// service detection would now resolve to a different one.
	configuredService string
}

func newPlatformManager() Manager {
	return &darwinManager{run: execRunner{}}
}

// SetProxy configures the HTTP, HTTPS and SOCKS proxies for the active network
// service via the networksetup utility.
func (m *darwinManager) SetProxy(address string) error {
	host, port, err := splitHostPort(address)
	if err != nil {
		return err
	}

	service, err := m.activeNetworkService()
	if err != nil {
		return err
	}

	// Configure web (HTTP), secure web (HTTPS) and SOCKS proxies to the same
	// listener. networksetup also enables the proxy when given host/port.
	steps := [][]string{
		{"-setwebproxy", service, host, port},
		{"-setwebproxystate", service, "on"},
		{"-setsecurewebproxy", service, host, port},
		{"-setsecurewebproxystate", service, "on"},
		{"-setsocksfirewallproxy", service, host, port},
		{"-setsocksfirewallproxystate", service, "on"},
	}
	for _, args := range steps {
		if err := m.exec(args...); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.configuredService = service
	m.mu.Unlock()
	return nil
}

// ClearProxy disables the HTTP, HTTPS and SOCKS proxies. It targets the service
// SetProxy configured (so cleanup is reliable even if the active service has
// since changed), falling back to active-service detection if none is recorded.
func (m *darwinManager) ClearProxy() error {
	m.mu.Lock()
	service := m.configuredService
	m.mu.Unlock()

	if service == "" {
		var err error
		service, err = m.activeNetworkService()
		if err != nil {
			return err
		}
	}

	steps := [][]string{
		{"-setwebproxystate", service, "off"},
		{"-setsecurewebproxystate", service, "off"},
		{"-setsocksfirewallproxystate", service, "off"},
	}
	for _, args := range steps {
		if err := m.exec(args...); err != nil {
			return err
		}
	}
	return nil
}

func (m *darwinManager) exec(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), darwinCommandTimeout)
	defer cancel()

	out, err := m.run.run(ctx, "networksetup", args...)
	if err != nil {
		return fmt.Errorf("networksetup %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// activeNetworkService returns the name of the first enabled network service
// that has an assigned IP address (i.e. the one currently providing
// connectivity). networksetup proxy commands operate on a named service.
func (m *darwinManager) activeNetworkService() (string, error) {
	services, err := m.listNetworkServices()
	if err != nil {
		return "", err
	}
	if len(services) == 0 {
		return "", fmt.Errorf("%w: no active network service found", ErrNotSupported)
	}

	for _, svc := range services {
		active, err := m.serviceHasIP(svc)
		if err != nil {
			// Skip services we cannot query rather than failing outright.
			continue
		}
		if active {
			return svc, nil
		}
	}
	return "", fmt.Errorf("%w: no active network service with an IP address", ErrNotSupported)
}

// listNetworkServices returns the enabled network services in the order
// networksetup reports them (which is the service ordering / priority).
func (m *darwinManager) listNetworkServices() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), darwinCommandTimeout)
	defer cancel()

	out, err := m.run.run(ctx, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("%w: list network services: %v: %s", ErrNotSupported, err, strings.TrimSpace(string(out)))
	}
	return parseNetworkServices(string(out)), nil
}

func (m *darwinManager) serviceHasIP(service string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), darwinCommandTimeout)
	defer cancel()

	out, err := m.run.run(ctx, "networksetup", "-getinfo", service)
	if err != nil {
		return false, fmt.Errorf("getinfo %s: %w", service, err)
	}
	return serviceInfoHasIP(string(out)), nil
}

// parseNetworkServices extracts service names from `networksetup
// -listallnetworkservices` output. The first line is an informational header
// and services prefixed with '*' are disabled and skipped.
func parseNetworkServices(output string) []string {
	var services []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	first := true
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if first {
			// Header: "An asterisk (*) denotes that a network service is disabled."
			first = false
			if strings.Contains(line, "asterisk") || strings.Contains(line, "denotes") {
				continue
			}
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "*") {
			// Disabled service.
			continue
		}
		services = append(services, trimmed)
	}
	return services
}

// serviceInfoHasIP reports whether `networksetup -getinfo <service>` output
// indicates an assigned IPv4/IPv6 address (i.e. the service is active).
func serviceInfoHasIP(output string) bool {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "IP address:"):
			val := strings.TrimSpace(strings.TrimPrefix(line, "IP address:"))
			if val != "" && val != "none" {
				return true
			}
		case strings.HasPrefix(line, "IPv6 IP address:"):
			val := strings.TrimSpace(strings.TrimPrefix(line, "IPv6 IP address:"))
			if val != "" && val != "none" {
				return true
			}
		}
	}
	return false
}
