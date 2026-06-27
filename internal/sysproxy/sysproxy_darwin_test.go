//go:build darwin

package sysproxy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRunner records invocations and returns canned responses keyed by the
// first argument (the networksetup subcommand flag).
type fakeRunner struct {
	calls     [][]string
	responses map[string]fakeResponse
	defaultFn func(args []string) ([]byte, error)
}

type fakeResponse struct {
	out []byte
	err error
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)

	if len(args) > 0 {
		if resp, ok := f.responses[args[0]]; ok {
			return resp.out, resp.err
		}
	}
	if f.defaultFn != nil {
		return f.defaultFn(args)
	}
	return nil, nil
}

const listOutput = `An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*Bluetooth PAN
Thunderbolt Ethernet
`

func infoFor(service string) []byte {
	switch service {
	case "Wi-Fi":
		// Active service with an IP.
		return []byte("DHCP Configuration\nIP address: 192.168.1.10\nSubnet mask: 255.255.255.0\nRouter: 192.168.1.1\n")
	default:
		return []byte("IP address: none\n")
	}
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		responses: map[string]fakeResponse{
			"-listallnetworkservices": {out: []byte(listOutput)},
		},
		defaultFn: func(args []string) ([]byte, error) {
			if args[0] == "-getinfo" && len(args) > 1 {
				return infoFor(args[1]), nil
			}
			return nil, nil
		},
	}
}

func TestDarwinSetProxy(t *testing.T) {
	f := newFakeRunner()
	m := &darwinManager{run: f}

	require.NoError(t, m.SetProxy("127.0.0.1:8080"))

	// The active service should be Wi-Fi (first enabled service with an IP).
	joined := joinCalls(f.calls)
	assert.Contains(t, joined, "networksetup -setwebproxy Wi-Fi 127.0.0.1 8080")
	assert.Contains(t, joined, "networksetup -setwebproxystate Wi-Fi on")
	assert.Contains(t, joined, "networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080")
	assert.Contains(t, joined, "networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 8080")
}

func TestDarwinSetProxyIPv6(t *testing.T) {
	f := newFakeRunner()
	m := &darwinManager{run: f}

	require.NoError(t, m.SetProxy("[::1]:9090"))
	joined := joinCalls(f.calls)
	assert.Contains(t, joined, "networksetup -setwebproxy Wi-Fi ::1 9090")
}

func TestDarwinSetProxyInvalidAddress(t *testing.T) {
	f := newFakeRunner()
	m := &darwinManager{run: f}

	err := m.SetProxy("not-an-address")
	require.Error(t, err)
	// Should fail before invoking networksetup.
	assert.Empty(t, f.calls)
}

func TestDarwinClearProxy(t *testing.T) {
	f := newFakeRunner()
	m := &darwinManager{run: f}

	require.NoError(t, m.ClearProxy())
	joined := joinCalls(f.calls)
	assert.Contains(t, joined, "networksetup -setwebproxystate Wi-Fi off")
	assert.Contains(t, joined, "networksetup -setsecurewebproxystate Wi-Fi off")
	assert.Contains(t, joined, "networksetup -setsocksfirewallproxystate Wi-Fi off")
}

func TestDarwinNoActiveService(t *testing.T) {
	f := &fakeRunner{
		responses: map[string]fakeResponse{
			"-listallnetworkservices": {out: []byte("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n")},
		},
		defaultFn: func(args []string) ([]byte, error) {
			// No service has an IP.
			return []byte("IP address: none\n"), nil
		},
	}
	m := &darwinManager{run: f}

	err := m.SetProxy("127.0.0.1:8080")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestDarwinListCommandFails(t *testing.T) {
	f := &fakeRunner{
		responses: map[string]fakeResponse{
			"-listallnetworkservices": {err: fmt.Errorf("boom")},
		},
	}
	m := &darwinManager{run: f}

	err := m.SetProxy("127.0.0.1:8080")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestDarwinSetCommandFails(t *testing.T) {
	f := newFakeRunner()
	f.responses["-setwebproxy"] = fakeResponse{out: []byte("denied"), err: fmt.Errorf("exit 1")}
	m := &darwinManager{run: f}

	err := m.SetProxy("127.0.0.1:8080")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "networksetup")
}

func TestParseNetworkServices(t *testing.T) {
	services := parseNetworkServices(listOutput)
	assert.Equal(t, []string{"Wi-Fi", "Thunderbolt Ethernet"}, services)
}

func TestParseNetworkServicesEmpty(t *testing.T) {
	assert.Empty(t, parseNetworkServices(""))
}

func TestServiceInfoHasIP(t *testing.T) {
	assert.True(t, serviceInfoHasIP("IP address: 10.0.0.2\n"))
	assert.True(t, serviceInfoHasIP("IPv6 IP address: fe80::1\n"))
	assert.False(t, serviceInfoHasIP("IP address: none\n"))
	assert.False(t, serviceInfoHasIP(""))
}

func joinCalls(calls [][]string) string {
	var lines []string
	for _, c := range calls {
		lines = append(lines, strings.Join(c, " "))
	}
	return strings.Join(lines, "\n")
}
