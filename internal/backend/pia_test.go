package backend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/pia"
)

// fakePortForwarder is a test double for portForwardRunner. It delivers a fixed
// port (when >0) and blocks until ctx is canceled, recording its invocation.
type fakePortForwarder struct {
	port       int
	acquireErr error
	started    atomic.Bool
	gotParams  pia.PortForwardParams
	mu         sync.Mutex
}

func (f *fakePortForwarder) Run(ctx context.Context, params pia.PortForwardParams, portCh chan<- int) error {
	f.started.Store(true)
	f.mu.Lock()
	f.gotParams = params
	f.mu.Unlock()

	if f.acquireErr != nil {
		return f.acquireErr
	}
	if f.port > 0 && portCh != nil {
		select {
		case portCh <- f.port:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakePortForwarder) params() pia.PortForwardParams {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotParams
}

// stubTokenRoundTripper intercepts the PIA token endpoint and returns a canned
// token so tests can exercise port-forwarding wiring without live PIA.
type stubTokenRoundTripper struct {
	token string
}

func (s stubTokenRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	body := `{"token":"` + s.token + `"}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}, nil
}

// newPIABackendWithToken builds a PIA backend whose client returns a fixed token
// on Authenticate, suitable for unit-testing the port-forwarding lifecycle.
func newPIABackendWithToken(t *testing.T, token string) *PIABackend {
	t.Helper()
	b := NewPIABackend(PIAConfig{
		Name:           "pf-test",
		Username:       "user",
		Password:       "pass",
		PortForwarding: true,
	})
	b.client = pia.NewClient("user", "pass",
		pia.WithHTTPClient(&http.Client{Transport: stubTokenRoundTripper{token: token}}))
	return b
}

func TestNewPIABackend(t *testing.T) {
	cfg := PIAConfig{
		Name:     "test-pia",
		Username: "p1234567",
		Password: "password",
		Country:  "US",
	}

	b := NewPIABackend(cfg)
	assert.NotNil(t, b)
	assert.Equal(t, "test-pia", b.Name())
	assert.Equal(t, "pia", b.Type())
}

func TestNewPIABackend_Defaults(t *testing.T) {
	cfg := PIAConfig{
		Name:     "test",
		Username: "p1234567",
		Password: "password",
	}

	b := NewPIABackend(cfg)

	// Check defaults are applied
	assert.Equal(t, "wireguard", b.config.Protocol)
	assert.Equal(t, 30*time.Minute, b.config.RefreshInterval)
}

func TestNewPIABackend_CustomConfig(t *testing.T) {
	cfg := PIAConfig{
		Name:            "custom",
		Username:        "p1234567",
		Password:        "password",
		Country:         "NL",
		Protocol:        "openvpn",
		PortForwarding:  true,
		RefreshInterval: 1 * time.Hour,
	}

	b := NewPIABackend(cfg)

	assert.Equal(t, "openvpn", b.config.Protocol)
	assert.Equal(t, "NL", b.config.Country)
	assert.True(t, b.config.PortForwarding)
	assert.Equal(t, 1*time.Hour, b.config.RefreshInterval)
}

func TestPIABackend_Dial_NotStarted(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	_, err := b.Dial(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestPIABackend_DialTimeout_NotStarted(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	_, err := b.DialTimeout(context.Background(), "tcp", "example.com:80", 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestPIABackend_IsHealthy_NotStarted(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	assert.False(t, b.IsHealthy())
}

func TestPIABackend_Stats(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test-pia", Username: "user", Password: "pass"})

	stats := b.Stats()
	assert.Equal(t, "test-pia", stats.Name)
	assert.Equal(t, "pia", stats.Type)
	assert.False(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
}

func TestPIABackend_Stop_NotRunning(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestPIABackend_SelectedServer_NilWhenNotStarted(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	server := b.SelectedServer()
	assert.Nil(t, server)
}

func TestPIABackend_ForwardedPort_ZeroByDefault(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})
	assert.Equal(t, 0, b.ForwardedPort())
}

// startPortForwarding must fail closed when the tunnel gateway is unavailable,
// without launching any goroutine or claiming success.
func TestPIABackend_StartPortForwarding_FailsClosedWithoutGateway(t *testing.T) {
	b := newPIABackendWithToken(t, "tok")
	fake := &fakePortForwarder{port: 12345}
	b.newPortForwarder = func(_ pia.PortForwardParams, _ *slog.Logger) portForwardRunner { return fake }

	err := b.startPortForwarding(gatewayInfo{}) // no gateway IP/hostname
	require.Error(t, err)
	assert.ErrorIs(t, err, pia.ErrPortForwardingNotAvailable)
	assert.False(t, fake.started.Load(), "runner must not start when gateway is missing")
	assert.Equal(t, 0, b.ForwardedPort())
}

// startPortForwarding must fail closed when no token can be obtained.
func TestPIABackend_StartPortForwarding_FailsClosedWithoutToken(t *testing.T) {
	b := newPIABackendWithToken(t, "") // stub returns an empty token -> auth fails
	fake := &fakePortForwarder{port: 12345}
	b.newPortForwarder = func(_ pia.PortForwardParams, _ *slog.Logger) portForwardRunner { return fake }

	err := b.startPortForwarding(gatewayInfo{ip: "10.0.0.1", hostname: "cn.example"})
	require.Error(t, err)
	assert.False(t, fake.started.Load())
	assert.Equal(t, 0, b.ForwardedPort())
}

// startPortForwarding wires the granted port through to ForwardedPort and passes
// the gateway/token params to the runner; stopPortForwarding tears it down.
func TestPIABackend_PortForwardingLifecycle(t *testing.T) {
	b := newPIABackendWithToken(t, "tok-123")
	fake := &fakePortForwarder{port: 50001}
	b.newPortForwarder = func(_ pia.PortForwardParams, _ *slog.Logger) portForwardRunner { return fake }

	gw := gatewayInfo{ip: "10.0.0.1", hostname: "cn.example"}
	require.NoError(t, b.startPortForwarding(gw))

	require.Eventually(t, func() bool {
		return b.ForwardedPort() == 50001
	}, time.Second, 5*time.Millisecond, "forwarded port should be published")

	assert.True(t, fake.started.Load())
	gotParams := fake.params()
	assert.Equal(t, "10.0.0.1", gotParams.GatewayIP)
	assert.Equal(t, "cn.example", gotParams.Hostname)
	assert.Equal(t, "tok-123", gotParams.Token)

	// Stop must cancel and wait for the runner goroutine to exit.
	b.stopPortForwarding()

	// After stop, starting again is safe and re-publishes the port.
	require.NoError(t, b.startPortForwarding(gw))
	require.Eventually(t, func() bool {
		return b.ForwardedPort() == 50001
	}, time.Second, 5*time.Millisecond)
	b.stopPortForwarding()
}

// A runner that fails to acquire a port must be logged but must not leave a
// stale forwarded port nor block stopPortForwarding.
func TestPIABackend_PortForwarding_AcquireError(t *testing.T) {
	b := newPIABackendWithToken(t, "tok")
	fake := &fakePortForwarder{acquireErr: errors.New("getSignature failed")}
	b.newPortForwarder = func(_ pia.PortForwardParams, _ *slog.Logger) portForwardRunner { return fake }

	require.NoError(t, b.startPortForwarding(gatewayInfo{ip: "10.0.0.1", hostname: "cn"}))

	require.Eventually(t, func() bool {
		return fake.started.Load()
	}, time.Second, 5*time.Millisecond)

	// No port is ever published.
	assert.Equal(t, 0, b.ForwardedPort())
	b.stopPortForwarding() // must not block even though Run already returned
}

// stopPortForwarding is a no-op when nothing is running.
func TestPIABackend_StopPortForwarding_Noop(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})
	b.stopPortForwarding() // must not panic or block
}
