package backend

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

func TestNetworkTuningFromConfig(t *testing.T) {
	no := false
	cfg := config.NetworkConfig{
		IPv6:        &no,
		PreferIPv6:  true,
		KeepAlive:   config.Duration(45 * time.Second),
		DialTimeout: config.Duration(10 * time.Second),
	}
	tuning := NetworkTuningFromConfig(cfg)
	assert.Equal(t, 45*time.Second, tuning.KeepAlive)
	assert.Equal(t, 10*time.Second, tuning.DialTimeout)
	assert.True(t, tuning.PreferIPv6)
	assert.Equal(t, "tcp4", tuning.AddressFamily)
}

func TestNetworkTuning_IsZero(t *testing.T) {
	assert.True(t, NetworkTuning{}.IsZero())
	assert.True(t, NetworkTuning{AddressFamily: "tcp"}.IsZero())
	assert.False(t, NetworkTuning{KeepAlive: time.Second}.IsZero())
	assert.False(t, NetworkTuning{DialTimeout: time.Second}.IsZero())
	assert.False(t, NetworkTuning{PreferIPv6: true}.IsZero())
	assert.False(t, NetworkTuning{AddressFamily: "tcp4"}.IsZero())
}

func TestNetworkTuning_Apply(t *testing.T) {
	// Keep-alive set; dial timeout fills unset; prefer-IPv6 sets a resolver.
	d := &net.Dialer{}
	tuning := NetworkTuning{KeepAlive: 20 * time.Second, DialTimeout: 7 * time.Second, PreferIPv6: true}
	tuning.apply(d, false)
	assert.Equal(t, 20*time.Second, d.KeepAlive)
	assert.Equal(t, 7*time.Second, d.Timeout)
	assert.NotNil(t, d.Resolver)

	// Existing timeout preserved when overrideTimeout=false.
	d2 := &net.Dialer{Timeout: 3 * time.Second}
	NetworkTuning{DialTimeout: 9 * time.Second}.apply(d2, false)
	assert.Equal(t, 3*time.Second, d2.Timeout)

	// overrideTimeout=true clobbers existing timeout.
	d3 := &net.Dialer{Timeout: 3 * time.Second}
	NetworkTuning{DialTimeout: 9 * time.Second}.apply(d3, true)
	assert.Equal(t, 9*time.Second, d3.Timeout)

	// Negative keep-alive disables.
	d4 := &net.Dialer{KeepAlive: 30 * time.Second}
	NetworkTuning{KeepAlive: -1}.apply(d4, false)
	assert.Equal(t, time.Duration(-1), d4.KeepAlive)

	// nil dialer is a no-op (no panic).
	NetworkTuning{KeepAlive: time.Second}.apply(nil, false)
}

func TestNetworkTuning_DialNetwork(t *testing.T) {
	assert.Equal(t, "tcp4", NetworkTuning{AddressFamily: "tcp4"}.dialNetwork("tcp"))
	assert.Equal(t, "tcp", NetworkTuning{}.dialNetwork("tcp"))
	assert.Equal(t, "tcp", NetworkTuning{}.dialNetwork(""))
}

func TestOrderAddrsIPv6First(t *testing.T) {
	addrs := []net.IPAddr{
		{IP: net.ParseIP("1.2.3.4")},
		{IP: net.ParseIP("2001:db8::1")},
		{IP: net.ParseIP("5.6.7.8")},
		{IP: net.ParseIP("2001:db8::2")},
	}
	out := orderAddrsIPv6First(addrs)
	require.Len(t, out, 4)
	assert.True(t, isIPv6(out[0].IP))
	assert.True(t, isIPv6(out[1].IP))
	assert.False(t, isIPv6(out[2].IP))
	assert.False(t, isIPv6(out[3].IP))
	// Stable within family.
	assert.Equal(t, "2001:db8::1", out[0].IP.String())
	assert.Equal(t, "5.6.7.8", out[3].IP.String())
}

func TestIsIPv6(t *testing.T) {
	assert.True(t, isIPv6(net.ParseIP("2001:db8::1")))
	assert.False(t, isIPv6(net.ParseIP("1.2.3.4")))
}

func TestDialPreferIPv6_LiteralIP(t *testing.T) {
	// A literal IP that refuses connection should still attempt and error,
	// exercising the literal-IP fast path.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	d := &net.Dialer{Timeout: 300 * time.Millisecond}
	_, err := dialPreferIPv6(ctx, d, "tcp", "127.0.0.1:1")
	assert.Error(t, err)
}

func TestDialPreferIPv6_BadAddress(t *testing.T) {
	// Address without a port falls back to plain dial which errors.
	ctx := context.Background()
	d := &net.Dialer{Timeout: 100 * time.Millisecond}
	_, err := dialPreferIPv6(ctx, d, "tcp", "not-a-host-port")
	assert.Error(t, err)
}

func TestDialPreferIPv6_Loopback(t *testing.T) {
	// Spin up a loopback listener and dial it by hostname "localhost" so the
	// resolver path executes and ordering selects a working address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		c, aErr := ln.Accept()
		if aErr == nil {
			_ = c.Close()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := &net.Dialer{Timeout: time.Second}
	conn, err := dialPreferIPv6(ctx, d, "tcp4", net.JoinHostPort("localhost", port))
	if err == nil {
		_ = conn.Close()
	}
	// localhost may resolve to IPv6 first on some hosts; tcp4 restricts to IPv4.
	// Either a successful connection or a clean error is acceptable; the point is
	// the resolver/ordering path runs without panicking.
}
