package backend

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// tuningTestNetwork returns a non-zero NetworkTuning for assertions.
func tuningTestNetwork() NetworkTuning {
	return NetworkTuning{
		KeepAlive:     45 * time.Second,
		DialTimeout:   12 * time.Second,
		PreferIPv6:    true,
		AddressFamily: "tcp6",
	}
}

// assertOpenVPNDelegateTuned type-asserts the delegate to *OpenVPNBackend and
// verifies the leak-proof routing flag and network tuning were threaded through.
func assertOpenVPNDelegateTuned(t *testing.T, delegate Backend, wantNet NetworkTuning) {
	t.Helper()
	ovpn, ok := delegate.(*OpenVPNBackend)
	require.True(t, ok, "delegate must be *OpenVPNBackend")
	assert.True(t, ovpn.config.LeakProofRouting, "leak_proof_routing must propagate to the OpenVPN delegate")
	assert.Equal(t, wantNet, ovpn.config.Network, "network tuning must propagate to the OpenVPN delegate")
}

func nordOpenVPNServer() *vpnprovider.Server {
	return &vpnprovider.Server{
		Hostname:    "de123.nordvpn.com",
		CountryCode: "DE",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "de123.nordvpn.com",
			UDPPort:  1194,
		},
	}
}

// TestNordVPN_OpenVPNDelegate_PropagatesTuning verifies finding 3/5 for NordVPN:
// network tuning and leak_proof_routing reach the OpenVPN delegate.
func TestNordVPN_OpenVPNDelegate_PropagatesTuning(t *testing.T) {
	net := tuningTestNetwork()
	b := NewNordVPNBackend(NordVPNConfig{
		Name:             "nord-ovpn",
		Protocol:         "openvpn",
		Username:         "u",
		Password:         "p",
		CACert:           nordTestCAPEM(t),
		LeakProofRouting: true,
		Network:          net,
	})

	delegate, err := b.buildDelegate(context.Background(), nordOpenVPNServer(), vpnprovider.Credentials{
		Username: "u",
		Password: "p",
		CACert:   nordTestCAPEM(t),
	})
	require.NoError(t, err)
	assertOpenVPNDelegateTuned(t, delegate, net)
}

// TestPIA_OpenVPNDelegate_PropagatesTuning verifies finding 3/5 for PIA.
func TestPIA_OpenVPNDelegate_PropagatesTuning(t *testing.T) {
	net := tuningTestNetwork()
	b := NewPIABackend(PIAConfig{
		Name:             "pia-ovpn",
		Protocol:         "openvpn",
		Username:         "u",
		Password:         "p",
		LeakProofRouting: true,
		Network:          net,
	})

	server := &vpnprovider.Server{
		ID:       "us-east",
		Hostname: "us-east.pia.com",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "us-east.pia.com",
			UDPPort:  1198,
		},
	}

	delegate, _, err := b.buildDelegate(context.Background(), server, vpnprovider.Credentials{
		Username: "u",
		Password: "p",
	})
	require.NoError(t, err)
	assertOpenVPNDelegateTuned(t, delegate, net)
}

// TestProtonVPN_OpenVPNDelegate_PropagatesTuning verifies finding 3/5 for
// ProtonVPN.
func TestProtonVPN_OpenVPNDelegate_PropagatesTuning(t *testing.T) {
	net := tuningTestNetwork()
	b := NewProtonVPNBackend(ProtonVPNConfig{
		Name:             "proton-ovpn",
		AuthMode:         "manual",
		Protocol:         "openvpn",
		Username:         "u",
		Password:         "p",
		LeakProofRouting: true,
		Network:          net,
	})

	server := &vpnprovider.Server{
		Name:     "PROTON#1",
		Hostname: "node-de-01.protonvpn.net",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "node-de-01.protonvpn.net",
			UDPPort:  1194,
		},
	}

	delegate, err := b.buildDelegate(context.Background(), server, vpnprovider.Credentials{
		Username: "u",
		Password: "p",
	})
	require.NoError(t, err)
	assertOpenVPNDelegateTuned(t, delegate, net)
}

// TestMullvad_OpenVPNDelegate_PropagatesTuning verifies finding 3/5 for Mullvad.
func TestMullvad_OpenVPNDelegate_PropagatesTuning(t *testing.T) {
	net := tuningTestNetwork()
	b := NewMullvadBackend(MullvadConfig{
		Name:             "mullvad-ovpn",
		Protocol:         "openvpn",
		AccountID:        "0000000000000000",
		LeakProofRouting: true,
		Network:          net,
	}, createMullvadTestClient())

	server := &vpnprovider.Server{
		Hostname: "de1-wireguard",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "de1.mullvad.net",
			UDPPort:  1194,
		},
	}

	delegate, err := b.buildDelegate(context.Background(), server, vpnprovider.Credentials{
		AccountID: "0000000000000000",
	})
	require.NoError(t, err)
	assertOpenVPNDelegateTuned(t, delegate, net)
}
