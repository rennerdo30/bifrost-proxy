package pia

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encodePayload(t *testing.T, p signedPayload) string {
	t.Helper()
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

func TestPortForwardParams_Validate(t *testing.T) {
	assert.ErrorIs(t, PortForwardParams{}.Validate(), ErrPortForwardingNotAvailable)
	assert.ErrorIs(t, PortForwardParams{GatewayIP: "10.0.0.1"}.Validate(), ErrPortForwardingNotAvailable)
	// Has gateway+hostname but no token.
	err := PortForwardParams{GatewayIP: "10.0.0.1", Hostname: "cn"}.Validate()
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrPortForwardingNotAvailable)
	// Complete.
	assert.NoError(t, PortForwardParams{GatewayIP: "10.0.0.1", Hostname: "cn", Token: "t"}.Validate())
}

func TestDecodePayload(t *testing.T) {
	p := signedPayload{Token: "t", Port: 51234, ExpiresAt: time.Now().Add(time.Hour)}
	decoded, err := decodePayload(encodePayload(t, p))
	require.NoError(t, err)
	assert.Equal(t, 51234, decoded.Port)
	assert.Equal(t, "t", decoded.Token)
}

func TestDecodePayload_Invalid(t *testing.T) {
	_, err := decodePayload("!!!not-base64")
	assert.Error(t, err)

	_, err = decodePayload(base64.StdEncoding.EncodeToString([]byte("not json")))
	assert.Error(t, err)

	// Valid JSON but no port.
	_, err = decodePayload(base64.StdEncoding.EncodeToString([]byte(`{"port":0}`)))
	assert.Error(t, err)
}

// pfTestServer starts an httptest server emulating the PIA gateway PF API
// (cleaned up via t.Cleanup) and returns a PortForwarder wired to it.
func pfTestServer(t *testing.T, handler http.HandlerFunc) *PortForwarder {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	pf := newPortForwarderWithClient(srv.Client(), nil)
	pf.baseOverride = srv.URL
	return pf
}

func TestPortForwarder_Acquire(t *testing.T) {
	payload := encodePayload(t, signedPayload{Token: "t", Port: 40001, ExpiresAt: time.Now().Add(2 * time.Hour)})

	var bound atomic.Bool
	pf := pfTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/getSignature":
			assert.Equal(t, "tok", r.URL.Query().Get("token"))
			_ = json.NewEncoder(w).Encode(PayloadResponse{Status: "OK", Payload: payload, Signature: "sig"})
		case "/bindPort":
			assert.Equal(t, payload, r.URL.Query().Get("payload"))
			assert.Equal(t, "sig", r.URL.Query().Get("signature"))
			bound.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK", "message": "port scheduled for add"})
		default:
			http.NotFound(w, r)
		}
	})

	params := PortForwardParams{GatewayIP: "10.0.0.1", Hostname: "cn.example", Token: "tok"}
	resp, sig, err := pf.Acquire(context.Background(), params)
	require.NoError(t, err)
	assert.Equal(t, 40001, resp.Port)
	assert.Equal(t, "OK", resp.Status)
	assert.Equal(t, payload, sig.Payload)
	assert.True(t, bound.Load())
}

func TestPortForwarder_Acquire_ValidationFails(t *testing.T) {
	pf := newPortForwarderWithClient(http.DefaultClient, nil)
	_, _, err := pf.Acquire(context.Background(), PortForwardParams{})
	assert.ErrorIs(t, err, ErrPortForwardingNotAvailable)
}

func TestPortForwarder_GetSignature_NonOK(t *testing.T) {
	pf := pfTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied"))
	})
	params := PortForwardParams{GatewayIP: "10.0.0.1", Hostname: "cn", Token: "t"}
	_, _, err := pf.Acquire(context.Background(), params)
	assert.Error(t, err)
}

func TestPortForwarder_GetSignature_StatusNotOK(t *testing.T) {
	pf := pfTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(PayloadResponse{Status: "ERROR"})
	})
	params := PortForwardParams{GatewayIP: "10.0.0.1", Hostname: "cn", Token: "t"}
	_, _, err := pf.Acquire(context.Background(), params)
	assert.Error(t, err)
}

func TestPortForwarder_BindPort_StatusNotOK(t *testing.T) {
	payload := encodePayload(t, signedPayload{Port: 1234, ExpiresAt: time.Now().Add(time.Hour)})
	pf := pfTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/getSignature" {
			_ = json.NewEncoder(w).Encode(PayloadResponse{Status: "OK", Payload: payload, Signature: "s"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ERROR", "message": "bad signature"})
	})
	params := PortForwardParams{GatewayIP: "10.0.0.1", Hostname: "cn", Token: "t"}
	_, _, err := pf.Acquire(context.Background(), params)
	assert.Error(t, err)
}

func TestPortForwarder_Run_DeliversPortAndStops(t *testing.T) {
	payload := encodePayload(t, signedPayload{Port: 55555, ExpiresAt: time.Now().Add(time.Hour)})
	pf := pfTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/getSignature" {
			_ = json.NewEncoder(w).Encode(PayloadResponse{Status: "OK", Payload: payload, Signature: "s"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
	})

	params := PortForwardParams{GatewayIP: "10.0.0.1", Hostname: "cn", Token: "t"}
	portCh := make(chan int, 1)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- pf.Run(ctx, params, portCh) }()

	select {
	case port := <-portCh:
		assert.Equal(t, 55555, port)
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive port")
	}

	cancel()
	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestPortForwarder_Run_AcquireError(t *testing.T) {
	pf := newPortForwarderWithClient(http.DefaultClient, nil)
	err := pf.Run(context.Background(), PortForwardParams{}, nil)
	assert.ErrorIs(t, err, ErrPortForwardingNotAvailable)
}

func TestPIACAValid(t *testing.T) {
	assert.True(t, piaPortForwardCAValid())
}

func TestPinnedTLSConfigFor(t *testing.T) {
	cfg := pinnedTLSConfigFor("us-east.privacy.network")
	assert.Equal(t, "us-east.privacy.network", cfg.ServerName)
	assert.NotNil(t, cfg.RootCAs)
}

func TestNewPortForwarder_PinsServerName(t *testing.T) {
	params := PortForwardParams{GatewayIP: "10.0.0.1", Hostname: "cn.example", Token: "t"}
	pf := NewPortForwarder(params, nil)
	tr, ok := pf.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, "cn.example", tr.TLSClientConfig.ServerName)
	assert.NotNil(t, tr.DialContext)
}

func TestTokenManager_RequestPortForward_FailsClosed(t *testing.T) {
	tm := NewTokenManager("u", "p", nil, nil)
	_, err := tm.RequestPortForward(context.Background())
	assert.ErrorIs(t, err, ErrPortForwardingNotAvailable)
}

func TestTokenManager_RequestPortForwardParams_Validation(t *testing.T) {
	tm := NewTokenManager("u", "p", nil, nil)
	// Token provided so no network token fetch; missing gateway -> fail closed.
	_, err := tm.RequestPortForwardParams(context.Background(),
		PortForwardParams{Token: "t"})
	assert.ErrorIs(t, err, ErrPortForwardingNotAvailable)
}
