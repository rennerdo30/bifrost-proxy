package pia

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Port-forwarding constants.
const (
	// PortForwardPort is the TCP port the PIA gateway exposes the
	// getSignature/bindPort endpoints on.
	PortForwardPort = "19999"

	// BindPortInterval is how often bindPort must be called to keep the
	// forwarded port alive. PIA recommends every 15 minutes.
	BindPortInterval = 15 * time.Minute
)

// ErrPortForwardingNotAvailable indicates port forwarding could not be set up
// because the active tunnel's gateway address or hostname is unknown. We fail
// closed in that case rather than returning a fake port.
var ErrPortForwardingNotAvailable = errors.New("pia: port forwarding gateway not available")

// PortForwardParams carries the tunnel-bound parameters required to drive the
// PIA port-forwarding API.
type PortForwardParams struct {
	// GatewayIP is the in-tunnel gateway address (the WireGuard server_vip or
	// the OpenVPN remote gateway) reachable only once the tunnel is up.
	GatewayIP string
	// Hostname is the common name (CN) the gateway's TLS certificate is issued
	// for; the connection dials GatewayIP but verifies against this name.
	Hostname string
	// Token is a valid PIA authentication token.
	Token string
}

// Validate checks that all required fields are present.
func (p PortForwardParams) Validate() error {
	if p.GatewayIP == "" || p.Hostname == "" {
		return ErrPortForwardingNotAvailable
	}
	if p.Token == "" {
		return errors.New("pia: port forwarding requires an authentication token")
	}
	return nil
}

// signedPayload is the base64-encoded, PIA-signed payload returned by
// getSignature and replayed to bindPort. The inner JSON carries the granted
// port and its expiry.
type signedPayload struct {
	Token     string    `json:"token"`
	Port      int       `json:"port"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PortForwarder runs the PIA port-forwarding lifecycle against a tunnel gateway.
type PortForwarder struct {
	httpClient *http.Client
	logger     *slog.Logger
	// baseOverride, when non-empty, replaces the "https://{hostname}:19999"
	// endpoint base. It is only set by tests to target an httptest server.
	baseOverride string
}

// endpointBase returns the URL prefix for the getSignature/bindPort endpoints.
func (pf *PortForwarder) endpointBase(hostname string) string {
	if pf.baseOverride != "" {
		return pf.baseOverride
	}
	return fmt.Sprintf("https://%s:%s", hostname, PortForwardPort)
}

// NewPortForwarder builds a PortForwarder. The TLS dialer is pinned so that
// requests to the gateway IP are verified against the PIA CA and the gateway's
// certificate CN (Hostname), mirroring PIA's reference `--resolve` behavior.
func NewPortForwarder(params PortForwardParams, logger *slog.Logger) *PortForwarder {
	if logger == nil {
		logger = slog.Default()
	}

	base := piaTLSConfig()
	tlsCfg := base.Clone()
	// Verify the cert against the gateway's CN regardless of the dialed IP.
	tlsCfg.ServerName = params.Hostname

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		// Force every connection to the in-tunnel gateway IP on the PF port,
		// while TLS still validates the configured CN.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 15 * time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort(params.GatewayIP, PortForwardPort))
		},
	}

	return &PortForwarder{
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		logger: logger,
	}
}

// newPortForwarderWithClient builds a PortForwarder around a caller-supplied
// HTTP client. It is used by tests to drive the flow against an httptest server
// without requiring the in-tunnel gateway or PIA CA.
func newPortForwarderWithClient(client *http.Client, logger *slog.Logger) *PortForwarder {
	if logger == nil {
		logger = slog.Default()
	}
	return &PortForwarder{httpClient: client, logger: logger}
}

// getSignature requests a signed port-forwarding payload from the gateway.
func (pf *PortForwarder) getSignature(ctx context.Context, params PortForwardParams) (*PayloadResponse, error) {
	// The Host is the CN; the transport rewrites the dial target to the gateway.
	endpoint := pf.endpointBase(params.Hostname) + "/getSignature"
	q := url.Values{}
	q.Set("token", params.Token)
	fullURL := endpoint + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create getSignature request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := pf.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getSignature request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read getSignature response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getSignature returned status %d: %s", resp.StatusCode, string(body))
	}

	var payload PayloadResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse getSignature response: %w", err)
	}
	if payload.Status != "OK" {
		return nil, fmt.Errorf("getSignature status %q", payload.Status)
	}
	if payload.Payload == "" || payload.Signature == "" {
		return nil, errors.New("getSignature returned empty payload/signature")
	}
	return &payload, nil
}

// bindPort (re)binds the forwarded port using a previously obtained payload and
// signature. It must be called periodically to keep the port alive.
func (pf *PortForwarder) bindPort(ctx context.Context, params PortForwardParams, payload, signature string) error {
	endpoint := pf.endpointBase(params.Hostname) + "/bindPort"
	q := url.Values{}
	q.Set("payload", payload)
	q.Set("signature", signature)
	fullURL := endpoint + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return fmt.Errorf("create bindPort request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := pf.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("bindPort request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read bindPort response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bindPort returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse bindPort response: %w", err)
	}
	if result.Status != "OK" {
		return fmt.Errorf("bindPort status %q: %s", result.Status, result.Message)
	}
	return nil
}

// decodePayload extracts the granted port and expiry from a base64 PIA payload.
func decodePayload(b64 string) (*signedPayload, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var p signedPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	if p.Port <= 0 {
		return nil, errors.New("payload contained no port")
	}
	return &p, nil
}

// Acquire performs the one-time getSignature + initial bindPort and returns the
// granted port plus the signed payload/signature needed for renewals.
func (pf *PortForwarder) Acquire(ctx context.Context, params PortForwardParams) (*PortForwardResponse, *PayloadResponse, error) {
	if err := params.Validate(); err != nil {
		return nil, nil, err
	}

	sig, err := pf.getSignature(ctx, params)
	if err != nil {
		return nil, nil, err
	}

	decoded, err := decodePayload(sig.Payload)
	if err != nil {
		return nil, nil, err
	}

	if err := pf.bindPort(ctx, params, sig.Payload, sig.Signature); err != nil {
		return nil, nil, fmt.Errorf("initial bindPort: %w", err)
	}

	pf.logger.Info("PIA port forwarding acquired",
		"port", decoded.Port,
		"expires_at", decoded.ExpiresAt,
	)

	return &PortForwardResponse{
		Status:  "OK",
		Port:    decoded.Port,
		Expires: decoded.ExpiresAt.Unix(),
	}, sig, nil
}

// Run drives the full port-forwarding lifecycle: it acquires a port, then calls
// bindPort on BindPortInterval until ctx is cancelled. The granted port is
// delivered on the returned channel exactly once (before renewals begin). Run
// blocks until ctx is done and returns the terminal error (ctx.Err() on normal
// shutdown, or the bind error that aborted renewal).
func (pf *PortForwarder) Run(ctx context.Context, params PortForwardParams, portCh chan<- int) error {
	resp, sig, err := pf.Acquire(ctx, params)
	if err != nil {
		return err
	}

	if portCh != nil {
		select {
		case portCh <- resp.Port:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	ticker := time.NewTicker(BindPortInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := pf.bindPort(ctx, params, sig.Payload, sig.Signature); err != nil {
				// A failed renewal means the port may be lost; surface the error
				// so the caller can re-acquire rather than silently leaking it.
				pf.logger.Warn("PIA bindPort renewal failed", "error", err)
				return fmt.Errorf("bindPort renewal: %w", err)
			}
			pf.logger.Debug("PIA port forwarding renewed", "port", resp.Port)
		}
	}
}

// piaPortForwardCAValid reports whether the bundled PIA CA parses. Exposed so
// tests can assert the TLS material used by the forwarder is well-formed without
// reaching the network.
func piaPortForwardCAValid() bool {
	pool := x509.NewCertPool()
	return pool.AppendCertsFromPEM([]byte(piaOpenVPNCA))
}

// pinnedTLSConfigFor returns the TLS config the forwarder would use for the
// given hostname. Exposed for testing the CN pinning behavior.
func pinnedTLSConfigFor(hostname string) *tls.Config {
	cfg := piaTLSConfig().Clone()
	cfg.ServerName = hostname
	return cfg
}
