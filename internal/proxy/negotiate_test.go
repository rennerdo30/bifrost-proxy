package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

func TestIsNegotiateScheme(t *testing.T) {
	assert.True(t, isNegotiateScheme("Negotiate YII..."))
	assert.True(t, isNegotiateScheme("NTLM TlRMTVNT..."))
	assert.True(t, isNegotiateScheme("negotiate abc"))
	assert.False(t, isNegotiateScheme("Basic dXNlcjpwYXNz"))
	assert.False(t, isNegotiateScheme("Bearer token"))
	assert.False(t, isNegotiateScheme(""))
}

// TestHTTPHandler_NegotiateChallenge verifies the proxy emits a 407 with the
// Proxy-Authenticate challenge header when the negotiate hook requests a
// challenge.
func TestHTTPHandler_NegotiateChallenge(t *testing.T) {
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:   func(_, _ string) backend.Backend { return nil },
		AuthRequired: true,
		NegotiateAuth: func(_ context.Context, _ *http.Request) (*NegotiateResult, error) {
			return &NegotiateResult{
				Challenge:       true,
				ChallengeStatus: http.StatusProxyAuthRequired,
				ChallengeHeaders: map[string]string{
					"Proxy-Authenticate": "NTLM TlRMTVNTUAAC",
				},
			}, nil
		},
	})

	clientConn, serverConn := net.Pipe()
	go handler.ServeConn(context.Background(), serverConn)

	req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: NTLM TlRMTVNTUAAB\r\n\r\n"
	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err := clientConn.Write([]byte(req))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	assert.Equal(t, "NTLM TlRMTVNTUAAC", resp.Header.Get("Proxy-Authenticate"))
	clientConn.Close()
}

// TestHTTPHandler_NegotiateSuccess verifies that a successful negotiate result
// allows the request to proceed (reaching backend selection).
func TestHTTPHandler_NegotiateSuccess(t *testing.T) {
	direct := backend.NewDirectBackend(backend.DirectConfig{Name: "direct"})
	require.NoError(t, direct.Start(context.Background()))
	defer direct.Stop(context.Background())

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer upstream.Close()
	go func() {
		for {
			c, aerr := upstream.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:   func(_, _ string) backend.Backend { return direct },
		AuthRequired: true,
		DialTimeout:  3 * time.Second,
		NegotiateAuth: func(_ context.Context, _ *http.Request) (*NegotiateResult, error) {
			return &NegotiateResult{UserInfo: &auth.UserInfo{Username: "alice"}}, nil
		},
	})

	clientConn, serverConn := net.Pipe()
	go handler.ServeConn(context.Background(), serverConn)

	target := upstream.Addr().String()
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Authorization: Negotiate YIIabc\r\n\r\n"
	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = clientConn.Write([]byte(req))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	clientConn.Close()
}
