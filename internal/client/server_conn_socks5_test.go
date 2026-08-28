package client

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tunnelSentinel is the first payload the "server" sends after the SOCKS5
// connect reply. The whole point of the test is that the client must see it
// intact, starting at its first byte.
const tunnelSentinel = "TUNNELED-PAYLOAD"

// TestSOCKS5Connect_ShortReplyReadsDoNotCorruptTunnel is the regression guard
// for the bound-address short read.
//
// net.Conn.Read may return fewer bytes than requested. The connect reply used
// to be consumed with plain Read calls, so a fragmented reply left its tail
// unread — and those leftover bytes then surfaced as the first bytes of the
// tunneled stream. The observable symptom was an intermittent TLS handshake
// failure *after* a connect that reported success, which is why it was hard to
// attribute.
//
// The fake server here writes every field of the reply in deliberately small
// fragments, so each client-side read is short unless it loops.
func TestSOCKS5Connect_ShortReplyReadsDoNotCorruptTunnel(t *testing.T) {
	tests := []struct {
		name     string
		atyp     byte
		boundLen int
	}{
		{"ipv4 bound address", socks5AddrIPv4, socks5BoundAddrLenIPv4},
		{"ipv6 bound address", socks5AddrIPv6, socks5BoundAddrLenIPv6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()

			// Deadlines on BOTH ends. net.Pipe is unbuffered, so if the client
			// leaves reply bytes unread the server's next write blocks; without
			// a deadline there, a regression would hang the package instead of
			// failing it.
			deadline := time.Now().Add(5 * time.Second)
			require.NoError(t, clientConn.SetDeadline(deadline))
			require.NoError(t, serverConn.SetDeadline(deadline))

			serverErr := make(chan error, 1)
			go func() {
				defer serverConn.Close()
				serverErr <- runFragmentedSOCKS5Server(serverConn, tt.atyp, tt.boundLen)
			}()

			s := NewServerConnection(ServerConnectionConfig{
				Address:  "server.invalid:1080",
				Protocol: "socks5",
			})

			require.NoError(t, s.socks5Connect(clientConn, "example.com:443"))

			// The next bytes on the wire must be the payload, undisturbed.
			got := make([]byte, len(tunnelSentinel))
			_, err := io.ReadFull(clientConn, got)
			require.NoError(t, err)
			assert.Equal(t, tunnelSentinel, string(got),
				"leftover connect-reply bytes leaked into the tunneled stream")

			// Never block on the server: on a regression its final write is
			// stuck behind bytes the client failed to consume.
			select {
			case err := <-serverErr:
				assert.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Error("fake server did not finish; the client left reply bytes unread")
			}
		})
	}
}

// TestSOCKS5Connect_RejectsUnknownAddressType asserts the connect reply's
// address type is validated. An unrecognized ATYP means the bound-address
// length is unknown, so the stream position cannot be recovered — continuing
// would hand the caller a desynchronized connection.
func TestSOCKS5Connect_RejectsUnknownAddressType(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		defer serverConn.Close()
		if err := readSOCKS5ConnectRequest(serverConn); err != nil {
			return
		}
		// Reply with a reserved ATYP value.
		_, _ = serverConn.Write([]byte{0x05, 0x00, 0x00, 0x07})
	}()

	s := NewServerConnection(ServerConnectionConfig{Protocol: "socks5"})
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))

	err := s.socks5Connect(clientConn, "example.com:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown SOCKS5 address type")
}

// TestSOCKS5Connect_TruncatedBoundAddressIsAnError asserts a reply that ends
// mid-bound-address is reported rather than silently accepted. Previously the
// read error was discarded and the function returned nil.
func TestSOCKS5Connect_TruncatedBoundAddressIsAnError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		if err := readSOCKS5ConnectRequest(serverConn); err != nil {
			serverConn.Close()
			return
		}
		// Header promises an IPv4 bound address, then only 3 of its 6 bytes
		// arrive before the connection closes.
		_, _ = serverConn.Write([]byte{0x05, 0x00, 0x00, socks5AddrIPv4})
		_, _ = serverConn.Write([]byte{10, 0, 0})
		serverConn.Close()
	}()

	s := NewServerConnection(ServerConnectionConfig{Protocol: "socks5"})
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))

	err := s.socks5Connect(clientConn, "example.com:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read bound address")
}

// runFragmentedSOCKS5Server consumes a connect request, then writes a success
// reply one or two bytes at a time, followed by the tunnel sentinel.
func runFragmentedSOCKS5Server(conn net.Conn, atyp byte, boundLen int) error {
	if err := readSOCKS5ConnectRequest(conn); err != nil {
		return err
	}

	reply := append([]byte{0x05, 0x00, 0x00, atyp}, make([]byte, boundLen)...)

	// Two bytes per write: every client read of 4 or more bytes is short.
	for i := 0; i < len(reply); i += 2 {
		end := i + 2
		if end > len(reply) {
			end = len(reply)
		}
		if _, err := conn.Write(reply[i:end]); err != nil {
			return err
		}
	}

	_, err := conn.Write([]byte(tunnelSentinel))
	return err
}

// readSOCKS5ConnectRequest consumes exactly one SOCKS5 connect request. net.Pipe
// is unbuffered, so the request must be drained before the reply is written or
// both sides block.
func readSOCKS5ConnectRequest(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	switch header[3] {
	case socks5AddrIPv4:
		_, err := io.ReadFull(conn, make([]byte, socks5BoundAddrLenIPv4))
		return err
	case socks5AddrIPv6:
		_, err := io.ReadFull(conn, make([]byte, socks5BoundAddrLenIPv6))
		return err
	case socks5AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])+socks5PortLen))
		return err
	default:
		return nil
	}
}
