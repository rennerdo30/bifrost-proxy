package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// localhostSuffix matches the reserved .localhost TLD (RFC 6761), which
// resolvers are required to resolve to loopback and which therefore cannot be
// pointed at another address by an attacker-controlled DNS zone.
const localhostSuffix = ".localhost"

// MaxWebSocketClients is the maximum number of concurrent WebSocket connections.
const MaxWebSocketClients = 100

// WebSocketReadTimeout bounds how long a connection may go without ANY traffic
// (application message, or a pong in reply to our keepalive ping) before it is
// considered dead. Keep it comfortably above WebSocketPingInterval.
const WebSocketReadTimeout = 60 * time.Second

// WebSocketPingInterval is how often the server sends a protocol-level ping to
// prove the peer is alive. Must be well under WebSocketReadTimeout so a healthy
// but idle connection is refreshed before the read deadline expires.
const WebSocketPingInterval = 20 * time.Second

// WebSocketWriteTimeout bounds a single broadcast write to one client, so one
// slow reader cannot stall the hub.
const WebSocketWriteTimeout = 5 * time.Second

// wsClient is one connected peer. Writes are serialized through mu because a
// broadcast and the keepalive pinger can otherwise write concurrently, which
// is not allowed on a single connection.
type wsClient struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (c *wsClient) write(ctx context.Context, msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, WebSocketWriteTimeout)
	defer cancel()
	return c.conn.Write(ctx, websocket.MessageText, msg)
}

func (c *wsClient) ping(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, WebSocketWriteTimeout)
	defer cancel()
	return c.conn.Ping(ctx)
}

func (c *wsClient) close() {
	_ = c.conn.Close(websocket.StatusNormalClosure, "") //nolint:errcheck // best effort
}

// WebSocketHub manages WebSocket connections.
type WebSocketHub struct {
	clients    map[*wsClient]bool
	broadcast  chan []byte
	register   chan *wsClient
	unregister chan *wsClient
	stopCh     chan struct{}
	mu         sync.RWMutex
	maxClients int

	// allowedOrigins are extra browser origins permitted to upgrade, on top of
	// the request's own Host which is always allowed. See SetAllowedOrigins.
	allowedOrigins []string
	// skipOriginCheck disables origin verification entirely. Only set when the
	// operator configures the explicit "*" wildcard.
	skipOriginCheck bool
}

// NewWebSocketHubWithMaxClients creates a new WebSocket hub with a custom max clients limit.
// For low-power devices (OpenWrt routers), use 5-10 to reduce memory usage.
func NewWebSocketHubWithMaxClients(maxClients int) *WebSocketHub {
	if maxClients <= 0 {
		maxClients = MaxWebSocketClients
	}
	return &WebSocketHub{
		clients:    make(map[*wsClient]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *wsClient),
		unregister: make(chan *wsClient),
		stopCh:     make(chan struct{}),
		maxClients: maxClients,
	}
}

// SetAllowedOrigins configures the operator-supplied WebSocket origin allowlist
// (api.allowed_origins). It must be called before the hub starts serving.
//
// The upgrade always accepts an Origin whose host equals the request Host, so
// the dashboard this server itself serves needs no allowlist. Entries are only
// required when a reverse proxy rewrites Host — Home Assistant Ingress being the
// case that originally caused the check to be disabled outright. Each entry is a
// host pattern or a scheme://host pattern with shell-style wildcards.
//
// A single "*" entry turns origin verification off completely and is reported by
// SkipsOriginCheck so the caller can warn about it.
// hostIsRebindSafe reports whether the request's Host header is one an attacker
// cannot forge via DNS rebinding.
//
// The Origin check alone is not sufficient. github.com/coder/websocket accepts
// any request where Origin's host equals the request Host (accept.go:239,
// strings.EqualFold), which is the same same-origin shortcut gorilla makes. An
// attacker who controls a DNS name can therefore serve a page from
// evil.example, rebind that name to this server's address, and arrive with
// Host and Origin both reading "evil.example:8080" — matching, and accepted.
// With api.token unset the route has no auth either, so the live traffic stream
// is readable by any browser that loads the attacker's page.
//
// Rebinding fundamentally requires a *name*: the attacker needs a DNS zone to
// re-point. So a Host that is a bare IP literal cannot be forged this way, and
// neither can loopback names, whose resolution is reserved. Everything else has
// to be named explicitly in api.allowed_origins, which is the same per-
// deployment grant a Host-rewriting reverse proxy already needs.
func (h *WebSocketHub) hostIsRebindSafe(reqHost string) bool {
	if reqHost == "" {
		return false
	}

	hostname := reqHost
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		hostname = h
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	// An IPv6 literal arrives bracketed when a port is present and bare when not.
	hostname = strings.TrimSuffix(strings.TrimPrefix(hostname, "["), "]")

	// IP literals are immune: there is no name for an attacker to re-point.
	if net.ParseIP(hostname) != nil {
		return true
	}
	if hostname == "localhost" || strings.HasSuffix(hostname, localhostSuffix) {
		return true
	}

	// Otherwise the operator must have named this host. Match with the same
	// semantics the library uses for Origin patterns (path.Match, lowercased) so
	// one allowed_origins entry covers both checks.
	for _, pattern := range h.allowedOrigins {
		p := pattern
		if i := strings.Index(p, "://"); i >= 0 {
			p = p[i+len("://"):]
		}
		for _, candidate := range []string{reqHost, hostname} {
			if ok, err := path.Match(strings.ToLower(p), strings.ToLower(candidate)); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func (h *WebSocketHub) SetAllowedOrigins(origins []string) {
	h.allowedOrigins = nil
	h.skipOriginCheck = false
	for _, origin := range origins {
		if origin == config.AllowedOriginsWildcard {
			h.skipOriginCheck = true
			continue
		}
		h.allowedOrigins = append(h.allowedOrigins, origin)
	}
}

// SkipsOriginCheck reports whether origin verification has been disabled via the
// "*" wildcard, so the server can log that fact at startup.
func (h *WebSocketHub) SkipsOriginCheck() bool {
	return h.skipOriginCheck
}

// Run starts the hub's main loop. Call Stop() to terminate the loop.
func (h *WebSocketHub) Run() {
	for {
		select {
		case <-h.stopCh:
			// Close all client connections on shutdown
			h.mu.Lock()
			for client := range h.clients {
				client.close()
				delete(h.clients, client)
			}
			h.mu.Unlock()
			return

		case client := <-h.register:
			h.mu.Lock()
			// Enforce connection limit to prevent resource exhaustion
			if len(h.clients) >= h.maxClients {
				h.mu.Unlock()
				client.close()
				continue
			}
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.close()
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			// Snapshot client list under lock, then write without lock
			// to avoid blocking other operations during slow writes
			h.mu.RLock()
			clients := make([]*wsClient, 0, len(h.clients))
			for client := range h.clients {
				clients = append(clients, client)
			}
			h.mu.RUnlock()

			var failed []*wsClient
			for _, client := range clients {
				if err := client.write(context.Background(), message); err != nil {
					failed = append(failed, client)
				}
			}
			// Remove failed clients directly instead of sending to unregister channel,
			// which would deadlock since this goroutine is the only reader
			if len(failed) > 0 {
				h.mu.Lock()
				for _, client := range failed {
					if _, ok := h.clients[client]; ok {
						delete(h.clients, client)
						client.close()
					}
				}
				h.mu.Unlock()
			}
		}
	}
}

// Stop signals the hub to stop and close all connections.
func (h *WebSocketHub) Stop() {
	close(h.stopCh)
}

// Broadcast sends a message to all connected clients.
func (h *WebSocketHub) Broadcast(eventType string, data interface{}) {
	msg := map[string]interface{}{
		"type":      eventType,
		"timestamp": time.Now().Format(time.RFC3339),
		"data":      data,
	}
	if jsonData, err := json.Marshal(msg); err == nil {
		h.broadcast <- jsonData
	}
}

// ServeHTTP upgrades the request and services the connection until it dies.
//
// ⚠ This used to use golang.org/x/net/websocket, which that package's own docs
// describe as having "limited support for pings, pongs and close frames". Any
// peer that sent a protocol-level ping — notably the Home Assistant Ingress
// proxy, and every browser-side keepalive — desynchronised the frame stream and
// the client aborted with "RSV1 set / reserved bits must be 0". The old code
// also only understood a literal text message "ping", which no standard client
// sends. Migrated to github.com/coder/websocket (the successor x/net/websocket
// itself points at), which handles control frames in the library.
//
// Origin enforcement: WebSockets are exempt from both the same-origin policy and
// CORS, so without an Origin check any web page loaded in a browser that can
// reach this server could open a socket and read the live traffic stream — and
// when no api.token is configured this route has no auth either. Requests whose
// Origin host matches the request Host are always accepted (the dashboard this
// server serves); anything else must be named in api.allowed_origins. Requests
// with no Origin header at all are accepted, because non-browser clients (the
// CLI, curl, integration tests) do not send one and are not subject to the
// browser-driven attack this check defends against.
func (h *WebSocketHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Guard the same-Host shortcut the library grants, which is otherwise
	// forgeable by DNS rebinding. Skipped only when the operator has explicitly
	// opted out with api.allowed_origins: ["*"].
	if !h.skipOriginCheck && !h.hostIsRebindSafe(r.Host) {
		slog.Warn("rejected WebSocket upgrade: request Host is neither an IP literal, "+
			"a loopback name, nor listed in api.allowed_origins; add it there to allow this host",
			"host", r.Host)
		http.Error(w, "forbidden: Host not permitted for WebSocket upgrade", http.StatusForbidden)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// OriginPatterns extends the implicit same-Host rule. A reverse proxy that
		// rewrites Host (Home Assistant Ingress being the case that originally
		// caused this check to be turned off wholesale) needs its public origin
		// listed in api.allowed_origins — an explicit, per-deployment grant
		// instead of a blanket bypass.
		OriginPatterns: h.allowedOrigins,
		// Only ever true when the operator sets api.allowed_origins: ["*"], which
		// the server logs a warning about at startup.
		InsecureSkipVerify: h.skipOriginCheck,
		// Compression is negotiated per-connection; leaving it at the default
		// avoids emitting RSV1-compressed frames to peers that did not agree.
	})
	if err != nil {
		return // Accept already wrote the error response (403 on origin failure)
	}

	client := &wsClient{conn: conn}
	h.register <- client
	defer func() { h.unregister <- client }()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Keepalive: a protocol ping every WebSocketPingInterval. The library
	// answers peer pings automatically, and Ping() waits for the matching pong,
	// so a dead peer surfaces here rather than hanging until the read deadline.
	go func() {
		t := time.NewTicker(WebSocketPingInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := client.ping(ctx); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	for {
		readCtx, readCancel := context.WithTimeout(ctx, WebSocketReadTimeout)
		typ, msg, err := conn.Read(readCtx)
		readCancel()
		if err != nil {
			if errors.Is(err, context.Canceled) || websocket.CloseStatus(err) != -1 {
				return
			}
			return
		}
		// Backwards compatibility: older clients emulate keepalive with a
		// literal "ping" text message rather than a control frame.
		if typ == websocket.MessageText && string(msg) == "ping" {
			_ = client.write(ctx, []byte("pong")) //nolint:errcheck // best effort
		}
	}
}

// Event types for WebSocket broadcasts
const (
	EventBackendHealth   = "backend.health"
	EventConnectionNew   = "connection.new"
	EventConnectionClose = "connection.close"
	EventConfigReload    = "config.reload"
	EventConfigSaved     = "config.saved"
	EventStats           = "stats.update"
)

// BackendHealthEvent represents a backend health change event.
type BackendHealthEvent struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
}

// ConnectionEvent represents a connection event.
type ConnectionEvent struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Backend  string `json:"backend"`
	ClientIP string `json:"client_ip"`
}

// StatsEvent represents a stats update event.
type StatsEvent struct {
	ActiveConnections int64 `json:"active_connections"`
	TotalConnections  int64 `json:"total_connections"`
	BytesSent         int64 `json:"bytes_sent"`
	BytesReceived     int64 `json:"bytes_received"`
}
