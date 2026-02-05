package server

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/websocket"
)

// MaxWebSocketClients is the maximum number of concurrent WebSocket connections.
const MaxWebSocketClients = 100

// WebSocketReadTimeout is the maximum time to wait for a message from a client.
const WebSocketReadTimeout = 60 * time.Second

// WebSocketHub manages WebSocket connections.
type WebSocketHub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan []byte
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	stopCh     chan struct{}
	mu         sync.RWMutex
	maxClients int
}

// NewWebSocketHub creates a new WebSocket hub with default max clients.
func NewWebSocketHub() *WebSocketHub {
	return NewWebSocketHubWithMaxClients(MaxWebSocketClients)
}

// NewWebSocketHubWithMaxClients creates a new WebSocket hub with a custom max clients limit.
// For low-power devices (OpenWrt routers), use 5-10 to reduce memory usage.
func NewWebSocketHubWithMaxClients(maxClients int) *WebSocketHub {
	if maxClients <= 0 {
		maxClients = MaxWebSocketClients
	}
	return &WebSocketHub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
		stopCh:     make(chan struct{}),
		maxClients: maxClients,
	}
}

// Run starts the hub's main loop. Call Stop() to terminate the loop.
func (h *WebSocketHub) Run() {
	for {
		select {
		case <-h.stopCh:
			// Close all client connections on shutdown
			h.mu.Lock()
			for client := range h.clients {
				client.Close()
				delete(h.clients, client)
			}
			h.mu.Unlock()
			return

		case client := <-h.register:
			h.mu.Lock()
			// Enforce connection limit to prevent resource exhaustion
			if len(h.clients) >= h.maxClients {
				h.mu.Unlock()
				client.Close()
				continue
			}
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			// Collect failed clients while holding lock, then unregister after releasing
			// to prevent deadlock from sending to channel while holding lock
			h.mu.RLock()
			var failed []*websocket.Conn
			for client := range h.clients {
				if _, err := client.Write(message); err != nil {
					failed = append(failed, client)
				}
			}
			h.mu.RUnlock()
			// Unregister failed clients after releasing lock
			for _, client := range failed {
				h.unregister <- client
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

// ServeWS handles WebSocket connections.
func (h *WebSocketHub) ServeWS(ws *websocket.Conn) {
	h.register <- ws
	defer func() {
		h.unregister <- ws
	}()

	// Keep connection alive and read messages (for ping/pong)
	for {
		// Set read deadline to prevent connections from being held indefinitely
		_ = ws.SetReadDeadline(time.Now().Add(WebSocketReadTimeout)) //nolint:errcheck // Best effort deadline

		var msg string
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			break
		}
		// Handle ping
		if msg == "ping" {
			_ = websocket.Message.Send(ws, "pong") //nolint:errcheck // Best effort pong response
		}
	}
}

// AddWebSocketRoutes adds WebSocket routes to the router.
func (a *API) AddWebSocketRoutes(r chi.Router, hub *WebSocketHub) {
	r.Handle("/api/v1/ws", websocket.Handler(hub.ServeWS))
}

// Event types for WebSocket broadcasts
const (
	EventBackendHealth   = "backend.health"
	EventConnectionNew   = "connection.new"
	EventConnectionClose = "connection.close"
	EventConfigReload    = "config.reload"
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
