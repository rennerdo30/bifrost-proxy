package server

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/websocket"
)

// WebSocketHub manages WebSocket connections.
type WebSocketHub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan []byte
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mu         sync.RWMutex
}

// NewWebSocketHub creates a new WebSocket hub.
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}
}

// Run starts the hub's main loop.
func (h *WebSocketHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
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
			h.mu.RLock()
			for client := range h.clients {
				if _, err := client.Write(message); err != nil {
					h.unregister <- client
				}
			}
			h.mu.RUnlock()
		}
	}
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
		var msg string
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			break
		}
		// Handle ping
		if msg == "ping" {
			websocket.Message.Send(ws, "pong")
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
