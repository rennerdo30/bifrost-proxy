package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// DiscoveryClient handles peer discovery through the central server.
type DiscoveryClient struct {
	config    DiscoveryConfig
	networkID string
	localPeer *Peer
	registry  *PeerRegistry

	httpClient *http.Client
	wsConn     *websocket.Conn

	eventChan chan PeerEvent

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
	connected bool
}

// PeerEvent represents a peer-related event from the discovery server.
type PeerEvent struct {
	Type      string    `json:"type"` // "join", "leave", "update"
	Peer      PeerInfo  `json:"peer"`
	Timestamp time.Time `json:"timestamp"`
}

// PeerInfo is the peer information exchanged with the discovery server.
type PeerInfo struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	PublicKey string            `json:"public_key"`
	VirtualIP string            `json:"virtual_ip,omitempty"`
	Endpoints []Endpoint        `json:"endpoints,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// RegistrationRequest is sent to register with the discovery server.
type RegistrationRequest struct {
	NetworkID string   `json:"network_id"`
	Peer      PeerInfo `json:"peer"`
}

// RegistrationResponse is received from the discovery server.
type RegistrationResponse struct {
	Success   bool       `json:"success"`
	VirtualIP string     `json:"virtual_ip"`
	Message   string     `json:"message,omitempty"`
	Peers     []PeerInfo `json:"peers,omitempty"`
}

// Common discovery errors.
var (
	ErrDiscoveryNotConnected = errors.New("discovery: not connected to server")
	ErrDiscoveryFailed       = errors.New("discovery: registration failed")
	ErrDiscoveryTimeout      = errors.New("discovery: operation timed out")
)

// NewDiscoveryClient creates a new discovery client.
func NewDiscoveryClient(config DiscoveryConfig, networkID string, localPeer *Peer, registry *PeerRegistry) *DiscoveryClient {
	return &DiscoveryClient{
		config:     config,
		networkID:  networkID,
		localPeer:  localPeer,
		registry:   registry,
		eventChan:  make(chan PeerEvent, 100),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Start starts the discovery client.
func (c *DiscoveryClient) Start(ctx context.Context) error {
	c.mu.Lock()
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.mu.Unlock()

	// Register with the discovery server
	if err := c.register(); err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	// Connect WebSocket for events
	if err := c.connectWebSocket(); err != nil {
		slog.Warn("failed to connect WebSocket, will retry", "error", err)
	}

	// Start heartbeat
	c.wg.Add(1)
	go c.heartbeatLoop()

	// Start event processing
	c.wg.Add(1)
	go c.eventLoop()

	return nil
}

// Stop stops the discovery client.
func (c *DiscoveryClient) Stop() error {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()

	// Deregister from the server
	c.deregister()

	// Close WebSocket
	c.closeWebSocket()

	// Wait for goroutines
	c.wg.Wait()

	close(c.eventChan)
	return nil
}

// Events returns the channel for peer events.
func (c *DiscoveryClient) Events() <-chan PeerEvent {
	return c.eventChan
}

// register registers this peer with the discovery server.
func (c *DiscoveryClient) register() error {
	c.localPeer.mu.RLock()
	peerInfo := PeerInfo{
		ID:        c.localPeer.ID,
		Name:      c.localPeer.Name,
		PublicKey: c.localPeer.PublicKey,
		Endpoints: c.localPeer.Endpoints,
		Metadata:  c.localPeer.Metadata,
	}
	if c.localPeer.VirtualIP.IsValid() {
		peerInfo.VirtualIP = c.localPeer.VirtualIP.String()
	}
	c.localPeer.mu.RUnlock()

	req := RegistrationRequest{
		NetworkID: c.networkID,
		Peer:      peerInfo,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.buildURL("/api/v1/mesh/networks/%s/peers", c.networkID)
	httpReq, err := http.NewRequestWithContext(c.ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.config.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort error message
		return fmt.Errorf("%w: status %d: %s", ErrDiscoveryFailed, resp.StatusCode, string(body))
	}

	var regResp RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !regResp.Success {
		return fmt.Errorf("%w: %s", ErrDiscoveryFailed, regResp.Message)
	}

	slog.Info("registered with discovery server",
		"network_id", c.networkID,
		"peer_id", c.localPeer.ID,
		"virtual_ip", regResp.VirtualIP,
	)

	// Add existing peers to registry
	for _, peerInfo := range regResp.Peers {
		if peerInfo.ID == c.localPeer.ID {
			continue // Skip self
		}
		c.addPeerFromInfo(peerInfo)
	}

	return nil
}

// deregister deregisters this peer from the discovery server.
func (c *DiscoveryClient) deregister() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := c.buildURL("/api/v1/mesh/networks/%s/peers/%s", c.networkID, c.localPeer.ID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		slog.Warn("failed to create deregister request", "error", err)
		return
	}

	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Warn("failed to deregister", "error", err)
		return
	}
	resp.Body.Close()

	slog.Info("deregistered from discovery server")
}

// connectWebSocket connects to the discovery server's WebSocket for events.
func (c *DiscoveryClient) connectWebSocket() error {
	wsURL := c.buildWSURL("/api/v1/mesh/networks/%s/events", c.networkID)

	config, err := websocket.NewConfig(wsURL, "http://localhost")
	if err != nil {
		return fmt.Errorf("failed to create WebSocket config: %w", err)
	}

	if c.config.Token != "" {
		config.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	conn, err := websocket.DialConfig(config)
	if err != nil {
		return fmt.Errorf("failed to connect WebSocket: %w", err)
	}

	c.mu.Lock()
	c.wsConn = conn
	c.connected = true
	c.mu.Unlock()

	// Start WebSocket reader
	c.wg.Add(1)
	go c.wsReadLoop()

	slog.Info("connected to discovery WebSocket")
	return nil
}

// closeWebSocket closes the WebSocket connection.
func (c *DiscoveryClient) closeWebSocket() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.wsConn != nil {
		c.wsConn.Close()
		c.wsConn = nil
	}
	c.connected = false
}

// wsReadLoop reads events from the WebSocket.
func (c *DiscoveryClient) wsReadLoop() {
	defer c.wg.Done()

	for {
		c.mu.RLock()
		conn := c.wsConn
		c.mu.RUnlock()

		if conn == nil {
			return
		}

		var event PeerEvent
		err := websocket.JSON.Receive(conn, &event)
		if err != nil {
			if c.ctx.Err() != nil {
				return // Context cancelled
			}
			slog.Warn("WebSocket read error, reconnecting", "error", err)
			c.closeWebSocket()
			time.Sleep(5 * time.Second)
			if err := c.connectWebSocket(); err != nil {
				slog.Warn("failed to reconnect WebSocket", "error", err)
			}
			return
		}

		// Send event to channel
		select {
		case c.eventChan <- event:
		default:
			slog.Warn("event channel full, dropping event")
		}
	}
}

// heartbeatLoop sends periodic heartbeats to the discovery server.
func (c *DiscoveryClient) heartbeatLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.sendHeartbeat(); err != nil {
				slog.Warn("heartbeat failed", "error", err)
			}
		}
	}
}

// sendHeartbeat sends a heartbeat to the discovery server.
func (c *DiscoveryClient) sendHeartbeat() error {
	url := c.buildURL("/api/v1/mesh/networks/%s/peers/%s/heartbeat", c.networkID, c.localPeer.ID)

	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return err
	}

	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("heartbeat failed: status %d", resp.StatusCode)
	}

	return nil
}

// eventLoop processes peer events.
func (c *DiscoveryClient) eventLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case event, ok := <-c.eventChan:
			if !ok {
				return
			}
			c.handleEvent(event)
		}
	}
}

// handleEvent processes a peer event.
func (c *DiscoveryClient) handleEvent(event PeerEvent) {
	switch event.Type {
	case "join":
		c.addPeerFromInfo(event.Peer)
		slog.Info("peer joined", "peer_id", event.Peer.ID, "name", event.Peer.Name)

	case "leave":
		c.registry.Remove(event.Peer.ID)
		slog.Info("peer left", "peer_id", event.Peer.ID, "name", event.Peer.Name)

	case "update":
		c.updatePeerFromInfo(event.Peer)
		slog.Debug("peer updated", "peer_id", event.Peer.ID)
	}
}

// addPeerFromInfo adds a peer to the registry from PeerInfo.
func (c *DiscoveryClient) addPeerFromInfo(info PeerInfo) {
	peer := NewPeer(info.ID, info.Name)
	peer.PublicKey = info.PublicKey
	peer.Endpoints = info.Endpoints
	peer.Metadata = info.Metadata

	c.registry.Add(peer)
}

// updatePeerFromInfo updates a peer in the registry from PeerInfo.
func (c *DiscoveryClient) updatePeerFromInfo(info PeerInfo) {
	peer, exists := c.registry.Get(info.ID)
	if !exists {
		c.addPeerFromInfo(info)
		return
	}

	peer.mu.Lock()
	peer.Name = info.Name
	peer.PublicKey = info.PublicKey
	peer.Endpoints = info.Endpoints
	for k, v := range info.Metadata {
		peer.Metadata[k] = v
	}
	peer.mu.Unlock()
}

// ListPeers retrieves all peers from the discovery server.
func (c *DiscoveryClient) ListPeers() ([]PeerInfo, error) {
	url := c.buildURL("/api/v1/mesh/networks/%s/peers", c.networkID)

	req, err := http.NewRequestWithContext(c.ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list peers failed: status %d", resp.StatusCode)
	}

	var result struct {
		Peers []PeerInfo `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Peers, nil
}

// UpdateEndpoints updates this peer's endpoints on the discovery server.
func (c *DiscoveryClient) UpdateEndpoints(endpoints []Endpoint) error {
	c.localPeer.mu.Lock()
	c.localPeer.Endpoints = endpoints
	c.localPeer.mu.Unlock()

	body, err := json.Marshal(map[string]interface{}{
		"endpoints": endpoints,
	})
	if err != nil {
		return err
	}

	url := c.buildURL("/api/v1/mesh/networks/%s/peers/%s", c.networkID, c.localPeer.ID)

	req, err := http.NewRequestWithContext(c.ctx, "PATCH", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("update endpoints failed: status %d", resp.StatusCode)
	}

	return nil
}

// buildURL builds an HTTP URL for the discovery server.
func (c *DiscoveryClient) buildURL(format string, args ...interface{}) string {
	path := fmt.Sprintf(format, args...)
	u := url.URL{
		Scheme: "https",
		Host:   c.config.Server,
		Path:   path,
	}
	return u.String()
}

// buildWSURL builds a WebSocket URL for the discovery server.
func (c *DiscoveryClient) buildWSURL(format string, args ...interface{}) string {
	path := fmt.Sprintf(format, args...)
	u := url.URL{
		Scheme: "wss",
		Host:   c.config.Server,
		Path:   path,
	}
	return u.String()
}

// IsConnected returns whether the client is connected to the discovery server.
func (c *DiscoveryClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}
