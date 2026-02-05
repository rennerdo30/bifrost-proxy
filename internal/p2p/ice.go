package p2p

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// logSetDeadlineError logs SetDeadline errors appropriately based on error type.
func logSetDeadlineError(context string, err error) {
	if err == nil {
		return
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		slog.Debug("failed to set deadline", "context", context, "error", err)
	} else {
		slog.Warn("failed to set deadline", "context", context, "error", err)
	}
}

// CandidateType represents the type of ICE candidate.
type CandidateType int

const (
	// CandidateTypeHost is a local interface address.
	CandidateTypeHost CandidateType = iota

	// CandidateTypeServerReflexive is an address discovered via STUN.
	CandidateTypeServerReflexive

	// CandidateTypePeerReflexive is an address discovered during connectivity checks.
	CandidateTypePeerReflexive

	// CandidateTypeRelay is a TURN relay address.
	CandidateTypeRelay
)

// String returns a human-readable string for the candidate type.
func (t CandidateType) String() string {
	switch t {
	case CandidateTypeHost:
		return "host"
	case CandidateTypeServerReflexive:
		return "srflx"
	case CandidateTypePeerReflexive:
		return "prflx"
	case CandidateTypeRelay:
		return "relay"
	default:
		return "unknown"
	}
}

// Candidate represents an ICE candidate.
type Candidate struct {
	// Type is the candidate type.
	Type CandidateType `json:"type"`

	// Address is the candidate address.
	Address netip.AddrPort `json:"address"`

	// Base is the local address associated with this candidate.
	Base netip.AddrPort `json:"base,omitempty"`

	// Priority is the candidate priority (higher is better).
	Priority uint32 `json:"priority"`

	// Foundation is used for candidate pruning.
	Foundation string `json:"foundation,omitempty"`

	// RelatedAddress is the related address for reflexive/relay candidates.
	RelatedAddress netip.AddrPort `json:"related_address,omitempty"`
}

// CandidatePair represents a pair of local and remote candidates.
type CandidatePair struct {
	Local    *Candidate
	Remote   *Candidate
	Priority uint64
	State    PairState
	RTT      time.Duration
}

// PairState represents the state of a candidate pair.
type PairState int

const (
	PairStateWaiting PairState = iota
	PairStateInProgress
	PairStateSucceeded
	PairStateFailed
)

// ICEAgent manages ICE candidate gathering and connectivity checks.
type ICEAgent struct {
	stunClient *STUNClient
	turnClient *TURNClient
	natDetector *NATDetector

	localCandidates  []*Candidate
	remoteCandidates []*Candidate
	candidatePairs   []*CandidatePair
	selectedPair     *CandidatePair

	conn           net.PacketConn
	localAddr      netip.AddrPort
	gatherComplete bool

	onCandidate   func(*Candidate)
	onConnected   func(*CandidatePair)

	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
}

// ICEConfig contains ICE agent configuration.
type ICEConfig struct {
	STUNServers []string
	TURNConfig  *TURNConfig
	Timeout     time.Duration
}

// Common ICE errors.
var (
	ErrICEGatheringFailed = errors.New("ice: candidate gathering failed")
	ErrICENoValidPair     = errors.New("ice: no valid candidate pair found")
	ErrICENotConnected    = errors.New("ice: not connected")
)

// NewICEAgent creates a new ICE agent.
func NewICEAgent(config ICEConfig) *ICEAgent {
	return &ICEAgent{
		stunClient:       NewSTUNClient(config.STUNServers, config.Timeout),
		localCandidates:  make([]*Candidate, 0),
		remoteCandidates: make([]*Candidate, 0),
		candidatePairs:   make([]*CandidatePair, 0),
	}
}

// GatherCandidates gathers all local candidates.
func (a *ICEAgent) GatherCandidates(ctx context.Context) error {
	a.mu.Lock()
	a.ctx, a.cancel = context.WithCancel(ctx)
	a.mu.Unlock()

	// Create UDP socket
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	a.conn = conn

	localUDPAddr := conn.LocalAddr().(*net.UDPAddr)
	a.localAddr = netip.AddrPortFrom(
		netip.MustParseAddr(localUDPAddr.IP.String()),
		uint16(localUDPAddr.Port),
	)

	// Gather host candidates
	if err := a.gatherHostCandidates(); err != nil {
		slog.Warn("failed to gather host candidates", "error", err)
	}

	// Gather server reflexive candidates via STUN
	if err := a.gatherServerReflexiveCandidates(ctx); err != nil {
		slog.Warn("failed to gather server reflexive candidates", "error", err)
	}

	// Gather relay candidates via TURN
	if a.turnClient != nil {
		if err := a.gatherRelayCandidates(ctx); err != nil {
			slog.Warn("failed to gather relay candidates", "error", err)
		}
	}

	a.mu.Lock()
	a.gatherComplete = true
	a.mu.Unlock()

	if len(a.localCandidates) == 0 {
		return ErrICEGatheringFailed
	}

	return nil
}

// gatherHostCandidates discovers local interface addresses.
func (a *ICEAgent) gatherHostCandidates() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip loopback and link-local
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			// Convert to netip
			netipAddr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}

			candidate := &Candidate{
				Type:     CandidateTypeHost,
				Address:  netip.AddrPortFrom(netipAddr, a.localAddr.Port()),
				Priority: calculatePriority(CandidateTypeHost, 0),
			}

			a.addLocalCandidate(candidate)
		}
	}

	return nil
}

// gatherServerReflexiveCandidates discovers addresses via STUN.
func (a *ICEAgent) gatherServerReflexiveCandidates(ctx context.Context) error {
	result, err := a.stunClient.Bind(ctx)
	if err != nil {
		return err
	}

	candidate := &Candidate{
		Type:           CandidateTypeServerReflexive,
		Address:        result.MappedAddress,
		Base:           a.localAddr,
		Priority:       calculatePriority(CandidateTypeServerReflexive, 0),
		RelatedAddress: a.localAddr,
	}

	a.addLocalCandidate(candidate)
	return nil
}

// gatherRelayCandidates discovers addresses via TURN.
func (a *ICEAgent) gatherRelayCandidates(ctx context.Context) error {
	if err := a.turnClient.Allocate(ctx); err != nil {
		return err
	}

	relayAddr, err := a.turnClient.RelayAddress()
	if err != nil {
		return err
	}

	candidate := &Candidate{
		Type:           CandidateTypeRelay,
		Address:        relayAddr,
		Base:           a.localAddr,
		Priority:       calculatePriority(CandidateTypeRelay, 0),
		RelatedAddress: a.localAddr,
	}

	a.addLocalCandidate(candidate)
	return nil
}

// addLocalCandidate adds a local candidate.
func (a *ICEAgent) addLocalCandidate(c *Candidate) {
	a.mu.Lock()
	a.localCandidates = append(a.localCandidates, c)
	a.mu.Unlock()

	if a.onCandidate != nil {
		a.onCandidate(c)
	}

	slog.Debug("gathered candidate",
		"type", c.Type.String(),
		"address", c.Address.String(),
	)
}

// AddRemoteCandidate adds a remote candidate.
func (a *ICEAgent) AddRemoteCandidate(c *Candidate) {
	a.mu.Lock()
	a.remoteCandidates = append(a.remoteCandidates, c)
	a.mu.Unlock()

	// Create pairs with all local candidates
	a.createCandidatePairs()
}

// createCandidatePairs creates all possible candidate pairs.
func (a *ICEAgent) createCandidatePairs() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.candidatePairs = make([]*CandidatePair, 0)

	for _, local := range a.localCandidates {
		for _, remote := range a.remoteCandidates {
			// Only pair same address families
			if local.Address.Addr().Is4() != remote.Address.Addr().Is4() {
				continue
			}

			pair := &CandidatePair{
				Local:    local,
				Remote:   remote,
				Priority: calculatePairPriority(local.Priority, remote.Priority),
				State:    PairStateWaiting,
			}

			a.candidatePairs = append(a.candidatePairs, pair)
		}
	}

	// Sort by priority (descending)
	sort.Slice(a.candidatePairs, func(i, j int) bool {
		return a.candidatePairs[i].Priority > a.candidatePairs[j].Priority
	})
}

// StartConnectivityChecks starts ICE connectivity checks.
func (a *ICEAgent) StartConnectivityChecks(ctx context.Context) error {
	a.mu.Lock()
	if len(a.candidatePairs) == 0 {
		a.mu.Unlock()
		return ErrICENoValidPair
	}
	pairs := make([]*CandidatePair, len(a.candidatePairs))
	copy(pairs, a.candidatePairs)
	a.mu.Unlock()

	// Try each pair in priority order
	for _, pair := range pairs {
		if ctx.Err() != nil {
			break
		}

		success, rtt := a.checkConnectivity(ctx, pair)
		if success {
			pair.State = PairStateSucceeded
			pair.RTT = rtt

			a.mu.Lock()
			a.selectedPair = pair
			a.mu.Unlock()

			if a.onConnected != nil {
				a.onConnected(pair)
			}

			slog.Info("ICE connection established",
				"local", pair.Local.Address.String(),
				"remote", pair.Remote.Address.String(),
				"rtt", rtt,
			)

			return nil
		}

		pair.State = PairStateFailed
	}

	return ErrICENoValidPair
}

// checkConnectivity performs a connectivity check for a candidate pair.
func (a *ICEAgent) checkConnectivity(ctx context.Context, pair *CandidatePair) (bool, time.Duration) {
	pair.State = PairStateInProgress

	// Simple connectivity check: send a packet and wait for response
	// In a real implementation, this would use STUN binding requests

	conn := a.conn
	if conn == nil {
		return false, 0
	}

	// Set deadline
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		logSetDeadlineError("ICE connectivity check", err)
	}

	// Send probe
	probe := []byte("BIFROST_ICE_PROBE")
	remoteAddr := net.UDPAddrFromAddrPort(pair.Remote.Address)

	start := time.Now()

	_, err := conn.WriteTo(probe, remoteAddr)
	if err != nil {
		return false, 0
	}

	// Wait for response
	buf := make([]byte, 1024)
	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		return false, 0
	}

	rtt := time.Since(start)

	// Verify response
	if n >= len(probe) && string(buf[:len(probe)]) == "BIFROST_ICE_PROBE" {
		// Verify it came from the expected address
		fromAddr := from.(*net.UDPAddr)
		if fromAddr.IP.Equal(pair.Remote.Address.Addr().AsSlice()) {
			return true, rtt
		}
	}

	return false, 0
}

// GetLocalCandidates returns all local candidates.
func (a *ICEAgent) GetLocalCandidates() []*Candidate {
	a.mu.RLock()
	defer a.mu.RUnlock()

	candidates := make([]*Candidate, len(a.localCandidates))
	copy(candidates, a.localCandidates)
	return candidates
}

// GetSelectedPair returns the selected candidate pair.
func (a *ICEAgent) GetSelectedPair() *CandidatePair {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.selectedPair
}

// IsConnected returns whether ICE has successfully connected.
func (a *ICEAgent) IsConnected() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.selectedPair != nil && a.selectedPair.State == PairStateSucceeded
}

// Send sends data to the connected peer.
func (a *ICEAgent) Send(data []byte) error {
	a.mu.RLock()
	pair := a.selectedPair
	conn := a.conn
	a.mu.RUnlock()

	if pair == nil {
		return ErrICENotConnected
	}

	if conn == nil {
		return ErrICENotConnected
	}

	remoteAddr := net.UDPAddrFromAddrPort(pair.Remote.Address)
	_, err := conn.WriteTo(data, remoteAddr)
	return err
}

// Receive receives data from the connected peer.
func (a *ICEAgent) Receive(buf []byte) (int, error) {
	a.mu.RLock()
	pair := a.selectedPair
	conn := a.conn
	a.mu.RUnlock()

	if pair == nil {
		return 0, ErrICENotConnected
	}

	if conn == nil {
		return 0, ErrICENotConnected
	}

	n, _, err := conn.ReadFrom(buf)
	return n, err
}

// OnCandidate sets the callback for new local candidates.
func (a *ICEAgent) OnCandidate(callback func(*Candidate)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onCandidate = callback
}

// OnConnected sets the callback for successful connection.
func (a *ICEAgent) OnConnected(callback func(*CandidatePair)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onConnected = callback
}

// Close closes the ICE agent.
func (a *ICEAgent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cancel != nil {
		a.cancel()
	}

	if a.stunClient != nil {
		a.stunClient.Close()
	}

	if a.turnClient != nil {
		a.turnClient.Close()
	}

	if a.conn != nil {
		return a.conn.Close()
	}

	return nil
}

// calculatePriority calculates candidate priority per ICE spec.
func calculatePriority(candidateType CandidateType, component int) uint32 {
	var typePref uint32
	switch candidateType {
	case CandidateTypeHost:
		typePref = 126
	case CandidateTypeServerReflexive:
		typePref = 100
	case CandidateTypePeerReflexive:
		typePref = 110
	case CandidateTypeRelay:
		typePref = 0
	}

	localPref := uint32(65535) // Simplified
	componentID := uint32(1)   // Simplified

	return (typePref << 24) | (localPref << 8) | (256 - componentID)
}

// calculatePairPriority calculates candidate pair priority.
func calculatePairPriority(localPriority, remotePriority uint32) uint64 {
	// RFC 8445 formula
	var max, min uint32
	if localPriority > remotePriority {
		max = localPriority
		min = remotePriority
	} else {
		max = remotePriority
		min = localPriority
	}

	return (1 << 32) * uint64(min) + 2*uint64(max)
}
