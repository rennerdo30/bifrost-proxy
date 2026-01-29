package p2p

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCandidateType_String(t *testing.T) {
	tests := []struct {
		name     string
		ct       CandidateType
		expected string
	}{
		{"Host", CandidateTypeHost, "host"},
		{"ServerReflexive", CandidateTypeServerReflexive, "srflx"},
		{"PeerReflexive", CandidateTypePeerReflexive, "prflx"},
		{"Relay", CandidateTypeRelay, "relay"},
		{"Unknown", CandidateType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ct.String())
		})
	}
}

func TestCalculatePriority(t *testing.T) {
	tests := []struct {
		name          string
		candidateType CandidateType
		component     int
	}{
		{"Host", CandidateTypeHost, 0},
		{"ServerReflexive", CandidateTypeServerReflexive, 0},
		{"PeerReflexive", CandidateTypePeerReflexive, 0},
		{"Relay", CandidateTypeRelay, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priority := calculatePriority(tt.candidateType, tt.component)
			assert.Greater(t, priority, uint32(0))

			// Host should have highest priority, relay lowest
			if tt.candidateType == CandidateTypeHost {
				relayPriority := calculatePriority(CandidateTypeRelay, 0)
				assert.Greater(t, priority, relayPriority)
			}
		})
	}
}

func TestCalculatePriority_Ordering(t *testing.T) {
	hostPriority := calculatePriority(CandidateTypeHost, 0)
	prflxPriority := calculatePriority(CandidateTypePeerReflexive, 0)
	srflxPriority := calculatePriority(CandidateTypeServerReflexive, 0)
	relayPriority := calculatePriority(CandidateTypeRelay, 0)

	// Verify priority ordering: host > prflx > srflx > relay
	assert.Greater(t, hostPriority, prflxPriority)
	assert.Greater(t, prflxPriority, srflxPriority)
	assert.Greater(t, srflxPriority, relayPriority)
}

func TestCalculatePairPriority(t *testing.T) {
	tests := []struct {
		name          string
		localPriority uint32
		remotePriority uint32
	}{
		{"Equal priorities", 1000, 1000},
		{"Local higher", 2000, 1000},
		{"Remote higher", 1000, 2000},
		{"Max values", 0xFFFFFFFF, 0xFFFFFFFF},
		{"Zero values", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priority := calculatePairPriority(tt.localPriority, tt.remotePriority)

			// Priority should be deterministic
			priority2 := calculatePairPriority(tt.localPriority, tt.remotePriority)
			assert.Equal(t, priority, priority2)

			// Order shouldn't matter (symmetric)
			prioritySwapped := calculatePairPriority(tt.remotePriority, tt.localPriority)
			assert.Equal(t, priority, prioritySwapped)
		})
	}
}

func TestCalculatePairPriority_HigherPrioritiesProduceHigherResult(t *testing.T) {
	lowPriority := calculatePairPriority(100, 100)
	highPriority := calculatePairPriority(1000, 1000)

	assert.Greater(t, highPriority, lowPriority)
}

func TestNewICEAgent(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)
	require.NotNil(t, agent)
	assert.NotNil(t, agent.stunClient)
	assert.NotNil(t, agent.localCandidates)
	assert.NotNil(t, agent.remoteCandidates)
	assert.NotNil(t, agent.candidatePairs)
	assert.Empty(t, agent.localCandidates)
	assert.Empty(t, agent.remoteCandidates)
	assert.Empty(t, agent.candidatePairs)
}

func TestICEAgent_GetLocalCandidates_Empty(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)
	candidates := agent.GetLocalCandidates()
	assert.Empty(t, candidates)
}

func TestICEAgent_GetSelectedPair_Nil(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)
	pair := agent.GetSelectedPair()
	assert.Nil(t, pair)
}

func TestICEAgent_IsConnected_False(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)
	assert.False(t, agent.IsConnected())
}

func TestICEAgent_OnCandidate(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)

	called := false
	agent.OnCandidate(func(c *Candidate) {
		called = true
	})

	// Add a candidate manually to trigger callback
	candidate := &Candidate{
		Type:     CandidateTypeHost,
		Address:  netip.MustParseAddrPort("192.168.1.1:12345"),
		Priority: calculatePriority(CandidateTypeHost, 0),
	}
	agent.addLocalCandidate(candidate)

	assert.True(t, called)
}

func TestICEAgent_OnConnected(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)

	agent.OnConnected(func(pair *CandidatePair) {
		// Callback would be triggered on connection
	})

	// Verify callback was set (we can't easily trigger it without network)
	assert.NotNil(t, agent.onConnected)
}

func TestICEAgent_AddRemoteCandidate(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)

	// Add a local candidate first
	localCandidate := &Candidate{
		Type:     CandidateTypeHost,
		Address:  netip.MustParseAddrPort("192.168.1.1:12345"),
		Priority: calculatePriority(CandidateTypeHost, 0),
	}
	agent.localCandidates = append(agent.localCandidates, localCandidate)

	// Add remote candidate
	remoteCandidate := &Candidate{
		Type:     CandidateTypeHost,
		Address:  netip.MustParseAddrPort("192.168.1.2:12345"),
		Priority: calculatePriority(CandidateTypeHost, 0),
	}
	agent.AddRemoteCandidate(remoteCandidate)

	// Should have one candidate pair
	assert.Len(t, agent.remoteCandidates, 1)
	assert.Len(t, agent.candidatePairs, 1)
}

func TestICEAgent_AddRemoteCandidate_MixedFamilies(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)

	// Add IPv4 local candidate
	localCandidate := &Candidate{
		Type:     CandidateTypeHost,
		Address:  netip.MustParseAddrPort("192.168.1.1:12345"),
		Priority: calculatePriority(CandidateTypeHost, 0),
	}
	agent.localCandidates = append(agent.localCandidates, localCandidate)

	// Add IPv6 remote candidate - should not create pair
	remoteCandidate := &Candidate{
		Type:     CandidateTypeHost,
		Address:  netip.MustParseAddrPort("[2001:db8::1]:12345"),
		Priority: calculatePriority(CandidateTypeHost, 0),
	}
	agent.AddRemoteCandidate(remoteCandidate)

	// Should have no candidate pairs due to address family mismatch
	assert.Len(t, agent.remoteCandidates, 1)
	assert.Len(t, agent.candidatePairs, 0)
}

func TestICEAgent_Close(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)
	err := agent.Close()
	assert.NoError(t, err)
}

func TestICEAgent_Send_NotConnected(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)
	err := agent.Send([]byte("test"))
	assert.Error(t, err)
	assert.Equal(t, ErrICENotConnected, err)
}

func TestICEAgent_Receive_NotConnected(t *testing.T) {
	config := ICEConfig{
		STUNServers: []string{"stun:stun.l.google.com:19302"},
		Timeout:     5 * time.Second,
	}

	agent := NewICEAgent(config)
	buf := make([]byte, 1024)
	_, err := agent.Receive(buf)
	assert.Error(t, err)
	assert.Equal(t, ErrICENotConnected, err)
}

func TestCandidate_Properties(t *testing.T) {
	candidate := &Candidate{
		Type:           CandidateTypeServerReflexive,
		Address:        netip.MustParseAddrPort("203.0.113.1:45678"),
		Base:           netip.MustParseAddrPort("192.168.1.100:12345"),
		Priority:       calculatePriority(CandidateTypeServerReflexive, 0),
		Foundation:     "abc123",
		RelatedAddress: netip.MustParseAddrPort("192.168.1.100:12345"),
	}

	assert.Equal(t, CandidateTypeServerReflexive, candidate.Type)
	assert.Equal(t, "srflx", candidate.Type.String())
	assert.True(t, candidate.Address.Addr().Is4())
	assert.Equal(t, uint16(45678), candidate.Address.Port())
}

func TestCandidatePair_Properties(t *testing.T) {
	local := &Candidate{
		Type:     CandidateTypeHost,
		Address:  netip.MustParseAddrPort("192.168.1.1:12345"),
		Priority: calculatePriority(CandidateTypeHost, 0),
	}

	remote := &Candidate{
		Type:     CandidateTypeHost,
		Address:  netip.MustParseAddrPort("192.168.1.2:12345"),
		Priority: calculatePriority(CandidateTypeHost, 0),
	}

	pair := &CandidatePair{
		Local:    local,
		Remote:   remote,
		Priority: calculatePairPriority(local.Priority, remote.Priority),
		State:    PairStateWaiting,
		RTT:      50 * time.Millisecond,
	}

	assert.Equal(t, local, pair.Local)
	assert.Equal(t, remote, pair.Remote)
	assert.Equal(t, PairStateWaiting, pair.State)
	assert.Equal(t, 50*time.Millisecond, pair.RTT)
}

func TestPairState_Values(t *testing.T) {
	assert.Equal(t, PairState(0), PairStateWaiting)
	assert.Equal(t, PairState(1), PairStateInProgress)
	assert.Equal(t, PairState(2), PairStateSucceeded)
	assert.Equal(t, PairState(3), PairStateFailed)
}

func TestICEErrors(t *testing.T) {
	assert.NotNil(t, ErrICEGatheringFailed)
	assert.NotNil(t, ErrICENoValidPair)
	assert.NotNil(t, ErrICENotConnected)

	assert.Contains(t, ErrICEGatheringFailed.Error(), "gathering failed")
	assert.Contains(t, ErrICENoValidPair.Error(), "no valid candidate pair")
	assert.Contains(t, ErrICENotConnected.Error(), "not connected")
}
