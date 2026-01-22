package ntlm

import "time"

// SetChallengeTimestamp is an exported test helper to manipulate challenge timestamps for testing.
func (a *Authenticator) SetChallengeTimestamp(sessionID string, timestamp int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if state, exists := a.challenges[sessionID]; exists {
		state.timestamp = timestamp
	}
}

// GetChallengeCount returns the number of active challenges (for testing).
func (a *Authenticator) GetChallengeCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.challenges)
}

// TriggerCleanup explicitly triggers the cleanup function (for testing).
func (a *Authenticator) TriggerCleanup() {
	a.cleanupChallenges()
}

// ExpiredTimestamp returns a timestamp that is older than maxAge (for testing).
func ExpiredTimestamp() int64 {
	return time.Now().Unix() - 400 // Older than 5 minutes (300 seconds)
}
