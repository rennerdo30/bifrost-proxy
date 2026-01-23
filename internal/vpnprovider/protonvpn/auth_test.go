package protonvpn

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSession(t *testing.T) {
	resp := &SessionResponse{
		UID:          "test-uid-123",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
		Scope:        "full",
		LocalID:      1,
	}

	session := NewSession(resp)

	assert.Equal(t, "test-uid-123", session.UID)
	assert.Equal(t, "test-access-token", session.AccessToken)
	assert.Equal(t, "test-refresh-token", session.RefreshToken)
	assert.Equal(t, "Bearer", session.TokenType)
	assert.False(t, session.IsExpired())
	assert.True(t, session.IsValid())
}

func TestSessionIsValid(t *testing.T) {
	validSession := &Session{
		UID:         "uid",
		AccessToken: "token",
	}
	assert.True(t, validSession.IsValid())

	noUID := &Session{
		AccessToken: "token",
	}
	assert.False(t, noUID.IsValid())

	noToken := &Session{
		UID: "uid",
	}
	assert.False(t, noToken.IsValid())

	var nilSession *Session
	assert.False(t, nilSession.IsValid())
}

func TestSessionIsExpired(t *testing.T) {
	notExpired := &Session{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	assert.False(t, notExpired.IsExpired())

	expired := &Session{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	assert.True(t, expired.IsExpired())

	var nilSession *Session
	assert.True(t, nilSession.IsExpired())
}

func TestSessionNeedsRefresh(t *testing.T) {
	fresh := &Session{
		ExpiresAt: time.Now().Add(2 * time.Hour),
	}
	assert.False(t, fresh.NeedsRefresh())

	almostExpired := &Session{
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	assert.True(t, almostExpired.NeedsRefresh())

	var nilSession *Session
	assert.True(t, nilSession.NeedsRefresh())
}

func TestSessionGetAuthHeader(t *testing.T) {
	withTokenType := &Session{
		AccessToken: "mytoken",
		TokenType:   "Bearer",
	}
	assert.Equal(t, "Bearer mytoken", withTokenType.GetAuthHeader())

	withoutTokenType := &Session{
		AccessToken: "mytoken",
	}
	assert.Equal(t, "Bearer mytoken", withoutTokenType.GetAuthHeader())

	var nilSession *Session
	assert.Equal(t, "", nilSession.GetAuthHeader())
}

func TestSessionGetUID(t *testing.T) {
	session := &Session{UID: "test-uid"}
	assert.Equal(t, "test-uid", session.GetUID())

	var nilSession *Session
	assert.Equal(t, "", nilSession.GetUID())
}

func TestSessionUpdate(t *testing.T) {
	session := &Session{
		UID:         "old-uid",
		AccessToken: "old-token",
	}

	resp := &SessionResponse{
		UID:          "new-uid",
		AccessToken:  "new-token",
		RefreshToken: "new-refresh",
		TokenType:    "Bearer",
	}

	session.Update(resp)

	assert.Equal(t, "new-uid", session.UID)
	assert.Equal(t, "new-token", session.AccessToken)
	assert.Equal(t, "new-refresh", session.RefreshToken)
	assert.Equal(t, "Bearer", session.TokenType)
}

func TestMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore()

	// Initially empty
	loaded, err := store.Load()
	assert.NoError(t, err)
	assert.Nil(t, loaded)

	// Save a session
	session := &Session{
		UID:         "test-uid",
		AccessToken: "test-token",
	}
	err = store.Save(session)
	assert.NoError(t, err)

	// Load it back
	loaded, err = store.Load()
	assert.NoError(t, err)
	assert.NotNil(t, loaded)
	assert.Equal(t, "test-uid", loaded.UID)

	// Clear it
	err = store.Clear()
	assert.NoError(t, err)

	// Should be empty again
	loaded, err = store.Load()
	assert.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestManualCredentials(t *testing.T) {
	valid := &ManualCredentials{
		OpenVPNUsername: "user+suffix",
		OpenVPNPassword: "password",
		Tier:            TierPlus,
	}
	assert.True(t, valid.IsValid())

	noUsername := &ManualCredentials{
		OpenVPNPassword: "password",
	}
	assert.False(t, noUsername.IsValid())

	noPassword := &ManualCredentials{
		OpenVPNUsername: "user",
	}
	assert.False(t, noPassword.IsValid())

	empty := &ManualCredentials{}
	assert.False(t, empty.IsValid())
}

func TestAuthMode(t *testing.T) {
	assert.Equal(t, "manual", AuthModeManual.String())
	assert.Equal(t, "api", AuthModeAPI.String())
	assert.Equal(t, "unknown", AuthMode(99).String())

	assert.Equal(t, AuthModeManual, ParseAuthMode("manual"))
	assert.Equal(t, AuthModeAPI, ParseAuthMode("api"))
	assert.Equal(t, AuthModeManual, ParseAuthMode("unknown"))
	assert.Equal(t, AuthModeManual, ParseAuthMode(""))
}
