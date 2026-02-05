package session_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_CreateAndGet(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	userInfo := &auth.UserInfo{
		Username: "testuser",
		Groups:   []string{"admin"},
		Metadata: map[string]string{"email": "test@example.com"},
	}

	now := time.Now()
	sess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		LastUsed:  now,
	}

	// Create session
	id, err := store.Create(sess)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// Get session
	retrieved, err := store.Get(id)
	require.NoError(t, err)
	assert.Equal(t, id, retrieved.ID)
	assert.Equal(t, "testuser", retrieved.UserInfo.Username)
	assert.Contains(t, retrieved.UserInfo.Groups, "admin")
}

func TestMemoryStore_GetNonExistent(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	_, err := store.Get("nonexistent-id")
	assert.Error(t, err)
}

func TestMemoryStore_Delete(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()
	sess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		LastUsed:  now,
	}

	id, err := store.Create(sess)
	require.NoError(t, err)

	// Delete session
	err = store.Delete(id)
	require.NoError(t, err)

	// Should not exist anymore
	_, err = store.Get(id)
	assert.Error(t, err)
}

func TestMemoryStore_DeleteNonExistent(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	err := store.Delete("nonexistent-id")
	assert.NoError(t, err) // Should not error
}

func TestMemoryStore_Update(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()
	sess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		LastUsed:  now,
	}

	id, err := store.Create(sess)
	require.NoError(t, err)

	// Update session
	sess.ID = id
	sess.ExpiresAt = now.Add(2 * time.Hour)
	err = store.Update(sess)
	require.NoError(t, err)

	// Verify update
	retrieved, err := store.Get(id)
	require.NoError(t, err)
	assert.True(t, retrieved.ExpiresAt.After(now.Add(time.Hour)))
}

func TestMemoryStore_ListByUser(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()

	// Create multiple sessions for same user
	for i := 0; i < 3; i++ {
		sess := &session.Session{
			UserInfo:  userInfo,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
			LastUsed:  now,
		}
		_, err := store.Create(sess)
		require.NoError(t, err)
	}

	sessions, err := store.ListByUser("testuser")
	require.NoError(t, err)
	assert.Len(t, sessions, 3)
}

func TestMemoryStore_DeleteByUser(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	user1 := &auth.UserInfo{Username: "user1"}
	user2 := &auth.UserInfo{Username: "user2"}
	now := time.Now()

	// Create sessions for user1
	for i := 0; i < 2; i++ {
		sess := &session.Session{
			UserInfo:  user1,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
			LastUsed:  now,
		}
		_, err := store.Create(sess)
		require.NoError(t, err)
	}

	// Create session for user2
	sess2 := &session.Session{
		UserInfo:  user2,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		LastUsed:  now,
	}
	_, err := store.Create(sess2)
	require.NoError(t, err)

	// Delete all sessions for user1
	err = store.DeleteByUser("user1")
	require.NoError(t, err)

	// user1 should have no sessions
	sessions, err := store.ListByUser("user1")
	require.NoError(t, err)
	assert.Len(t, sessions, 0)

	// user2 should still have session
	sessions2, err := store.ListByUser("user2")
	require.NoError(t, err)
	assert.Len(t, sessions2, 1)
}

func TestMemoryStore_Expiration(t *testing.T) {
	store := session.NewMemoryStore(10 * time.Millisecond)
	defer store.Close()

	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()
	sess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now,
		ExpiresAt: now.Add(50 * time.Millisecond),
		LastUsed:  now,
	}

	id, err := store.Create(sess)
	require.NoError(t, err)

	// Should exist initially
	_, err = store.Get(id)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	_, err = store.Get(id)
	assert.Error(t, err)
}

func TestMemoryStore_Cleanup(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	err := store.Cleanup()
	assert.NoError(t, err)
}

func TestManager_CreateSession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)
	assert.NotEmpty(t, sess.ID)
	assert.Equal(t, "testuser", sess.UserInfo.Username)
	assert.Equal(t, "127.0.0.1", sess.IPAddress)
	assert.Equal(t, "TestAgent", sess.UserAgent)
}

func TestManager_GetSession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Get session
	retrieved, err := manager.GetSession(sess.ID)
	require.NoError(t, err)
	assert.Equal(t, "testuser", retrieved.UserInfo.Username)
}

func TestManager_ValidateSession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Validate session
	retrieved, err := manager.ValidateSession(sess.ID)
	require.NoError(t, err)
	assert.Equal(t, "testuser", retrieved.Username)
}

func TestManager_DestroySession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	err = manager.DestroySession(sess.ID)
	require.NoError(t, err)

	_, err = manager.ValidateSession(sess.ID)
	assert.Error(t, err)
}

func TestManager_MaxSessionsPerUser(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	config.MaxSessionsPerUser = 2
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}

	// Create first two sessions
	sess1, err := manager.CreateSession(userInfo, "127.0.0.1", "Agent1")
	require.NoError(t, err)
	sess2, err := manager.CreateSession(userInfo, "127.0.0.2", "Agent2")
	require.NoError(t, err)

	// Create third session (should evict oldest)
	sess3, err := manager.CreateSession(userInfo, "127.0.0.3", "Agent3")
	require.NoError(t, err)

	// First session should be gone
	_, err = manager.ValidateSession(sess1.ID)
	assert.Error(t, err)

	// Second and third should exist
	_, err = manager.ValidateSession(sess2.ID)
	assert.NoError(t, err)
	_, err = manager.ValidateSession(sess3.ID)
	assert.NoError(t, err)
}

func TestManager_Middleware(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Handler that checks for session in context
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := session.GetUserInfoFromContext(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	// Test with valid session cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: config.CookieName, Value: sess.ID})
	rec := httptest.NewRecorder()

	manager.Middleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "testuser", rec.Body.String())
}

func TestManager_MiddlewareNoSession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := session.GetUserInfoFromContext(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	// Test without session cookie
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	manager.Middleware(handler).ServeHTTP(rec, req)

	// Should still call handler but without user info
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestManager_SetAndClearSessionCookie(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	config.SecureCookies = true
	config.CookiePath = "/api"
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Set cookie
	rec := httptest.NewRecorder()
	manager.SetSessionCookie(rec, sess)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, config.CookieName, cookies[0].Name)
	assert.Equal(t, sess.ID, cookies[0].Value)
	assert.True(t, cookies[0].Secure)
	assert.Equal(t, "/api", cookies[0].Path)
	assert.True(t, cookies[0].HttpOnly)

	// Clear cookie
	rec2 := httptest.NewRecorder()
	manager.ClearSessionCookie(rec2)

	cookies2 := rec2.Result().Cookies()
	require.Len(t, cookies2, 1)
	assert.Equal(t, config.CookieName, cookies2[0].Name)
	assert.Equal(t, "", cookies2[0].Value)
	assert.True(t, cookies2[0].MaxAge < 0)
}

func TestGetUserInfoFromContext(t *testing.T) {
	userInfo := &auth.UserInfo{Username: "testuser"}
	ctx := context.WithValue(context.Background(), session.UserInfoContextKey, userInfo)

	retrieved := session.GetUserInfoFromContext(ctx)
	require.NotNil(t, retrieved)
	assert.Equal(t, "testuser", retrieved.Username)
}

func TestGetUserInfoFromContextMissing(t *testing.T) {
	ctx := context.Background()
	retrieved := session.GetUserInfoFromContext(ctx)
	assert.Nil(t, retrieved)
}

func TestDefaultManagerConfig(t *testing.T) {
	config := session.DefaultManagerConfig()

	assert.Equal(t, 8*time.Hour, config.SessionDuration)
	assert.Equal(t, 10, config.MaxSessionsPerUser)
	assert.True(t, config.SecureCookies)
	assert.Equal(t, "bifrost_session", config.CookieName)
	assert.Equal(t, "/", config.CookiePath)
	assert.True(t, config.ExtendOnUse)
}

func TestSession_IsExpired(t *testing.T) {
	now := time.Now()

	// Not expired
	sess1 := &session.Session{
		ExpiresAt: now.Add(time.Hour),
	}
	assert.False(t, sess1.IsExpired())

	// Expired
	sess2 := &session.Session{
		ExpiresAt: now.Add(-time.Hour),
	}
	assert.True(t, sess2.IsExpired())
}

func TestManager_DestroyUserSessions(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}

	// Create multiple sessions for the user
	_, err := manager.CreateSession(userInfo, "127.0.0.1", "Agent1")
	require.NoError(t, err)
	_, err = manager.CreateSession(userInfo, "127.0.0.2", "Agent2")
	require.NoError(t, err)

	// Verify sessions exist
	sessions, err := manager.ListUserSessions("testuser")
	require.NoError(t, err)
	assert.Len(t, sessions, 2)

	// Destroy all user sessions
	err = manager.DestroyUserSessions("testuser")
	require.NoError(t, err)

	// Verify all sessions are gone
	sessions, err = manager.ListUserSessions("testuser")
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}

func TestManager_ListUserSessions(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}

	// Create sessions
	sess1, err := manager.CreateSession(userInfo, "127.0.0.1", "Agent1")
	require.NoError(t, err)
	sess2, err := manager.CreateSession(userInfo, "127.0.0.2", "Agent2")
	require.NoError(t, err)

	// List user sessions
	sessions, err := manager.ListUserSessions("testuser")
	require.NoError(t, err)
	assert.Len(t, sessions, 2)

	// Verify session IDs are present
	ids := make(map[string]bool)
	for _, s := range sessions {
		ids[s.ID] = true
	}
	assert.True(t, ids[sess1.ID])
	assert.True(t, ids[sess2.ID])
}

func TestManager_ListUserSessions_NoSessions(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	// List sessions for nonexistent user
	sessions, err := manager.ListUserSessions("nonexistent")
	require.NoError(t, err)
	assert.Nil(t, sessions)
}

func TestManager_OptionalMiddleware_WithSession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Handler that checks for session in context
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := session.GetUserInfoFromContext(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("anonymous"))
		}
	})

	// Test with valid session cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: config.CookieName, Value: sess.ID})
	rec := httptest.NewRecorder()

	manager.OptionalMiddleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "testuser", rec.Body.String())
}

func TestManager_OptionalMiddleware_WithoutSession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	// Handler that checks for session in context
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := session.GetUserInfoFromContext(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("anonymous"))
		}
	})

	// Test without session cookie - should still call handler
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	manager.OptionalMiddleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "anonymous", rec.Body.String())
}

func TestManager_OptionalMiddleware_WithInvalidSession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	// Handler that checks for session in context
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := session.GetUserInfoFromContext(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("anonymous"))
		}
	})

	// Test with invalid session - should still call handler as anonymous
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: config.CookieName, Value: "invalid-session-id"})
	rec := httptest.NewRecorder()

	manager.OptionalMiddleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "anonymous", rec.Body.String())
}

func TestGetSessionFromContext(t *testing.T) {
	userInfo := &auth.UserInfo{Username: "testuser"}
	sess := &session.Session{
		ID:       "test-session-id",
		UserInfo: userInfo,
	}
	ctx := context.WithValue(context.Background(), session.SessionContextKey, sess)

	retrieved := session.GetSessionFromContext(ctx)
	require.NotNil(t, retrieved)
	assert.Equal(t, "test-session-id", retrieved.ID)
	assert.Equal(t, "testuser", retrieved.UserInfo.Username)
}

func TestGetSessionFromContext_Missing(t *testing.T) {
	ctx := context.Background()
	retrieved := session.GetSessionFromContext(ctx)
	assert.Nil(t, retrieved)
}

func TestGetSessionFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), session.SessionContextKey, "not a session")
	retrieved := session.GetSessionFromContext(ctx)
	assert.Nil(t, retrieved)
}

func TestManager_Close(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	err := manager.Close()
	assert.NoError(t, err)
}

func TestMemoryStore_Count(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	// Initially empty
	assert.Equal(t, 0, store.Count())

	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()

	// Create sessions
	for i := 0; i < 3; i++ {
		sess := &session.Session{
			UserInfo:  userInfo,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
			LastUsed:  now,
		}
		_, err := store.Create(sess)
		require.NoError(t, err)
	}

	assert.Equal(t, 3, store.Count())

	// Delete one
	sessions, err := store.ListByUser("testuser")
	require.NoError(t, err)
	err = store.Delete(sessions[0].ID)
	require.NoError(t, err)

	assert.Equal(t, 2, store.Count())
}

func TestManager_GetSessionFromRequest_BearerToken(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Test with Bearer token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+sess.ID)

	sessionID, err := manager.GetSessionFromRequest(req)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, sessionID)
}

func TestManager_GetSessionFromRequest_XSessionToken(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Test with X-Session-Token header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Session-Token", sess.ID)

	sessionID, err := manager.GetSessionFromRequest(req)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, sessionID)
}

func TestManager_GetSessionFromRequest_Priority(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Test that cookie takes priority over headers
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: config.CookieName, Value: sess.ID})
	req.Header.Set("Authorization", "Bearer other-token")
	req.Header.Set("X-Session-Token", "another-token")

	sessionID, err := manager.GetSessionFromRequest(req)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, sessionID)
}

func TestManager_GetSessionFromRequest_ShortAuthHeader(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	// Test with Authorization header that's too short for "Bearer "
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic")

	_, err := manager.GetSessionFromRequest(req)
	assert.Error(t, err)
}

func TestManager_GetSessionFromRequest_WrongAuthScheme(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	// Test with Authorization header that's not Bearer
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	_, err := manager.GetSessionFromRequest(req)
	assert.Error(t, err)
}

func TestMemoryStore_Update_NonExistent(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	sess := &session.Session{
		ID:        "nonexistent-id",
		UserInfo:  &auth.UserInfo{Username: "testuser"},
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := store.Update(sess)
	assert.Error(t, err)
}

func TestMemoryStore_Create_WithPresetID(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()
	customID := "custom-session-id-12345"
	sess := &session.Session{
		ID:        customID,
		UserInfo:  userInfo,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		LastUsed:  now,
	}

	// Create with preset ID
	id, err := store.Create(sess)
	require.NoError(t, err)
	assert.Equal(t, customID, id)

	// Verify can retrieve
	retrieved, err := store.Get(customID)
	require.NoError(t, err)
	assert.Equal(t, customID, retrieved.ID)
}

func TestMemoryStore_Create_WithoutUserInfo(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	now := time.Now()
	sess := &session.Session{
		UserInfo:  nil,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		LastUsed:  now,
	}

	// Create without UserInfo
	id, err := store.Create(sess)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// Verify can retrieve
	retrieved, err := store.Get(id)
	require.NoError(t, err)
	assert.Nil(t, retrieved.UserInfo)
}

func TestMemoryStore_Delete_WithoutUserInfo(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	now := time.Now()
	sess := &session.Session{
		UserInfo:  nil,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		LastUsed:  now,
	}

	id, err := store.Create(sess)
	require.NoError(t, err)

	// Delete session without UserInfo
	err = store.Delete(id)
	require.NoError(t, err)

	// Verify deleted
	_, err = store.Get(id)
	assert.Error(t, err)
}

func TestNewMemoryStore_DefaultCleanupInterval(t *testing.T) {
	// Create with zero cleanup interval - should use default
	store := session.NewMemoryStore(0)
	defer store.Close()

	// Verify store works correctly
	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()
	sess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		LastUsed:  now,
	}

	id, err := store.Create(sess)
	require.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestMemoryStore_Cleanup_WithExpiredSessions(t *testing.T) {
	store := session.NewMemoryStore(time.Hour) // Long interval so we control cleanup
	defer store.Close()

	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()

	// Create an expired session
	expiredSess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour), // Already expired
		LastUsed:  now.Add(-2 * time.Hour),
	}
	expiredID, err := store.Create(expiredSess)
	require.NoError(t, err)

	// Create a valid session
	validSess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour), // Not expired
		LastUsed:  now,
	}
	validID, err := store.Create(validSess)
	require.NoError(t, err)

	// Both exist initially (expired session exists in store but Get returns error)
	assert.Equal(t, 2, store.Count())

	// Run cleanup
	err = store.Cleanup()
	require.NoError(t, err)

	// Expired session should be gone
	assert.Equal(t, 1, store.Count())

	// Valid session should still exist
	_, err = store.Get(validID)
	require.NoError(t, err)

	// Expired session should be gone
	_, err = store.Get(expiredID)
	assert.Error(t, err)
}

func TestMemoryStore_Cleanup_RemovesFromUserIndex(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()

	// Create only expired sessions for a user
	expiredSess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour), // Already expired
		LastUsed:  now.Add(-2 * time.Hour),
	}
	_, err := store.Create(expiredSess)
	require.NoError(t, err)

	// Run cleanup
	err = store.Cleanup()
	require.NoError(t, err)

	// User should have no sessions after cleanup
	sessions, err := store.ListByUser("testuser")
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}

func TestMemoryStore_ListByUser_ExcludesExpired(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	userInfo := &auth.UserInfo{Username: "testuser"}
	now := time.Now()

	// Create an expired session
	expiredSess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour), // Already expired
		LastUsed:  now.Add(-2 * time.Hour),
	}
	_, err := store.Create(expiredSess)
	require.NoError(t, err)

	// Create a valid session
	validSess := &session.Session{
		UserInfo:  userInfo,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour), // Not expired
		LastUsed:  now,
	}
	_, err = store.Create(validSess)
	require.NoError(t, err)

	// ListByUser should only return valid session
	sessions, err := store.ListByUser("testuser")
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
}

func TestManager_GetSession_NotFound(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	_, err := manager.GetSession("nonexistent-session-id")
	assert.Error(t, err)
}

func TestManager_CreateSession_NoSessionLimit(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	config.MaxSessionsPerUser = 0 // Unlimited
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}

	// Create many sessions - should all succeed
	for i := 0; i < 20; i++ {
		_, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
		require.NoError(t, err)
	}

	sessions, err := manager.ListUserSessions("testuser")
	require.NoError(t, err)
	assert.Len(t, sessions, 20)
}

func TestManager_CreateSession_ExtendOnUseFalse(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	config.ExtendOnUse = false
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	originalExpiry := sess.ExpiresAt

	// Wait a tiny bit and get session
	time.Sleep(10 * time.Millisecond)

	retrieved, err := manager.GetSession(sess.ID)
	require.NoError(t, err)

	// Expiry should not have changed (within tolerance)
	assert.WithinDuration(t, originalExpiry, retrieved.ExpiresAt, time.Second)
}

func TestManager_Middleware_WithBearerToken(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Handler that checks for session in context
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := session.GetUserInfoFromContext(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	// Test with Bearer token instead of cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+sess.ID)
	rec := httptest.NewRecorder()

	manager.Middleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "testuser", rec.Body.String())
}

func TestManager_Middleware_WithXSessionToken(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Handler that checks for session in context
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := session.GetUserInfoFromContext(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	// Test with X-Session-Token header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Session-Token", sess.ID)
	rec := httptest.NewRecorder()

	manager.Middleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "testuser", rec.Body.String())
}

func TestManager_ValidateRequestSession_NoSession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	req := httptest.NewRequest("GET", "/", nil)

	_, err := manager.ValidateRequestSession(req)
	assert.Error(t, err)
}

func TestManager_ValidateRequestSession_InvalidSession(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: config.CookieName, Value: "invalid-session-id"})

	_, err := manager.ValidateRequestSession(req)
	assert.Error(t, err)
}

func TestManager_SetSessionCookie_WithDomain(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	config.CookieDomain = "example.com"
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	manager.SetSessionCookie(rec, sess)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "example.com", cookies[0].Domain)
}

func TestManager_ClearSessionCookie_WithDomain(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	config := session.DefaultManagerConfig()
	config.CookieDomain = "example.com"
	manager := session.NewManager(store, config)

	rec := httptest.NewRecorder()
	manager.ClearSessionCookie(rec)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "example.com", cookies[0].Domain)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

func TestMemoryStore_DeleteByUser_NoSessions(t *testing.T) {
	store := session.NewMemoryStore(time.Hour)
	defer store.Close()

	// Delete sessions for user that doesn't exist - should not error
	err := store.DeleteByUser("nonexistent")
	require.NoError(t, err)
}

// mockStore is a test helper that implements the Store interface
// with configurable error injection for testing error paths
type mockStore struct {
	sessions        map[string]*session.Session
	userIndex       map[string][]string
	getErr          error
	createErr       error
	updateErr       error
	deleteErr       error
	deleteByUserErr error
	listByUserErr   error
	cleanupErr      error
	closeErr        error
}

func newMockStore() *mockStore {
	return &mockStore{
		sessions:  make(map[string]*session.Session),
		userIndex: make(map[string][]string),
	}
}

func (m *mockStore) Get(id string) (*session.Session, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	s, ok := m.sessions[id]
	if !ok {
		return nil, session.ErrSessionNotFound
	}
	if s.IsExpired() {
		return nil, session.ErrSessionExpired
	}
	return s, nil
}

func (m *mockStore) Create(s *session.Session) (string, error) {
	if m.createErr != nil {
		return "", m.createErr
	}
	if s.ID == "" {
		s.ID = "mock-session-id"
	}
	m.sessions[s.ID] = s
	if s.UserInfo != nil {
		m.userIndex[s.UserInfo.Username] = append(m.userIndex[s.UserInfo.Username], s.ID)
	}
	return s.ID, nil
}

func (m *mockStore) Update(s *session.Session) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.sessions[s.ID]; !ok {
		return session.ErrSessionNotFound
	}
	m.sessions[s.ID] = s
	return nil
}

func (m *mockStore) Delete(id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.sessions, id)
	return nil
}

func (m *mockStore) DeleteByUser(username string) error {
	if m.deleteByUserErr != nil {
		return m.deleteByUserErr
	}
	for _, id := range m.userIndex[username] {
		delete(m.sessions, id)
	}
	delete(m.userIndex, username)
	return nil
}

func (m *mockStore) ListByUser(username string) ([]*session.Session, error) {
	if m.listByUserErr != nil {
		return nil, m.listByUserErr
	}
	ids := m.userIndex[username]
	result := make([]*session.Session, 0, len(ids))
	for _, id := range ids {
		if s, ok := m.sessions[id]; ok && !s.IsExpired() {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockStore) Cleanup() error {
	return m.cleanupErr
}

func (m *mockStore) Close() error {
	return m.closeErr
}

func TestManager_CreateSession_ListByUserError(t *testing.T) {
	store := newMockStore()
	store.listByUserErr = fmt.Errorf("database error")

	config := session.DefaultManagerConfig()
	config.MaxSessionsPerUser = 5 // Enable session limit check
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	_, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check existing sessions")
}

func TestManager_CreateSession_CreateError(t *testing.T) {
	store := newMockStore()
	store.createErr = fmt.Errorf("create failed")

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}
	_, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create session")
}

func TestManager_GetSession_UpdateError(t *testing.T) {
	store := newMockStore()
	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}

	// Create a session first
	sess, err := manager.CreateSession(userInfo, "127.0.0.1", "TestAgent")
	require.NoError(t, err)

	// Now inject update error
	store.updateErr = fmt.Errorf("update failed")

	// Get session should still succeed but log warning
	retrieved, err := manager.GetSession(sess.ID)
	require.NoError(t, err)
	assert.Equal(t, "testuser", retrieved.UserInfo.Username)
}

func TestManager_DestroySession_DeleteError(t *testing.T) {
	store := newMockStore()
	store.deleteErr = fmt.Errorf("delete failed")

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	err := manager.DestroySession("any-session-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to destroy session")
}

func TestManager_DestroyUserSessions_DeleteByUserError(t *testing.T) {
	store := newMockStore()
	store.deleteByUserErr = fmt.Errorf("delete by user failed")

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	err := manager.DestroyUserSessions("testuser")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to destroy user sessions")
}

func TestManager_Close_Error(t *testing.T) {
	store := newMockStore()
	store.closeErr = fmt.Errorf("close failed")

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	err := manager.Close()
	assert.Error(t, err)
}

func TestManager_CreateSession_EvictOldestSession_DeleteError(t *testing.T) {
	store := newMockStore()

	config := session.DefaultManagerConfig()
	config.MaxSessionsPerUser = 1 // Limit to 1 session
	manager := session.NewManager(store, config)

	userInfo := &auth.UserInfo{Username: "testuser"}

	// Create first session
	sess1, err := manager.CreateSession(userInfo, "127.0.0.1", "Agent1")
	require.NoError(t, err)
	assert.NotEmpty(t, sess1.ID)

	// Inject delete error for next eviction
	store.deleteErr = fmt.Errorf("delete failed")

	// Create second session - should try to evict but get error (logged as warning)
	// The session should still be created
	sess2, err := manager.CreateSession(userInfo, "127.0.0.2", "Agent2")
	require.NoError(t, err)
	assert.NotEmpty(t, sess2.ID)
}

func TestManager_ValidateSession_Error(t *testing.T) {
	store := newMockStore()
	store.getErr = fmt.Errorf("get failed")

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	_, err := manager.ValidateSession("any-session-id")
	assert.Error(t, err)
}

func TestManager_ListUserSessions_Error(t *testing.T) {
	store := newMockStore()
	store.listByUserErr = fmt.Errorf("list failed")

	config := session.DefaultManagerConfig()
	manager := session.NewManager(store, config)

	_, err := manager.ListUserSessions("testuser")
	assert.Error(t, err)
}
