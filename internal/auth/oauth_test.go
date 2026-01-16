package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewOAuthAuthenticator_MissingClientID(t *testing.T) {
	cfg := OAuthConfig{
		UserInfoURL: "https://example.com/userinfo",
	}

	_, err := NewOAuthAuthenticator(cfg)
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}
}

func TestNewOAuthAuthenticator_MissingEndpoint(t *testing.T) {
	cfg := OAuthConfig{
		ClientID: "client-id",
	}

	_, err := NewOAuthAuthenticator(cfg)
	if err == nil {
		t.Fatal("expected error for missing endpoints")
	}
}

func TestNewOAuthAuthenticator_WithUserInfoURL(t *testing.T) {
	cfg := OAuthConfig{
		ClientID:    "client-id",
		UserInfoURL: "https://example.com/userinfo",
	}

	auth, err := NewOAuthAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator failed: %v", err)
	}
	if auth == nil {
		t.Fatal("auth is nil")
	}
	if auth.Name() != "oauth" {
		t.Errorf("expected Name()=oauth, got %s", auth.Name())
	}
	if auth.Type() != "oauth" {
		t.Errorf("expected Type()=oauth, got %s", auth.Type())
	}
}

func TestNewOAuthAuthenticator_WithProvider(t *testing.T) {
	cfg := OAuthConfig{
		Provider:    "google",
		ClientID:    "client-id",
		UserInfoURL: "https://example.com/userinfo",
	}

	auth, err := NewOAuthAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator failed: %v", err)
	}
	if auth.Name() != "oauth-google" {
		t.Errorf("expected Name()=oauth-google, got %s", auth.Name())
	}
}

func TestOAuthAuthenticator_Authenticate_EmptyToken(t *testing.T) {
	cfg := OAuthConfig{
		ClientID:    "client-id",
		UserInfoURL: "https://example.com/userinfo",
	}
	auth, _ := NewOAuthAuthenticator(cfg)

	_, err := auth.Authenticate(context.Background(), "", "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestOAuthAuthenticator_Authenticate_UserInfo(t *testing.T) {
	userinfo := struct {
		Sub               string   `json:"sub"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
	}{
		Sub:               "12345",
		Name:              "Test User",
		PreferredUsername: "testuser",
		Email:             "test@example.com",
		Groups:            []string{"admin", "users"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(userinfo)
	}))
	defer server.Close()

	cfg := OAuthConfig{
		ClientID:    "client-id",
		UserInfoURL: server.URL,
	}
	auth, _ := NewOAuthAuthenticator(cfg)

	user, err := auth.Authenticate(context.Background(), "bearer", "valid-token")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if user.Username != "testuser" {
		t.Errorf("expected Username=testuser, got %s", user.Username)
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected Email=test@example.com, got %s", user.Email)
	}
	if user.FullName != "Test User" {
		t.Errorf("expected FullName=Test User, got %s", user.FullName)
	}
}

func TestOAuthAuthenticator_Authenticate_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	cfg := OAuthConfig{
		ClientID:    "client-id",
		UserInfoURL: server.URL,
	}
	auth, _ := NewOAuthAuthenticator(cfg)

	_, err := auth.Authenticate(context.Background(), "", "invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestOAuthAuthenticator_Authenticate_Introspection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// Check basic auth
		username, password, ok := r.BasicAuth()
		if !ok || username != "client-id" || password != "client-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		result := map[string]interface{}{
			"active":   true,
			"username": "testuser",
			"email":    "test@example.com",
			"name":     "Test User",
			"scope":    "read write",
		}
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	cfg := OAuthConfig{
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
		IntrospectURL: server.URL,
	}
	auth, _ := NewOAuthAuthenticator(cfg)

	user, err := auth.Authenticate(context.Background(), "", "valid-token")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if user.Username != "testuser" {
		t.Errorf("expected Username=testuser, got %s", user.Username)
	}
}

func TestOAuthAuthenticator_Authenticate_IntrospectionInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := map[string]interface{}{"active": false}
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	cfg := OAuthConfig{
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
		IntrospectURL: server.URL,
	}
	auth, _ := NewOAuthAuthenticator(cfg)

	_, err := auth.Authenticate(context.Background(), "", "invalid-token")
	if err == nil {
		t.Fatal("expected error for inactive token")
	}
}

func TestOAuthAuthenticator_Authenticate_RequiredScopes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := map[string]interface{}{
			"active":   true,
			"username": "testuser",
			"scope":    "read",
		}
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	cfg := OAuthConfig{
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
		IntrospectURL: server.URL,
		Scopes:        []string{"read", "write"}, // Require write scope
	}
	auth, _ := NewOAuthAuthenticator(cfg)

	_, err := auth.Authenticate(context.Background(), "", "token-missing-scope")
	if err == nil {
		t.Fatal("expected error for missing required scope")
	}
}

func TestOAuthAuthenticator_Authenticate_Caching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		userinfo := map[string]interface{}{
			"preferred_username": "testuser",
		}
		json.NewEncoder(w).Encode(userinfo)
	}))
	defer server.Close()

	cfg := OAuthConfig{
		ClientID:    "client-id",
		UserInfoURL: server.URL,
	}
	auth, _ := NewOAuthAuthenticator(cfg)

	// First call
	_, err := auth.Authenticate(context.Background(), "", "cached-token")
	if err != nil {
		t.Fatalf("first Authenticate failed: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}

	// Second call (should use cache)
	_, err = auth.Authenticate(context.Background(), "", "cached-token")
	if err != nil {
		t.Fatalf("second Authenticate failed: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call (cached), got %d", callCount)
	}
}

func TestOAuthAuthenticator_Authenticate_TokenAsUsername(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userinfo := map[string]interface{}{
			"preferred_username": "testuser",
		}
		json.NewEncoder(w).Encode(userinfo)
	}))
	defer server.Close()

	cfg := OAuthConfig{
		ClientID:    "client-id",
		UserInfoURL: server.URL,
	}
	auth, _ := NewOAuthAuthenticator(cfg)

	// Token as username, empty password
	user, err := auth.Authenticate(context.Background(), "my-token", "")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("expected Username=testuser, got %s", user.Username)
	}
}

func TestHashToken(t *testing.T) {
	token1 := "test-token-1"
	token2 := "test-token-2"

	hash1 := hashToken(token1)
	hash2 := hashToken(token2)

	// Hashes should be deterministic
	if hashToken(token1) != hash1 {
		t.Error("hash is not deterministic")
	}

	// Different tokens should produce different hashes
	if hash1 == hash2 {
		t.Error("different tokens produced same hash")
	}

	// Hash should be hex string (64 chars for SHA256)
	if len(hash1) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}
}

func TestDiscoverOIDCEndpoints(t *testing.T) {
	config := map[string]interface{}{
		"introspection_endpoint": "https://example.com/introspect",
		"userinfo_endpoint":      "https://example.com/userinfo",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(config)
	}))
	defer server.Close()

	introspect, userinfo, err := discoverOIDCEndpoints(server.URL)
	if err != nil {
		t.Fatalf("discoverOIDCEndpoints failed: %v", err)
	}

	if introspect != "https://example.com/introspect" {
		t.Errorf("expected introspect endpoint, got %s", introspect)
	}
	if userinfo != "https://example.com/userinfo" {
		t.Errorf("expected userinfo endpoint, got %s", userinfo)
	}
}

func TestDiscoverOIDCEndpoints_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, _, err := discoverOIDCEndpoints(server.URL)
	if err == nil {
		t.Fatal("expected error for 404")
	}
}
