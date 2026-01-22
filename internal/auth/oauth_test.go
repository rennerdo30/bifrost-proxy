package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/oauth"
)

func createOAuthAuthenticator(t *testing.T, config map[string]any) (auth.Authenticator, error) {
	t.Helper()
	factory := auth.NewFactory()
	return factory.Create(auth.ProviderConfig{
		Name:    "oauth-test",
		Type:    "oauth",
		Enabled: true,
		Config:  config,
	})
}

func TestOAuthAuthenticator_MissingClientID(t *testing.T) {
	_, err := createOAuthAuthenticator(t, map[string]any{
		"userinfo_url": "https://example.com/userinfo",
	})
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}
}

func TestOAuthAuthenticator_MissingEndpoint(t *testing.T) {
	_, err := createOAuthAuthenticator(t, map[string]any{
		"client_id": "client-id",
	})
	if err == nil {
		t.Fatal("expected error for missing endpoints")
	}
}

func TestOAuthAuthenticator_WithUserInfoURL(t *testing.T) {
	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"client_id":    "client-id",
		"userinfo_url": "https://example.com/userinfo",
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}
	if authenticator == nil {
		t.Fatal("authenticator is nil")
	}
	if authenticator.Name() != "oauth" {
		t.Errorf("expected Name()=oauth, got %s", authenticator.Name())
	}
	if authenticator.Type() != "oauth" {
		t.Errorf("expected Type()=oauth, got %s", authenticator.Type())
	}
}

func TestOAuthAuthenticator_WithProvider(t *testing.T) {
	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"provider":     "google",
		"client_id":    "client-id",
		"userinfo_url": "https://example.com/userinfo",
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}
	if authenticator.Name() != "oauth-google" {
		t.Errorf("expected Name()=oauth-google, got %s", authenticator.Name())
	}
}

func TestOAuthAuthenticator_Authenticate_EmptyToken(t *testing.T) {
	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"client_id":    "client-id",
		"userinfo_url": "https://example.com/userinfo",
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}

	_, err = authenticator.Authenticate(context.Background(), "", "")
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

	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"client_id":    "client-id",
		"userinfo_url": server.URL,
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}

	user, err := authenticator.Authenticate(context.Background(), "bearer", "valid-token")
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

	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"client_id":    "client-id",
		"userinfo_url": server.URL,
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}

	_, err = authenticator.Authenticate(context.Background(), "", "invalid-token")
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

	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"client_id":      "client-id",
		"client_secret":  "client-secret",
		"introspect_url": server.URL,
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}

	user, err := authenticator.Authenticate(context.Background(), "", "valid-token")
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

	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"client_id":      "client-id",
		"client_secret":  "client-secret",
		"introspect_url": server.URL,
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}

	_, err = authenticator.Authenticate(context.Background(), "", "invalid-token")
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

	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"client_id":      "client-id",
		"client_secret":  "client-secret",
		"introspect_url": server.URL,
		"scopes":         []string{"read", "write"}, // Require write scope
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}

	_, err = authenticator.Authenticate(context.Background(), "", "token-missing-scope")
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

	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"client_id":    "client-id",
		"userinfo_url": server.URL,
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}

	// First call
	_, err = authenticator.Authenticate(context.Background(), "", "cached-token")
	if err != nil {
		t.Fatalf("first Authenticate failed: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}

	// Second call (should use cache)
	_, err = authenticator.Authenticate(context.Background(), "", "cached-token")
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

	authenticator, err := createOAuthAuthenticator(t, map[string]any{
		"client_id":    "client-id",
		"userinfo_url": server.URL,
	})
	if err != nil {
		t.Fatalf("createOAuthAuthenticator failed: %v", err)
	}

	// Token as username, empty password
	user, err := authenticator.Authenticate(context.Background(), "my-token", "")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("expected Username=testuser, got %s", user.Username)
	}
}

func TestOAuthPlugin_Registration(t *testing.T) {
	plugin, ok := auth.GetPlugin("oauth")
	if !ok {
		t.Fatal("oauth plugin not registered")
	}
	if plugin.Type() != "oauth" {
		t.Errorf("expected plugin type oauth, got %s", plugin.Type())
	}
}

func TestOAuthPlugin_ValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("oauth")
	if !ok {
		t.Fatal("oauth plugin not registered")
	}

	// Missing client_id should fail
	err := plugin.ValidateConfig(map[string]any{})
	if err == nil {
		t.Error("expected validation error for missing client_id")
	}

	// Missing endpoints should fail
	err = plugin.ValidateConfig(map[string]any{
		"client_id": "test-client",
	})
	if err == nil {
		t.Error("expected validation error for missing endpoints")
	}

	// Valid config should pass
	err = plugin.ValidateConfig(map[string]any{
		"client_id":    "test-client",
		"userinfo_url": "https://example.com/userinfo",
	})
	if err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}
