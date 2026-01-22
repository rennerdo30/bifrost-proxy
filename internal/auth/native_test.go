package auth_test

import (
	"context"
	"testing"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/native"
)

func createNativeAuthenticatorWithUsers(t *testing.T, users []map[string]any) auth.Authenticator {
	t.Helper()
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "native-test",
		Type:    "native",
		Enabled: true,
		Config: map[string]any{
			"users": users,
		},
	})
	if err != nil {
		t.Fatalf("failed to create native authenticator: %v", err)
	}
	return authenticator
}

func TestNewNativeAuthenticator(t *testing.T) {
	hash, err := auth.HashPassword("password")
	if err != nil {
		t.Fatal(err)
	}

	authenticator := createNativeAuthenticatorWithUsers(t, []map[string]any{
		{
			"username":      "testuser",
			"password_hash": hash,
			"groups":        []string{"admin"},
			"email":         "test@example.com",
			"full_name":     "Test User",
		},
	})

	if authenticator == nil {
		t.Fatal("authenticator returned nil")
	}
	if authenticator.Name() != "native" {
		t.Errorf("expected Name()=native, got %s", authenticator.Name())
	}
	if authenticator.Type() != "native" {
		t.Errorf("expected Type()=native, got %s", authenticator.Type())
	}
}

func TestNativeAuthenticator_Authenticate_Success(t *testing.T) {
	hash, err := auth.HashPassword("password")
	if err != nil {
		t.Fatal(err)
	}

	authenticator := createNativeAuthenticatorWithUsers(t, []map[string]any{
		{
			"username":      "testuser",
			"password_hash": hash,
			"groups":        []string{"admin", "users"},
			"email":         "test@example.com",
			"full_name":     "Test User",
		},
	})
	ctx := context.Background()

	user, err := authenticator.Authenticate(ctx, "testuser", "password")
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
	if len(user.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(user.Groups))
	}
}

func TestNativeAuthenticator_Authenticate_UserNotFound(t *testing.T) {
	authenticator := createNativeAuthenticatorWithUsers(t, nil)

	_, err := authenticator.Authenticate(context.Background(), "nonexistent", "password")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestNativeAuthenticator_Authenticate_InvalidPassword(t *testing.T) {
	hash, _ := auth.HashPassword("correctpassword")
	authenticator := createNativeAuthenticatorWithUsers(t, []map[string]any{
		{"username": "testuser", "password_hash": hash},
	})

	_, err := authenticator.Authenticate(context.Background(), "testuser", "wrongpassword")
	if err == nil {
		t.Fatal("expected error for invalid password")
	}
}

func TestNativeAuthenticator_Authenticate_DisabledUser(t *testing.T) {
	hash, _ := auth.HashPassword("password")
	authenticator := createNativeAuthenticatorWithUsers(t, []map[string]any{
		{"username": "disabled", "password_hash": hash, "disabled": true},
	})

	_, err := authenticator.Authenticate(context.Background(), "disabled", "password")
	if err == nil {
		t.Fatal("expected error for disabled user")
	}
}

// UserManager is an interface for authenticators that support dynamic user management.
type UserManager interface {
	AddUser(username, passwordHash string, groups []string, email, fullName string, disabled bool) error
	RemoveUser(username string) error
}

func TestNativeAuthenticator_AddUser(t *testing.T) {
	authenticator := createNativeAuthenticatorWithUsers(t, nil)

	// Cast to UserManager to access AddUser
	um, ok := authenticator.(UserManager)
	if !ok {
		t.Skip("authenticator does not implement UserManager - skipping AddUser test")
	}

	hash, _ := auth.HashPassword("password")
	err := um.AddUser("newuser", hash, []string{"users"}, "", "", false)
	if err != nil {
		t.Fatalf("AddUser failed: %v", err)
	}

	// Verify we can authenticate
	user, err := authenticator.Authenticate(context.Background(), "newuser", "password")
	if err != nil {
		t.Fatalf("Authenticate failed after AddUser: %v", err)
	}
	if user.Username != "newuser" {
		t.Errorf("expected Username=newuser, got %s", user.Username)
	}
}

func TestNativeAuthenticator_RemoveUser(t *testing.T) {
	hash, _ := auth.HashPassword("password")
	authenticator := createNativeAuthenticatorWithUsers(t, []map[string]any{
		{"username": "toremove", "password_hash": hash},
	})

	// Verify user exists
	_, err := authenticator.Authenticate(context.Background(), "toremove", "password")
	if err != nil {
		t.Fatal("user should exist before removal")
	}

	// Cast to UserManager to access RemoveUser
	um, ok := authenticator.(UserManager)
	if !ok {
		t.Skip("authenticator does not implement UserManager - skipping RemoveUser test")
	}

	// Remove user
	err = um.RemoveUser("toremove")
	if err != nil {
		t.Fatalf("RemoveUser failed: %v", err)
	}

	// Verify user no longer exists
	_, err = authenticator.Authenticate(context.Background(), "toremove", "password")
	if err == nil {
		t.Fatal("expected error after user removal")
	}
}

func TestNativeAuthenticator_HashPassword(t *testing.T) {
	hash, err := auth.HashPassword("testpassword")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Hash should be non-empty
	if len(hash) == 0 {
		t.Error("hash is empty")
	}

	// Hash should start with bcrypt prefix
	if hash[0:4] != "$2a$" {
		t.Errorf("expected bcrypt hash prefix, got %s", hash[0:4])
	}
}

func TestNativePlugin_Registration(t *testing.T) {
	plugin, ok := auth.GetPlugin("native")
	if !ok {
		t.Fatal("native plugin not registered")
	}
	if plugin.Type() != "native" {
		t.Errorf("expected plugin type native, got %s", plugin.Type())
	}
}

func TestNativePlugin_ValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("native")
	if !ok {
		t.Fatal("native plugin not registered")
	}

	// Empty config requires users field
	err := plugin.ValidateConfig(map[string]any{})
	if err == nil {
		t.Error("expected validation error for empty config")
	}

	// Empty users list is valid
	err = plugin.ValidateConfig(map[string]any{
		"users": []map[string]any{},
	})
	if err != nil {
		t.Errorf("unexpected validation error for empty users list: %v", err)
	}

	// Config with users is valid
	err = plugin.ValidateConfig(map[string]any{
		"users": []map[string]any{
			{"username": "test", "password_hash": "$2a$12$..."},
		},
	})
	if err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}
