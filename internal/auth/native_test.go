package auth

import (
	"context"
	"testing"
)

func TestNewNativeAuthenticator(t *testing.T) {
	cfg := NativeConfig{
		Users: []NativeUserConfig{
			{
				Username:     "testuser",
				PasswordHash: "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4C0j5nFx5.5Q5z5S", // hash of "password"
				Groups:       []string{"admin"},
				Email:        "test@example.com",
				FullName:     "Test User",
			},
		},
	}

	auth := NewNativeAuthenticator(cfg)
	if auth == nil {
		t.Fatal("NewNativeAuthenticator returned nil")
	}
	if auth.Name() != "native" {
		t.Errorf("expected Name()=native, got %s", auth.Name())
	}
	if auth.Type() != "native" {
		t.Errorf("expected Type()=native, got %s", auth.Type())
	}
}

func TestNativeAuthenticator_Authenticate_Success(t *testing.T) {
	// Create a valid bcrypt hash for "password"
	hash, err := HashPassword("password")
	if err != nil {
		t.Fatal(err)
	}

	cfg := NativeConfig{
		Users: []NativeUserConfig{
			{
				Username:     "testuser",
				PasswordHash: hash,
				Groups:       []string{"admin", "users"},
				Email:        "test@example.com",
				FullName:     "Test User",
			},
		},
	}

	auth := NewNativeAuthenticator(cfg)
	ctx := context.Background()

	user, err := auth.Authenticate(ctx, "testuser", "password")
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
	cfg := NativeConfig{}
	auth := NewNativeAuthenticator(cfg)

	_, err := auth.Authenticate(context.Background(), "nonexistent", "password")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestNativeAuthenticator_Authenticate_InvalidPassword(t *testing.T) {
	hash, _ := HashPassword("correctpassword")
	cfg := NativeConfig{
		Users: []NativeUserConfig{
			{Username: "testuser", PasswordHash: hash},
		},
	}
	auth := NewNativeAuthenticator(cfg)

	_, err := auth.Authenticate(context.Background(), "testuser", "wrongpassword")
	if err == nil {
		t.Fatal("expected error for invalid password")
	}
}

func TestNativeAuthenticator_Authenticate_DisabledUser(t *testing.T) {
	hash, _ := HashPassword("password")
	cfg := NativeConfig{
		Users: []NativeUserConfig{
			{Username: "disabled", PasswordHash: hash, Disabled: true},
		},
	}
	auth := NewNativeAuthenticator(cfg)

	_, err := auth.Authenticate(context.Background(), "disabled", "password")
	if err == nil {
		t.Fatal("expected error for disabled user")
	}
}

func TestNativeAuthenticator_AddUser(t *testing.T) {
	auth := NewNativeAuthenticator(NativeConfig{})

	hash, _ := HashPassword("password")
	err := auth.AddUser(NativeUserConfig{
		Username:     "newuser",
		PasswordHash: hash,
		Groups:       []string{"users"},
	})
	if err != nil {
		t.Fatalf("AddUser failed: %v", err)
	}

	// Verify we can authenticate
	user, err := auth.Authenticate(context.Background(), "newuser", "password")
	if err != nil {
		t.Fatalf("Authenticate failed after AddUser: %v", err)
	}
	if user.Username != "newuser" {
		t.Errorf("expected Username=newuser, got %s", user.Username)
	}
}

func TestNativeAuthenticator_RemoveUser(t *testing.T) {
	hash, _ := HashPassword("password")
	cfg := NativeConfig{
		Users: []NativeUserConfig{
			{Username: "toremove", PasswordHash: hash},
		},
	}
	auth := NewNativeAuthenticator(cfg)

	// Verify user exists
	_, err := auth.Authenticate(context.Background(), "toremove", "password")
	if err != nil {
		t.Fatal("user should exist before removal")
	}

	// Remove user
	err = auth.RemoveUser("toremove")
	if err != nil {
		t.Fatalf("RemoveUser failed: %v", err)
	}

	// Verify user no longer exists
	_, err = auth.Authenticate(context.Background(), "toremove", "password")
	if err == nil {
		t.Fatal("expected error after user removal")
	}
}

func TestNativeAuthenticator_HashPassword(t *testing.T) {
	hash, err := HashPassword("testpassword")
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

func TestNativeAuthenticator_BcryptCost(t *testing.T) {
	// Verify bcrypt cost is at least 12 per security guidelines
	if bcryptCost < 12 {
		t.Errorf("bcryptCost should be at least 12, got %d", bcryptCost)
	}
}
