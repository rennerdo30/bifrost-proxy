package auth

import (
	"context"
	"testing"
)

func TestNewChainAuthenticator(t *testing.T) {
	chain := NewChainAuthenticator()
	if chain == nil {
		t.Fatal("NewChainAuthenticator returned nil")
	}
}

func TestChainAuthenticator_AddAuthenticator(t *testing.T) {
	chain := NewChainAuthenticator()

	// Add a native authenticator
	native := NewNativeAuthenticator(NativeConfig{})
	chain.AddAuthenticator("native", 1, native)

	// Verify it was added
	if chain.Count() != 1 {
		t.Errorf("expected 1 authenticator, got %d", chain.Count())
	}
}

func TestChainAuthenticator_Authenticate_FirstMatch(t *testing.T) {
	chain := NewChainAuthenticator()

	// Add two native authenticators
	hash, _ := HashPassword("password1")
	native1 := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{
			{Username: "user1", PasswordHash: hash, Email: "user1@example.com"},
		},
	})

	hash2, _ := HashPassword("password2")
	native2 := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{
			{Username: "user2", PasswordHash: hash2, Email: "user2@example.com"},
		},
	})

	chain.AddAuthenticator("native1", 1, native1)
	chain.AddAuthenticator("native2", 2, native2)

	// Authenticate user from first authenticator
	user, err := chain.Authenticate(context.Background(), "user1", "password1")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if user.Username != "user1" {
		t.Errorf("expected user1, got %s", user.Username)
	}

	// Authenticate user from second authenticator
	user, err = chain.Authenticate(context.Background(), "user2", "password2")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if user.Username != "user2" {
		t.Errorf("expected user2, got %s", user.Username)
	}
}

func TestChainAuthenticator_Authenticate_NoMatch(t *testing.T) {
	chain := NewChainAuthenticator()

	hash, _ := HashPassword("password")
	native := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{
			{Username: "user1", PasswordHash: hash},
		},
	})

	chain.AddAuthenticator("native", 1, native)

	_, err := chain.Authenticate(context.Background(), "nonexistent", "password")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestChainAuthenticator_Authenticate_EmptyChain(t *testing.T) {
	chain := NewChainAuthenticator()

	_, err := chain.Authenticate(context.Background(), "user", "password")
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
}

func TestChainAuthenticator_Name(t *testing.T) {
	chain := NewChainAuthenticator()
	if chain.Name() != "chain" {
		t.Errorf("expected Name()=chain, got %s", chain.Name())
	}
}

func TestChainAuthenticator_Type(t *testing.T) {
	chain := NewChainAuthenticator()
	if chain.Type() != "chain" {
		t.Errorf("expected Type()=chain, got %s", chain.Type())
	}
}
