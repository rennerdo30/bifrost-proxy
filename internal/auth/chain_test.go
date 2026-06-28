package auth_test

import (
	"context"
	"testing"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/native"
)

func createNativeAuthenticator(t *testing.T, users []map[string]any) auth.Authenticator {
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

func TestNewChainAuthenticator(t *testing.T) {
	chain := auth.NewChainAuthenticator()
	if chain == nil {
		t.Fatal("NewChainAuthenticator returned nil")
	}
}

func TestChainAuthenticator_AddAuthenticator(t *testing.T) {
	chain := auth.NewChainAuthenticator()

	// Add a native authenticator
	native := createNativeAuthenticator(t, nil)
	chain.AddAuthenticator("native", 1, native)

	// Verify it was added
	if chain.Count() != 1 {
		t.Errorf("expected 1 authenticator, got %d", chain.Count())
	}
}

func TestChainAuthenticator_Authenticate_FirstMatch(t *testing.T) {
	chain := auth.NewChainAuthenticator()

	// Add two native authenticators
	hash, _ := auth.HashPassword("password1")
	native1 := createNativeAuthenticator(t, []map[string]any{
		{
			"username":      "user1",
			"password_hash": hash,
			"email":         "user1@example.com",
		},
	})

	hash2, _ := auth.HashPassword("password2")
	native2 := createNativeAuthenticator(t, []map[string]any{
		{
			"username":      "user2",
			"password_hash": hash2,
			"email":         "user2@example.com",
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

// skipAuthenticator is a stub that always declines to decide (ErrAuthSkip),
// mimicking e.g. an mTLS provider with no client certificate presented and
// require_client_cert=false / allow_anonymous unset.
type skipAuthenticator struct{}

func (skipAuthenticator) Authenticate(_ context.Context, _, _ string) (*auth.UserInfo, error) {
	return nil, auth.ErrAuthSkip
}
func (skipAuthenticator) Name() string { return "skip" }
func (skipAuthenticator) Type() string { return "skip" }

func TestChainAuthenticator_Authenticate_SkipContinues(t *testing.T) {
	chain := auth.NewChainAuthenticator()

	// A skip provider placed first must NOT short-circuit the chain.
	chain.AddAuthenticator("skip", 1, skipAuthenticator{})

	hash, _ := auth.HashPassword("password1")
	native := createNativeAuthenticator(t, []map[string]any{
		{"username": "user1", "password_hash": hash},
	})
	chain.AddAuthenticator("native", 2, native)

	user, err := chain.Authenticate(context.Background(), "user1", "password1")
	if err != nil {
		t.Fatalf("expected chain to continue past skip provider: %v", err)
	}
	if user.Username != "user1" {
		t.Errorf("expected user1, got %s", user.Username)
	}
	if user.Metadata["auth_provider"] != "native" {
		t.Errorf("expected native to authenticate, got %s", user.Metadata["auth_provider"])
	}
}

func TestChainAuthenticator_Authenticate_AllSkip(t *testing.T) {
	chain := auth.NewChainAuthenticator()
	chain.AddAuthenticator("skip1", 1, skipAuthenticator{})
	chain.AddAuthenticator("skip2", 2, skipAuthenticator{})

	// When every provider skips, the chain must deny (never grant access),
	// returning ErrInvalidCredentials rather than the skip sentinel.
	_, err := chain.Authenticate(context.Background(), "user", "password")
	if err == nil {
		t.Fatal("expected error when all providers skip")
	}
	if auth.IsAuthSkip(err) {
		t.Errorf("chain must not surface ErrAuthSkip to callers, got %v", err)
	}
	if !auth.IsInvalidCredentials(err) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestChainAuthenticator_Authenticate_NoMatch(t *testing.T) {
	chain := auth.NewChainAuthenticator()

	hash, _ := auth.HashPassword("password")
	native := createNativeAuthenticator(t, []map[string]any{
		{
			"username":      "user1",
			"password_hash": hash,
		},
	})

	chain.AddAuthenticator("native", 1, native)

	_, err := chain.Authenticate(context.Background(), "nonexistent", "password")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestChainAuthenticator_Authenticate_EmptyChain(t *testing.T) {
	chain := auth.NewChainAuthenticator()

	_, err := chain.Authenticate(context.Background(), "user", "password")
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
}

func TestChainAuthenticator_Name(t *testing.T) {
	chain := auth.NewChainAuthenticator()
	if chain.Name() != "chain" {
		t.Errorf("expected Name()=chain, got %s", chain.Name())
	}
}

func TestChainAuthenticator_Type(t *testing.T) {
	chain := auth.NewChainAuthenticator()
	if chain.Type() != "chain" {
		t.Errorf("expected Type()=chain, got %s", chain.Type())
	}
}
