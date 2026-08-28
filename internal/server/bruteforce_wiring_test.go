package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// Brute-force protection existed fully tested — with no config key and no
// caller. auth.brute_force now wraps the whole provider chain: repeated failed
// logins lock the (username, source) out even with the CORRECT password.
func TestCreateAuthenticator_BruteForceWiring(t *testing.T) {
	hash, err := auth.HashPassword("correct-password")
	require.NoError(t, err)

	cfg := config.AuthConfig{
		Providers: []config.AuthProvider{
			{
				Name: "native", Type: "native", Enabled: true,
				Config: map[string]any{
					"users": []map[string]any{
						{"username": "u", "password_hash": hash},
					},
				},
			},
		},
		BruteForce: &config.BruteForceConfig{
			Enabled:     true,
			MaxAttempts: 3,
			LockoutTime: config.Duration(time.Hour),
			WindowSize:  config.Duration(time.Hour),
		},
	}

	authenticator, err := createAuthenticator(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, err = authenticator.Authenticate(ctx, "u", "wrong")
		require.Error(t, err)
	}

	// Locked out now: even the correct password is refused.
	_, err = authenticator.Authenticate(ctx, "u", "correct-password")
	require.Error(t, err, "after max_attempts failures the account/source must be locked out")

	// Without the block, the correct password works immediately after the
	// same number of failures.
	cfg.BruteForce = nil
	plain, err := createAuthenticator(cfg)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, _ = plain.Authenticate(ctx, "u", "wrong") //nolint:errcheck // failures are the point
	}
	user, err := plain.Authenticate(ctx, "u", "correct-password")
	require.NoError(t, err)
	assert.Equal(t, "u", user.Username)
}
