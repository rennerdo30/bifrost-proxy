package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoneAuthenticator(t *testing.T) {
	auth := NewNoneAuthenticator()

	assert.Equal(t, "none", auth.Name())
	assert.Equal(t, "none", auth.Type())

	// Should always succeed
	ctx := context.Background()
	user, err := auth.Authenticate(ctx, "any", "thing")
	require.NoError(t, err)
	assert.Equal(t, "anonymous", user.Username)
}

func TestNativeAuthenticator(t *testing.T) {
	// Create password hash for "password123"
	hash, err := HashPassword("password123")
	require.NoError(t, err)

	cfg := NativeConfig{
		Users: []NativeUserConfig{
			{
				Username:     "admin",
				PasswordHash: hash,
				Groups:       []string{"admins"},
				Email:        "admin@example.com",
			},
			{
				Username:     "disabled",
				PasswordHash: hash,
				Disabled:     true,
			},
		},
	}

	auth := NewNativeAuthenticator(cfg)

	assert.Equal(t, "native", auth.Name())
	assert.Equal(t, "native", auth.Type())

	ctx := context.Background()

	t.Run("valid credentials", func(t *testing.T) {
		user, err := auth.Authenticate(ctx, "admin", "password123")
		require.NoError(t, err)
		assert.Equal(t, "admin", user.Username)
		assert.Equal(t, []string{"admins"}, user.Groups)
		assert.Equal(t, "admin@example.com", user.Email)
	})

	t.Run("wrong password", func(t *testing.T) {
		_, err := auth.Authenticate(ctx, "admin", "wrongpassword")
		assert.Error(t, err)
		assert.True(t, IsInvalidCredentials(err))
	})

	t.Run("user not found", func(t *testing.T) {
		_, err := auth.Authenticate(ctx, "unknown", "password")
		assert.Error(t, err)
	})

	t.Run("disabled user", func(t *testing.T) {
		_, err := auth.Authenticate(ctx, "disabled", "password123")
		assert.Error(t, err)
	})
}

func TestNativeAuthenticator_AddRemoveUser(t *testing.T) {
	auth := NewNativeAuthenticator(NativeConfig{})

	hash, _ := HashPassword("test")
	err := auth.AddUser(NativeUserConfig{
		Username:     "newuser",
		PasswordHash: hash,
	})
	require.NoError(t, err)

	// Should be able to authenticate
	ctx := context.Background()
	_, err = auth.Authenticate(ctx, "newuser", "test")
	require.NoError(t, err)

	// Remove user
	err = auth.RemoveUser("newuser")
	require.NoError(t, err)

	// Should fail now
	_, err = auth.Authenticate(ctx, "newuser", "test")
	assert.Error(t, err)
}

func TestHashPassword(t *testing.T) {
	password := "mysecretpassword"

	hash1, err := HashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash1)

	hash2, err := HashPassword(password)
	require.NoError(t, err)

	// Same password should produce different hashes (due to salt)
	assert.NotEqual(t, hash1, hash2)
}

func TestAuthErrors(t *testing.T) {
	err := NewAuthError("ldap", "connect", ErrConnectionFailed)

	assert.Contains(t, err.Error(), "ldap")
	assert.Contains(t, err.Error(), "connect")

	// Should unwrap
	assert.True(t, IsInvalidCredentials(NewAuthError("test", "op", ErrInvalidCredentials)))
	assert.True(t, IsAuthRequired(NewAuthError("test", "op", ErrAuthRequired)))
}
