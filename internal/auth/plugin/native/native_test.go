// Package native provides username/password authentication with bcrypt hashes.
package native

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// Helper function to create a valid bcrypt hash for testing.
// Pass nil for t when calling from non-test functions.
func mustHash(t *testing.T, password string) string {
	if t != nil {
		t.Helper()
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		if t != nil {
			require.NoError(t, err)
		}
		panic(err)
	}
	return string(hash)
}

// =============================================================================
// Plugin Interface Tests
// =============================================================================

func TestPlugin_Type(t *testing.T) {
	p := &plugin{}
	assert.Equal(t, "native", p.Type())
}

func TestPlugin_Description(t *testing.T) {
	p := &plugin{}
	desc := p.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Native")
	assert.Contains(t, desc, "bcrypt")
}

func TestPlugin_ConfigSchema(t *testing.T) {
	p := &plugin{}
	schema := p.ConfigSchema()
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "json-schema")
	assert.Contains(t, schema, "users")
	assert.Contains(t, schema, "username")
	assert.Contains(t, schema, "password_hash")
	assert.Contains(t, schema, "groups")
	assert.Contains(t, schema, "email")
	assert.Contains(t, schema, "full_name")
	assert.Contains(t, schema, "disabled")
}

func TestPlugin_DefaultConfig(t *testing.T) {
	p := &plugin{}
	config := p.DefaultConfig()

	assert.NotNil(t, config)
	users, ok := config["users"]
	assert.True(t, ok, "default config should contain 'users' key")

	usersSlice, ok := users.([]map[string]any)
	assert.True(t, ok, "users should be a slice of maps")
	assert.Len(t, usersSlice, 1, "default config should have one example user")

	// Check the example user has expected fields
	exampleUser := usersSlice[0]
	assert.Equal(t, "admin", exampleUser["username"])
	assert.NotEmpty(t, exampleUser["password_hash"])
	assert.Equal(t, []string{"admins"}, exampleUser["groups"])
	assert.Equal(t, "admin@example.com", exampleUser["email"])
	assert.Equal(t, "Administrator", exampleUser["full_name"])
	assert.Equal(t, false, exampleUser["disabled"])
}

func TestPlugin_Create_Success(t *testing.T) {
	p := &plugin{}
	hash := mustHash(t, "testpassword")

	config := map[string]any{
		"users": []map[string]any{
			{
				"username":      "testuser",
				"password_hash": hash,
				"groups":        []string{"admin", "users"},
				"email":         "test@example.com",
				"full_name":     "Test User",
				"disabled":      false,
			},
		},
	}

	authenticator, err := p.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	// Verify it returns a valid Authenticator
	assert.Equal(t, "native", authenticator.Name())
	assert.Equal(t, "native", authenticator.Type())
}

func TestPlugin_Create_EmptyUsers(t *testing.T) {
	p := &plugin{}

	config := map[string]any{
		"users": []map[string]any{},
	}

	authenticator, err := p.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestPlugin_Create_NilConfig(t *testing.T) {
	p := &plugin{}

	authenticator, err := p.Create(nil)
	require.Error(t, err)
	assert.Nil(t, authenticator)
	assert.Contains(t, err.Error(), "native auth config is required")
}

func TestPlugin_Create_MissingUsersField(t *testing.T) {
	p := &plugin{}

	config := map[string]any{
		"something_else": "value",
	}

	authenticator, err := p.Create(config)
	require.Error(t, err)
	assert.Nil(t, authenticator)
	assert.Contains(t, err.Error(), "'users' field is required")
}

func TestPlugin_ValidateConfig_Success(t *testing.T) {
	p := &plugin{}
	hash := mustHash(t, "password")

	config := map[string]any{
		"users": []map[string]any{
			{
				"username":      "user1",
				"password_hash": hash,
			},
		},
	}

	err := p.ValidateConfig(config)
	assert.NoError(t, err)
}

func TestPlugin_ValidateConfig_NilConfig(t *testing.T) {
	p := &plugin{}

	err := p.ValidateConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "native auth config is required")
}

func TestPlugin_ValidateConfig_MissingUsers(t *testing.T) {
	p := &plugin{}

	err := p.ValidateConfig(map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'users' field is required")
}

// =============================================================================
// parseUsersConfig Tests
// =============================================================================

func TestParseUsersConfig_NilConfig(t *testing.T) {
	users, err := parseUsersConfig(nil)
	require.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "native auth config is required")
}

func TestParseUsersConfig_MissingUsersField(t *testing.T) {
	config := map[string]any{
		"other": "value",
	}

	users, err := parseUsersConfig(config)
	require.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "'users' field is required")
}

func TestParseUsersConfig_UsersNotArray(t *testing.T) {
	config := map[string]any{
		"users": "not_an_array",
	}

	users, err := parseUsersConfig(config)
	require.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "'users' must be an array")
}

func TestParseUsersConfig_UsersAsSliceOfAny(t *testing.T) {
	hash := mustHash(nil, "password")

	config := map[string]any{
		"users": []any{
			map[string]any{
				"username":      "user1",
				"password_hash": hash,
				"groups":        []any{"admin", "users"},
				"email":         "user1@example.com",
				"full_name":     "User One",
				"disabled":      false,
			},
		},
	}

	users, err := parseUsersConfig(config)
	require.NoError(t, err)
	require.Len(t, users, 1)

	assert.Equal(t, "user1", users[0].Username)
	assert.Equal(t, hash, users[0].PasswordHash)
	assert.Equal(t, []string{"admin", "users"}, users[0].Groups)
	assert.Equal(t, "user1@example.com", users[0].Email)
	assert.Equal(t, "User One", users[0].FullName)
	assert.False(t, users[0].Disabled)
}

func TestParseUsersConfig_UsersAsSliceOfMaps(t *testing.T) {
	hash := mustHash(nil, "password")

	config := map[string]any{
		"users": []map[string]any{
			{
				"username":      "user1",
				"password_hash": hash,
			},
		},
	}

	users, err := parseUsersConfig(config)
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "user1", users[0].Username)
}

func TestParseUsersConfig_UserNotObject(t *testing.T) {
	config := map[string]any{
		"users": []any{
			"not_an_object",
		},
	}

	users, err := parseUsersConfig(config)
	require.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "user at index 0 must be an object")
}

// =============================================================================
// parseUsersList Tests
// =============================================================================

func TestParseUsersList_EmptyList(t *testing.T) {
	users, err := parseUsersList([]map[string]any{})
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestParseUsersList_MissingUsername(t *testing.T) {
	usersList := []map[string]any{
		{
			"password_hash": "somehash",
		},
	}

	users, err := parseUsersList(usersList)
	require.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "user at index 0: 'username' is required")
}

func TestParseUsersList_EmptyUsername(t *testing.T) {
	usersList := []map[string]any{
		{
			"username":      "",
			"password_hash": "somehash",
		},
	}

	users, err := parseUsersList(usersList)
	require.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "'username' is required")
}

func TestParseUsersList_MissingPasswordHash(t *testing.T) {
	usersList := []map[string]any{
		{
			"username": "testuser",
		},
	}

	users, err := parseUsersList(usersList)
	require.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "user \"testuser\": 'password_hash' is required")
}

func TestParseUsersList_EmptyPasswordHash(t *testing.T) {
	usersList := []map[string]any{
		{
			"username":      "testuser",
			"password_hash": "",
		},
	}

	users, err := parseUsersList(usersList)
	require.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "'password_hash' is required")
}

func TestParseUsersList_GroupsAsSliceOfAny(t *testing.T) {
	hash := mustHash(nil, "password")

	usersList := []map[string]any{
		{
			"username":      "testuser",
			"password_hash": hash,
			"groups":        []any{"admin", "users", 123}, // 123 should be ignored (non-string)
		},
	}

	users, err := parseUsersList(usersList)
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, []string{"admin", "users"}, users[0].Groups)
}

func TestParseUsersList_GroupsAsSliceOfStrings(t *testing.T) {
	hash := mustHash(nil, "password")

	usersList := []map[string]any{
		{
			"username":      "testuser",
			"password_hash": hash,
			"groups":        []string{"admin", "users"},
		},
	}

	users, err := parseUsersList(usersList)
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, []string{"admin", "users"}, users[0].Groups)
}

func TestParseUsersList_NoGroups(t *testing.T) {
	hash := mustHash(nil, "password")

	usersList := []map[string]any{
		{
			"username":      "testuser",
			"password_hash": hash,
		},
	}

	users, err := parseUsersList(usersList)
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Nil(t, users[0].Groups)
}

func TestParseUsersList_AllFields(t *testing.T) {
	hash := mustHash(nil, "password")

	usersList := []map[string]any{
		{
			"username":      "fulluser",
			"password_hash": hash,
			"groups":        []string{"admin"},
			"email":         "full@example.com",
			"full_name":     "Full User",
			"disabled":      true,
		},
	}

	users, err := parseUsersList(usersList)
	require.NoError(t, err)
	require.Len(t, users, 1)

	u := users[0]
	assert.Equal(t, "fulluser", u.Username)
	assert.Equal(t, hash, u.PasswordHash)
	assert.Equal(t, []string{"admin"}, u.Groups)
	assert.Equal(t, "full@example.com", u.Email)
	assert.Equal(t, "Full User", u.FullName)
	assert.True(t, u.Disabled)
}

func TestParseUsersList_MultipleUsers(t *testing.T) {
	hash := mustHash(nil, "password")

	usersList := []map[string]any{
		{"username": "user1", "password_hash": hash},
		{"username": "user2", "password_hash": hash},
		{"username": "user3", "password_hash": hash},
	}

	users, err := parseUsersList(usersList)
	require.NoError(t, err)
	require.Len(t, users, 3)
	assert.Equal(t, "user1", users[0].Username)
	assert.Equal(t, "user2", users[1].Username)
	assert.Equal(t, "user3", users[2].Username)
}

// =============================================================================
// Authenticator Tests
// =============================================================================

func TestAuthenticator_Name(t *testing.T) {
	a := &Authenticator{users: make(map[string]user)}
	assert.Equal(t, "native", a.Name())
}

func TestAuthenticator_Type(t *testing.T) {
	a := &Authenticator{users: make(map[string]user)}
	assert.Equal(t, "native", a.Type())
}

func TestAuthenticator_Authenticate_Success(t *testing.T) {
	hash := mustHash(t, "correctpassword")

	a := &Authenticator{
		users: map[string]user{
			"testuser": {
				Username:     "testuser",
				PasswordHash: hash,
				Groups:       []string{"admin", "users"},
				Email:        "test@example.com",
				FullName:     "Test User",
				Disabled:     false,
			},
		},
	}

	userInfo, err := a.Authenticate(context.Background(), "testuser", "correctpassword")
	require.NoError(t, err)
	require.NotNil(t, userInfo)

	assert.Equal(t, "testuser", userInfo.Username)
	assert.Equal(t, []string{"admin", "users"}, userInfo.Groups)
	assert.Equal(t, "test@example.com", userInfo.Email)
	assert.Equal(t, "Test User", userInfo.FullName)
}

func TestAuthenticator_Authenticate_UserNotFound(t *testing.T) {
	a := &Authenticator{
		users: map[string]user{},
	}

	userInfo, err := a.Authenticate(context.Background(), "nonexistent", "password")
	require.Error(t, err)
	assert.Nil(t, userInfo)

	// Verify error type
	var authErr *auth.AuthError
	require.True(t, errors.As(err, &authErr))
	assert.Equal(t, "native", authErr.Authenticator)
	assert.Equal(t, "authenticate", authErr.Operation)
	assert.True(t, errors.Is(err, auth.ErrUserNotFound))
}

func TestAuthenticator_Authenticate_UserDisabled(t *testing.T) {
	hash := mustHash(t, "password")

	a := &Authenticator{
		users: map[string]user{
			"disableduser": {
				Username:     "disableduser",
				PasswordHash: hash,
				Disabled:     true,
			},
		},
	}

	userInfo, err := a.Authenticate(context.Background(), "disableduser", "password")
	require.Error(t, err)
	assert.Nil(t, userInfo)

	// Verify error type
	var authErr *auth.AuthError
	require.True(t, errors.As(err, &authErr))
	assert.Equal(t, "native", authErr.Authenticator)
	assert.Equal(t, "authenticate", authErr.Operation)
	assert.True(t, errors.Is(err, auth.ErrUserDisabled))
}

func TestAuthenticator_Authenticate_InvalidPassword(t *testing.T) {
	hash := mustHash(t, "correctpassword")

	a := &Authenticator{
		users: map[string]user{
			"testuser": {
				Username:     "testuser",
				PasswordHash: hash,
				Disabled:     false,
			},
		},
	}

	userInfo, err := a.Authenticate(context.Background(), "testuser", "wrongpassword")
	require.Error(t, err)
	assert.Nil(t, userInfo)

	// Verify error type
	var authErr *auth.AuthError
	require.True(t, errors.As(err, &authErr))
	assert.Equal(t, "native", authErr.Authenticator)
	assert.Equal(t, "authenticate", authErr.Operation)
	assert.True(t, errors.Is(err, auth.ErrInvalidCredentials))
}

func TestAuthenticator_Authenticate_InvalidPasswordHash(t *testing.T) {
	a := &Authenticator{
		users: map[string]user{
			"testuser": {
				Username:     "testuser",
				PasswordHash: "invalid_hash_format",
				Disabled:     false,
			},
		},
	}

	userInfo, err := a.Authenticate(context.Background(), "testuser", "anypassword")
	require.Error(t, err)
	assert.Nil(t, userInfo)

	// bcrypt will fail to compare, resulting in invalid credentials error
	var authErr *auth.AuthError
	require.True(t, errors.As(err, &authErr))
	assert.True(t, errors.Is(err, auth.ErrInvalidCredentials))
}

func TestAuthenticator_Authenticate_EmptyPassword(t *testing.T) {
	hash := mustHash(t, "password")

	a := &Authenticator{
		users: map[string]user{
			"testuser": {
				Username:     "testuser",
				PasswordHash: hash,
				Disabled:     false,
			},
		},
	}

	userInfo, err := a.Authenticate(context.Background(), "testuser", "")
	require.Error(t, err)
	assert.Nil(t, userInfo)
	assert.True(t, errors.Is(err, auth.ErrInvalidCredentials))
}

func TestAuthenticator_Authenticate_ContextCancelled(t *testing.T) {
	// Context cancellation doesn't affect bcrypt comparison,
	// but we test it for completeness
	hash := mustHash(t, "password")

	a := &Authenticator{
		users: map[string]user{
			"testuser": {
				Username:     "testuser",
				PasswordHash: hash,
				Disabled:     false,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Authentication should still work since bcrypt doesn't check context
	userInfo, err := a.Authenticate(ctx, "testuser", "password")
	require.NoError(t, err)
	assert.NotNil(t, userInfo)
}

// =============================================================================
// AddUser Tests
// =============================================================================

func TestAuthenticator_AddUser_Success(t *testing.T) {
	a := &Authenticator{
		users: make(map[string]user),
	}

	hash := mustHash(t, "newpassword")
	err := a.AddUser("newuser", hash, []string{"group1", "group2"}, "new@example.com", "New User", false)
	require.NoError(t, err)

	// Verify user was added
	userInfo, err := a.Authenticate(context.Background(), "newuser", "newpassword")
	require.NoError(t, err)
	assert.Equal(t, "newuser", userInfo.Username)
	assert.Equal(t, []string{"group1", "group2"}, userInfo.Groups)
	assert.Equal(t, "new@example.com", userInfo.Email)
	assert.Equal(t, "New User", userInfo.FullName)
}

func TestAuthenticator_AddUser_OverwriteExisting(t *testing.T) {
	hash1 := mustHash(t, "oldpassword")
	hash2 := mustHash(t, "newpassword")

	a := &Authenticator{
		users: map[string]user{
			"existinguser": {
				Username:     "existinguser",
				PasswordHash: hash1,
				Email:        "old@example.com",
			},
		},
	}

	err := a.AddUser("existinguser", hash2, []string{"newgroup"}, "new@example.com", "New Name", false)
	require.NoError(t, err)

	// Verify old password no longer works
	_, err = a.Authenticate(context.Background(), "existinguser", "oldpassword")
	require.Error(t, err)

	// Verify new password works
	userInfo, err := a.Authenticate(context.Background(), "existinguser", "newpassword")
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", userInfo.Email)
	assert.Equal(t, "New Name", userInfo.FullName)
}

func TestAuthenticator_AddUser_DisabledUser(t *testing.T) {
	a := &Authenticator{
		users: make(map[string]user),
	}

	hash := mustHash(t, "password")
	err := a.AddUser("disableduser", hash, nil, "", "", true)
	require.NoError(t, err)

	// Verify user is disabled
	_, err = a.Authenticate(context.Background(), "disableduser", "password")
	require.Error(t, err)
	assert.True(t, errors.Is(err, auth.ErrUserDisabled))
}

// =============================================================================
// RemoveUser Tests
// =============================================================================

func TestAuthenticator_RemoveUser_Success(t *testing.T) {
	hash := mustHash(t, "password")

	a := &Authenticator{
		users: map[string]user{
			"toremove": {
				Username:     "toremove",
				PasswordHash: hash,
			},
		},
	}

	// Verify user exists
	_, err := a.Authenticate(context.Background(), "toremove", "password")
	require.NoError(t, err)

	// Remove user
	err = a.RemoveUser("toremove")
	require.NoError(t, err)

	// Verify user no longer exists
	_, err = a.Authenticate(context.Background(), "toremove", "password")
	require.Error(t, err)
	assert.True(t, errors.Is(err, auth.ErrUserNotFound))
}

func TestAuthenticator_RemoveUser_NonExistent(t *testing.T) {
	a := &Authenticator{
		users: make(map[string]user),
	}

	// Removing non-existent user should not error
	err := a.RemoveUser("nonexistent")
	require.NoError(t, err)
}

// =============================================================================
// HashPassword Tests
// =============================================================================

func TestHashPassword_Success(t *testing.T) {
	hash, err := HashPassword("testpassword")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify hash starts with bcrypt prefix
	assert.True(t, len(hash) > 4)
	assert.Equal(t, "$2a$", hash[:4])

	// Verify hash can be used to verify password
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("testpassword"))
	assert.NoError(t, err)
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	hash, err := HashPassword("")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// bcrypt allows empty passwords
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(""))
	assert.NoError(t, err)
}

func TestHashPassword_LongPassword(t *testing.T) {
	// bcrypt has a 72 byte limit for passwords
	// In newer Go versions, bcrypt returns an error for passwords > 72 bytes
	longPassword := string(make([]byte, 100))
	hash, err := HashPassword(longPassword)

	// Either the hash succeeds (older bcrypt truncates), or it fails with length error
	if err != nil {
		assert.Contains(t, err.Error(), "72 bytes")
	} else {
		assert.NotEmpty(t, hash)
	}
}

func TestHashPassword_ExactlyMaxLength(t *testing.T) {
	// 72 bytes is the exact limit for bcrypt
	maxPassword := make([]byte, 72)
	for i := range maxPassword {
		maxPassword[i] = 'a'
	}
	hash, err := HashPassword(string(maxPassword))
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
}

func TestHashPassword_SpecialCharacters(t *testing.T) {
	specialPassword := "p@$$w0rd!#%^&*(){}[]|\\:\";<>,.?/~`"
	hash, err := HashPassword(specialPassword)
	require.NoError(t, err)

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(specialPassword))
	assert.NoError(t, err)
}

func TestHashPassword_UnicodeCharacters(t *testing.T) {
	unicodePassword := "password123"
	hash, err := HashPassword(unicodePassword)
	require.NoError(t, err)

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(unicodePassword))
	assert.NoError(t, err)
}

func TestHashPassword_UsesCorrectCost(t *testing.T) {
	hash, err := HashPassword("testpassword")
	require.NoError(t, err)

	cost, err := bcrypt.Cost([]byte(hash))
	require.NoError(t, err)
	assert.Equal(t, bcryptCost, cost, "hash should use bcryptCost (12)")
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestAuthenticator_ConcurrentAuthenticate(t *testing.T) {
	hash := mustHash(t, "password")

	a := &Authenticator{
		users: map[string]user{
			"user1": {Username: "user1", PasswordHash: hash},
			"user2": {Username: "user2", PasswordHash: hash},
			"user3": {Username: "user3", PasswordHash: hash},
		},
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 100)

	// Run multiple concurrent authentications
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			username := "user" + string(rune('1'+idx%3))
			_, err := a.Authenticate(context.Background(), username, "password")
			if err != nil {
				errChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent authentication failed: %v", err)
	}
}

func TestAuthenticator_ConcurrentAddRemove(t *testing.T) {
	a := &Authenticator{
		users: make(map[string]user),
	}

	var wg sync.WaitGroup
	hash := mustHash(t, "password")

	// Add users concurrently
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			username := "user" + string(rune('a'+idx))
			_ = a.AddUser(username, hash, nil, "", "", false)
		}(i)
	}

	wg.Wait()

	// Remove users concurrently
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			username := "user" + string(rune('a'+idx))
			_ = a.RemoveUser(username)
		}(i)
	}

	wg.Wait()
}

func TestAuthenticator_ConcurrentMixedOperations(t *testing.T) {
	hash := mustHash(t, "password")

	a := &Authenticator{
		users: map[string]user{
			"persistent": {Username: "persistent", PasswordHash: hash},
		},
	}

	var wg sync.WaitGroup

	// Run mixed operations concurrently
	for i := 0; i < 30; i++ {
		wg.Add(3)

		// Authentication goroutine
		go func() {
			defer wg.Done()
			_, _ = a.Authenticate(context.Background(), "persistent", "password")
		}()

		// Add user goroutine
		go func(idx int) {
			defer wg.Done()
			username := "temp" + string(rune('a'+idx%26))
			_ = a.AddUser(username, hash, nil, "", "", false)
		}(i)

		// Remove user goroutine
		go func(idx int) {
			defer wg.Done()
			username := "temp" + string(rune('a'+idx%26))
			_ = a.RemoveUser(username)
		}(i)
	}

	wg.Wait()
}

// =============================================================================
// Plugin Registration Tests
// =============================================================================

func TestPlugin_Registration(t *testing.T) {
	// The init() function should have registered the plugin
	p, ok := auth.GetPlugin("native")
	require.True(t, ok, "native plugin should be registered")
	require.NotNil(t, p)
	assert.Equal(t, "native", p.Type())
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestPlugin_EndToEnd(t *testing.T) {
	p := &plugin{}

	// Create authenticator with multiple users
	hash1 := mustHash(t, "password1")
	hash2 := mustHash(t, "password2")

	config := map[string]any{
		"users": []map[string]any{
			{
				"username":      "admin",
				"password_hash": hash1,
				"groups":        []string{"admins", "users"},
				"email":         "admin@example.com",
				"full_name":     "Admin User",
				"disabled":      false,
			},
			{
				"username":      "guest",
				"password_hash": hash2,
				"groups":        []string{"guests"},
				"email":         "guest@example.com",
				"full_name":     "Guest User",
				"disabled":      false,
			},
			{
				"username":      "disabled",
				"password_hash": hash1,
				"disabled":      true,
			},
		},
	}

	// Validate config
	err := p.ValidateConfig(config)
	require.NoError(t, err)

	// Create authenticator
	authenticator, err := p.Create(config)
	require.NoError(t, err)

	// Test admin authentication
	adminInfo, err := authenticator.Authenticate(context.Background(), "admin", "password1")
	require.NoError(t, err)
	assert.Equal(t, "admin", adminInfo.Username)
	assert.Contains(t, adminInfo.Groups, "admins")

	// Test guest authentication
	guestInfo, err := authenticator.Authenticate(context.Background(), "guest", "password2")
	require.NoError(t, err)
	assert.Equal(t, "guest", guestInfo.Username)

	// Test disabled user
	_, err = authenticator.Authenticate(context.Background(), "disabled", "password1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, auth.ErrUserDisabled))

	// Test nonexistent user
	_, err = authenticator.Authenticate(context.Background(), "nonexistent", "password")
	require.Error(t, err)
	assert.True(t, errors.Is(err, auth.ErrUserNotFound))

	// Test wrong password
	_, err = authenticator.Authenticate(context.Background(), "admin", "wrongpassword")
	require.Error(t, err)
	assert.True(t, errors.Is(err, auth.ErrInvalidCredentials))

	// Test dynamic user management
	nativeAuth, ok := authenticator.(*Authenticator)
	require.True(t, ok)

	hash3 := mustHash(t, "newpassword")
	err = nativeAuth.AddUser("newuser", hash3, []string{"users"}, "new@example.com", "New User", false)
	require.NoError(t, err)

	newUserInfo, err := authenticator.Authenticate(context.Background(), "newuser", "newpassword")
	require.NoError(t, err)
	assert.Equal(t, "newuser", newUserInfo.Username)

	// Remove user and verify
	err = nativeAuth.RemoveUser("newuser")
	require.NoError(t, err)

	_, err = authenticator.Authenticate(context.Background(), "newuser", "newpassword")
	require.Error(t, err)
	assert.True(t, errors.Is(err, auth.ErrUserNotFound))
}

func TestPlugin_ConfigWithDifferentGroupFormats(t *testing.T) {
	p := &plugin{}
	hash := mustHash(t, "password")

	// Test with []any groups (common when parsing from YAML/JSON)
	config := map[string]any{
		"users": []any{
			map[string]any{
				"username":      "user1",
				"password_hash": hash,
				"groups":        []any{"group1", "group2"},
			},
		},
	}

	authenticator, err := p.Create(config)
	require.NoError(t, err)

	userInfo, err := authenticator.Authenticate(context.Background(), "user1", "password")
	require.NoError(t, err)
	assert.Equal(t, []string{"group1", "group2"}, userInfo.Groups)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkAuthenticator_Authenticate(b *testing.B) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)

	a := &Authenticator{
		users: map[string]user{
			"testuser": {
				Username:     "testuser",
				PasswordHash: string(hash),
			},
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = a.Authenticate(ctx, "testuser", "password")
	}
}

func BenchmarkHashPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = HashPassword("testpassword")
	}
}
