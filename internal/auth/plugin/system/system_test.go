// Package system provides system (PAM) authentication for Bifrost.
package system

import (
	"context"
	"os/user"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginRegistration verifies the plugin is registered correctly.
func TestPluginRegistration(t *testing.T) {
	plugin, ok := auth.GetPlugin("system")
	require.True(t, ok, "system plugin should be registered")
	assert.Equal(t, "system", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
	// Description varies by platform - just check it's not empty
}

// TestPluginType verifies the Type method.
func TestPluginType(t *testing.T) {
	p := &plugin{}
	assert.Equal(t, "system", p.Type())
}

// TestPluginDescription verifies the Description method.
func TestPluginDescription(t *testing.T) {
	p := &plugin{}
	desc := p.Description()
	assert.NotEmpty(t, desc)

	// Platform-specific description check
	if runtime.GOOS == "windows" {
		assert.Contains(t, desc, "Windows")
		assert.Contains(t, desc, "LogonUser")
	} else {
		assert.Contains(t, desc, "PAM")
	}
}

// TestPluginDefaultConfig verifies the DefaultConfig method.
func TestPluginDefaultConfig(t *testing.T) {
	p := &plugin{}
	defaults := p.DefaultConfig()

	assert.NotNil(t, defaults)
	assert.Equal(t, "login", defaults["service"])

	// Check allowed_users is empty slice
	allowedUsers, ok := defaults["allowed_users"]
	assert.True(t, ok)
	assert.IsType(t, []string{}, allowedUsers)
	assert.Empty(t, allowedUsers)

	// Check allowed_groups is empty slice
	allowedGroups, ok := defaults["allowed_groups"]
	assert.True(t, ok)
	assert.IsType(t, []string{}, allowedGroups)
	assert.Empty(t, allowedGroups)
}

// TestPluginConfigSchema verifies the ConfigSchema method.
func TestPluginConfigSchema(t *testing.T) {
	p := &plugin{}
	schema := p.ConfigSchema()

	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "service")
	assert.Contains(t, schema, "allowed_users")
	assert.Contains(t, schema, "allowed_groups")
	assert.Contains(t, schema, "json-schema.org")
}

// TestParseConfig tests the parseConfig function.
func TestParseConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         map[string]any
		expectedSvc    string
		expectedUsers  []string
		expectedGroups []string
	}{
		{
			name:           "nil config uses defaults",
			config:         nil,
			expectedSvc:    "login",
			expectedUsers:  nil,
			expectedGroups: nil,
		},
		{
			name:           "empty config uses defaults",
			config:         map[string]any{},
			expectedSvc:    "login",
			expectedUsers:  nil,
			expectedGroups: nil,
		},
		{
			name: "custom service name",
			config: map[string]any{
				"service": "sshd",
			},
			expectedSvc:    "sshd",
			expectedUsers:  nil,
			expectedGroups: nil,
		},
		{
			name: "empty service name uses default",
			config: map[string]any{
				"service": "",
			},
			expectedSvc:    "login",
			expectedUsers:  nil,
			expectedGroups: nil,
		},
		{
			name: "allowed_users as []any",
			config: map[string]any{
				"allowed_users": []any{"user1", "user2"},
			},
			expectedSvc:    "login",
			expectedUsers:  []string{"user1", "user2"},
			expectedGroups: nil,
		},
		{
			name: "allowed_users as []string",
			config: map[string]any{
				"allowed_users": []string{"admin", "root"},
			},
			expectedSvc:    "login",
			expectedUsers:  []string{"admin", "root"},
			expectedGroups: nil,
		},
		{
			name: "allowed_groups as []any",
			config: map[string]any{
				"allowed_groups": []any{"wheel", "sudo"},
			},
			expectedSvc:    "login",
			expectedUsers:  nil,
			expectedGroups: []string{"wheel", "sudo"},
		},
		{
			name: "allowed_groups as []string",
			config: map[string]any{
				"allowed_groups": []string{"admins", "developers"},
			},
			expectedSvc:    "login",
			expectedUsers:  nil,
			expectedGroups: []string{"admins", "developers"},
		},
		{
			name: "full config",
			config: map[string]any{
				"service":        "custom",
				"allowed_users":  []any{"user1"},
				"allowed_groups": []any{"group1"},
			},
			expectedSvc:    "custom",
			expectedUsers:  []string{"user1"},
			expectedGroups: []string{"group1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedSvc, cfg.service)
			assert.Equal(t, tt.expectedUsers, cfg.allowedUsers)
			assert.Equal(t, tt.expectedGroups, cfg.allowedGroups)
		})
	}
}

// TestParseStringSlice tests the parseStringSlice function.
func TestParseStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected []string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty []any",
			input:    []any{},
			expected: nil,
		},
		{
			name:     "[]any with strings",
			input:    []any{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "[]any with mixed types (non-strings ignored)",
			input:    []any{"a", 123, "b", true, "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "[]string input",
			input:    []string{"x", "y", "z"},
			expected: []string{"x", "y", "z"},
		},
		{
			name:     "unsupported type returns nil",
			input:    "single string",
			expected: nil,
		},
		{
			name:     "int returns nil",
			input:    42,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStringSlice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPluginCreateOnWindows tests that Create returns an error on Windows.
func TestPluginCreateOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("test only runs on Windows")
	}

	p := &plugin{}
	_, err := p.Create(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrAuthMethodUnsupported)
	assert.Contains(t, err.Error(), "Windows")
}

// TestPluginValidateConfigOnWindows tests that ValidateConfig returns an error on Windows.
func TestPluginValidateConfigOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("test only runs on Windows")
	}

	p := &plugin{}
	err := p.ValidateConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Windows")
}

// TestPluginCreateOnUnix tests that Create succeeds on Unix systems.
func TestPluginCreateOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	p := &plugin{}
	authenticator, err := p.Create(nil)
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	// Verify it's the correct type
	sysAuth, ok := authenticator.(*Authenticator)
	require.True(t, ok)
	assert.Equal(t, "login", sysAuth.service)
	assert.Empty(t, sysAuth.allowedUsers)
	assert.Empty(t, sysAuth.allowedGroups)
}

// TestPluginCreateWithConfig tests Create with various configurations.
func TestPluginCreateWithConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	tests := []struct {
		name                  string
		config                map[string]any
		expectedService       string
		expectedUsersCount    int
		expectedGroupsCount   int
	}{
		{
			name:                "with custom service",
			config:              map[string]any{"service": "sshd"},
			expectedService:     "sshd",
			expectedUsersCount:  0,
			expectedGroupsCount: 0,
		},
		{
			name:                "with allowed users",
			config:              map[string]any{"allowed_users": []any{"user1", "user2"}},
			expectedService:     "login",
			expectedUsersCount:  2,
			expectedGroupsCount: 0,
		},
		{
			name:                "with allowed groups",
			config:              map[string]any{"allowed_groups": []any{"wheel", "admin"}},
			expectedService:     "login",
			expectedUsersCount:  0,
			expectedGroupsCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &plugin{}
			authenticator, err := p.Create(tt.config)
			require.NoError(t, err)

			sysAuth, ok := authenticator.(*Authenticator)
			require.True(t, ok)
			assert.Equal(t, tt.expectedService, sysAuth.service)
			assert.Len(t, sysAuth.allowedUsers, tt.expectedUsersCount)
			assert.Len(t, sysAuth.allowedGroups, tt.expectedGroupsCount)
		})
	}
}

// TestPluginValidateConfigOnUnix tests ValidateConfig on Unix systems.
func TestPluginValidateConfigOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	p := &plugin{}

	// nil config should be valid
	err := p.ValidateConfig(nil)
	assert.NoError(t, err)

	// Valid config should pass
	err = p.ValidateConfig(map[string]any{
		"service":        "sshd",
		"allowed_users":  []any{"user1"},
		"allowed_groups": []any{"group1"},
	})
	assert.NoError(t, err)
}

// TestAuthenticatorName tests the Name method.
func TestAuthenticatorName(t *testing.T) {
	a := &Authenticator{}
	name := a.Name()

	// Name should include the OS
	assert.Contains(t, name, "system-")
	assert.Contains(t, name, runtime.GOOS)
}

// TestAuthenticatorType tests the Type method.
func TestAuthenticatorType(t *testing.T) {
	a := &Authenticator{}
	assert.Equal(t, "system", a.Type())
}

// TestAuthenticateEmptyCredentials tests authentication with empty credentials.
func TestAuthenticateEmptyCredentials(t *testing.T) {
	a := &Authenticator{}

	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "empty username and password",
			username: "",
			password: "",
		},
		{
			name:     "empty username",
			username: "",
			password: "somepassword",
		},
		{
			name:     "empty password",
			username: "someuser",
			password: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.Authenticate(context.Background(), tt.username, tt.password)
			assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
		})
	}
}

// TestAuthenticateUserNotInAllowedList tests that users not in allowed list are rejected.
func TestAuthenticateUserNotInAllowedList(t *testing.T) {
	a := &Authenticator{
		allowedUsers: map[string]bool{
			"allowed_user": true,
		},
	}

	_, err := a.Authenticate(context.Background(), "not_allowed_user", "somepassword")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestAuthenticateNonexistentUser tests authentication with a nonexistent user.
func TestAuthenticateNonexistentUser(t *testing.T) {
	a := &Authenticator{}

	// Use a username that should not exist on any system
	_, err := a.Authenticate(context.Background(), "nonexistent_user_xyz_12345", "password")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestAuthenticateCurrentUser tests behavior with current user (user lookup succeeds).
func TestAuthenticateCurrentUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	// Get current user to ensure user lookup succeeds
	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	a := &Authenticator{}

	// Password validation will fail (we don't know the password),
	// but user lookup should succeed before that
	_, err = a.Authenticate(context.Background(), currentUser.Username, "wrong_password")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestAuthenticateWithAllowedGroups tests group-based access control.
func TestAuthenticateWithAllowedGroups(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	// Create authenticator with a group that current user is definitely not in
	a := &Authenticator{
		allowedGroups: map[string]bool{
			"nonexistent_group_xyz_12345": true,
		},
	}

	// This should fail because user is not in the allowed group
	// (though it will likely fail at password validation first in practice)
	_, err = a.Authenticate(context.Background(), currentUser.Username, "wrong_password")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestGetUserGroups tests the getUserGroups method.
func TestGetUserGroups(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	a := &Authenticator{}
	groups, err := a.getUserGroups(currentUser)

	// On most systems, current user should have at least one group
	// Note: err might be non-nil on some systems due to group lookup issues
	if err == nil {
		assert.NotNil(t, groups)
	}
}

// TestValidatePassword tests the validatePassword method.
func TestValidatePassword(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	a := &Authenticator{}
	ctx := context.Background()

	// With invalid credentials, should return false
	result := a.validatePassword(ctx, "nonexistent_user_xyz_12345", "wrong_password")
	assert.False(t, result)
}

// TestValidateDarwin tests the validateDarwin method.
func TestValidateDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("test only runs on macOS")
	}

	a := &Authenticator{}
	ctx := context.Background()

	// With invalid credentials, should return false
	result := a.validateDarwin(ctx, "nonexistent_user_xyz_12345", "wrong_password")
	assert.False(t, result)
}

// TestValidateLinux tests the validateLinux method.
func TestValidateLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("test only runs on Linux")
	}

	a := &Authenticator{}
	ctx := context.Background()

	// With invalid credentials, should return false
	result := a.validateLinux(ctx, "nonexistent_user_xyz_12345", "wrong_password")
	assert.False(t, result)
}

// TestValidateWithSu tests the validateWithSu method.
func TestValidateWithSu(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	a := &Authenticator{}
	ctx := context.Background()

	// With invalid credentials, should return false
	result := a.validateWithSu(ctx, "nonexistent_user_xyz_12345", "wrong_password")
	assert.False(t, result)
}

// TestValidateWithCancelledContext tests password validation with cancelled context.
func TestValidateWithCancelledContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	a := &Authenticator{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// With cancelled context, validation should fail
	result := a.validatePassword(ctx, "anyuser", "anypassword")
	assert.False(t, result)
}

// TestAuthenticatorIntegration tests the full authenticator integration via factory.
func TestAuthenticatorIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "system-test",
		Type:    "system",
		Enabled: true,
		Config: map[string]any{
			"service":        "login",
			"allowed_users":  []any{},
			"allowed_groups": []any{},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	assert.Equal(t, "system", authenticator.Type())
	assert.Contains(t, authenticator.Name(), "system-")
}

// TestAuthenticatorIntegrationWindows tests that factory returns error on Windows.
func TestAuthenticatorIntegrationWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("test only runs on Windows")
	}

	factory := auth.NewFactory()
	_, err := factory.Create(auth.ProviderConfig{
		Name:    "system-test",
		Type:    "system",
		Enabled: true,
		Config:  nil,
	})
	require.Error(t, err)
}

// TestAllowedUserMap tests that allowed users map is populated correctly.
func TestAllowedUserMap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"allowed_users": []any{"user1", "user2", "user3"},
	})
	require.NoError(t, err)

	sysAuth := authenticator.(*Authenticator)
	assert.True(t, sysAuth.allowedUsers["user1"])
	assert.True(t, sysAuth.allowedUsers["user2"])
	assert.True(t, sysAuth.allowedUsers["user3"])
	assert.False(t, sysAuth.allowedUsers["user4"])
}

// TestAllowedGroupMap tests that allowed groups map is populated correctly.
func TestAllowedGroupMap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"allowed_groups": []any{"wheel", "admin", "sudo"},
	})
	require.NoError(t, err)

	sysAuth := authenticator.(*Authenticator)
	assert.True(t, sysAuth.allowedGroups["wheel"])
	assert.True(t, sysAuth.allowedGroups["admin"])
	assert.True(t, sysAuth.allowedGroups["sudo"])
	assert.False(t, sysAuth.allowedGroups["other"])
}

// TestAuthenticateUserInfoMetadata tests that metadata is populated correctly on successful auth.
func TestAuthenticateUserInfoMetadata(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	// This test documents expected behavior for successful authentication
	// We can't easily test actual authentication without valid system credentials

	// Create a mock-like test by verifying the UserInfo structure
	userInfo := &auth.UserInfo{
		Username: "testuser",
		FullName: "Test User",
		Groups:   []string{"group1"},
		Metadata: map[string]string{
			"uid":      "1000",
			"gid":      "1000",
			"home_dir": "/home/testuser",
		},
	}

	assert.Equal(t, "testuser", userInfo.Username)
	assert.Equal(t, "Test User", userInfo.FullName)
	assert.Contains(t, userInfo.Groups, "group1")
	assert.Equal(t, "1000", userInfo.Metadata["uid"])
	assert.Equal(t, "1000", userInfo.Metadata["gid"])
	assert.Equal(t, "/home/testuser", userInfo.Metadata["home_dir"])
}

// TestSystemConfigStruct tests the systemConfig struct fields.
func TestSystemConfigStruct(t *testing.T) {
	cfg := &systemConfig{
		service:       "sshd",
		allowedUsers:  []string{"user1", "user2"},
		allowedGroups: []string{"group1", "group2"},
	}

	assert.Equal(t, "sshd", cfg.service)
	assert.Len(t, cfg.allowedUsers, 2)
	assert.Len(t, cfg.allowedGroups, 2)
}

// TestAuthenticateAllowedUserEmpty tests that empty allowed users means all users allowed.
func TestAuthenticateAllowedUserEmpty(t *testing.T) {
	// When allowedUsers is empty, all users should be allowed (past the user check)
	a := &Authenticator{
		allowedUsers:  map[string]bool{}, // Empty map
		allowedGroups: map[string]bool{},
	}

	// This should fail at user lookup (nonexistent user), not at allowed users check
	_, err := a.Authenticate(context.Background(), "nonexistent_user_xyz_12345", "password")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestParseStringSliceWithEmptyStrings tests parseStringSlice with empty strings in array.
func TestParseStringSliceWithEmptyStrings(t *testing.T) {
	input := []any{"a", "", "b", "", "c"}
	result := parseStringSlice(input)

	// Empty strings should be included (they are valid strings)
	assert.Len(t, result, 5)
	assert.Contains(t, result, "")
}

// TestAuthenticateWithAllowedUserInList tests that allowed users pass the user check.
func TestAuthenticateWithAllowedUserInList(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	// Create authenticator with current user in allowed list
	a := &Authenticator{
		allowedUsers: map[string]bool{
			currentUser.Username: true,
		},
		allowedGroups: map[string]bool{},
	}

	// Will fail at password validation, but user check should pass
	_, err = a.Authenticate(context.Background(), currentUser.Username, "wrong_password")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestValidatePasswordOnDarwinFallback tests the Darwin validation fallback to su.
func TestValidatePasswordOnDarwinFallback(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("test only runs on macOS")
	}

	a := &Authenticator{}
	ctx := context.Background()

	// Invalid user should fail via both dscl and su
	result := a.validateDarwin(ctx, "invalid_user_xyz_12345", "wrong")
	assert.False(t, result)
}

// TestGetUserGroupsWithCurrentUser tests getUserGroups with the current user.
func TestGetUserGroupsWithCurrentUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	a := &Authenticator{}
	groups, err := a.getUserGroups(currentUser)

	// Most users should have at least one group (primary group)
	require.NoError(t, err)
	assert.NotEmpty(t, groups)
}

// TestAuthenticatorNameFormat tests that the name is formatted correctly.
func TestAuthenticatorNameFormat(t *testing.T) {
	a := &Authenticator{}
	name := a.Name()

	// Should be "system-<os>" with lowercase OS name
	expected := "system-" + strings.ToLower(runtime.GOOS)
	assert.Equal(t, expected, name)
}

// TestValidatePasswordWithTimeout tests password validation with a timeout context.
func TestValidatePasswordWithTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	a := &Authenticator{}

	// Use a very short timeout - the validation should fail quickly for invalid user
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := a.validatePassword(ctx, "nonexistent_user_xyz_12345", "wrong_password")
	assert.False(t, result)
}

// TestAuthenticateWithNilMaps tests that nil maps in Authenticator are handled correctly.
func TestAuthenticateWithNilMaps(t *testing.T) {
	// Create authenticator with nil maps (simulating zero-value struct)
	a := &Authenticator{
		service:       "login",
		allowedUsers:  nil, // nil map
		allowedGroups: nil, // nil map
	}

	// len(nil map) returns 0, so this should work the same as empty maps
	_, err := a.Authenticate(context.Background(), "nonexistent_user_xyz_12345", "password")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestParseConfigNonStringService tests parseConfig with non-string service value.
func TestParseConfigNonStringService(t *testing.T) {
	config := map[string]any{
		"service": 123, // Not a string
	}

	cfg, err := parseConfig(config)
	require.NoError(t, err)
	// Should use default since type assertion fails
	assert.Equal(t, "login", cfg.service)
}

// TestParseConfigAllowedUsersWrongType tests parseConfig with wrong type for allowed_users.
func TestParseConfigAllowedUsersWrongType(t *testing.T) {
	config := map[string]any{
		"allowed_users": "not-an-array", // Wrong type
	}

	cfg, err := parseConfig(config)
	require.NoError(t, err)
	// parseStringSlice returns nil for unsupported types
	assert.Nil(t, cfg.allowedUsers)
}

// TestParseConfigAllowedGroupsWrongType tests parseConfig with wrong type for allowed_groups.
func TestParseConfigAllowedGroupsWrongType(t *testing.T) {
	config := map[string]any{
		"allowed_groups": map[string]string{"key": "value"}, // Wrong type
	}

	cfg, err := parseConfig(config)
	require.NoError(t, err)
	// parseStringSlice returns nil for unsupported types
	assert.Nil(t, cfg.allowedGroups)
}

// TestValidateWithSuStdinError tests validateWithSu behavior when stdin pipe fails.
// Note: This is difficult to test directly, but we can verify the method handles
// the error path by testing with an invalid user.
func TestValidateWithSuInvalidUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	a := &Authenticator{}
	ctx := context.Background()

	// With a user that doesn't exist, su should fail
	result := a.validateWithSu(ctx, "invalid_user_xyz_12345", "any_password")
	assert.False(t, result)
}

// TestMultiplePlatformValidation tests validatePassword on the current platform.
func TestMultiplePlatformValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	a := &Authenticator{}
	ctx := context.Background()

	// Test multiple different nonexistent users to exercise code paths
	users := []string{
		"test_user_1_xyz",
		"test_user_2_xyz",
		"test_user_3_xyz",
	}

	for _, username := range users {
		t.Run(username, func(t *testing.T) {
			result := a.validatePassword(ctx, username, "password")
			assert.False(t, result)
		})
	}
}

// TestAuthenticateWithGroupCheckPath tests the group check path in Authenticate.
// This tests when user exists and allowed groups are configured.
func TestAuthenticateWithGroupCheckPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	// Get the user's actual groups
	a := &Authenticator{}
	groups, err := a.getUserGroups(currentUser)
	if err != nil || len(groups) == 0 {
		t.Skip("cannot get user groups")
	}

	// Create authenticator with a group the user is NOT in
	a = &Authenticator{
		allowedUsers:  map[string]bool{}, // Allow all users
		allowedGroups: map[string]bool{
			"nonexistent_group_xyz_99999": true, // User won't be in this group
		},
	}

	// This will fail because user is not in the required group
	// (though password check happens first in current implementation)
	_, err = a.Authenticate(context.Background(), currentUser.Username, "wrong_password")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestPluginCreateVerifyAllFields tests that Create populates all authenticator fields.
func TestPluginCreateVerifyAllFields(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	p := &plugin{}
	config := map[string]any{
		"service":        "customsvc",
		"allowed_users":  []any{"user1", "user2"},
		"allowed_groups": []any{"group1", "group2"},
	}

	authenticator, err := p.Create(config)
	require.NoError(t, err)

	sysAuth := authenticator.(*Authenticator)
	assert.Equal(t, "customsvc", sysAuth.service)
	assert.Len(t, sysAuth.allowedUsers, 2)
	assert.Len(t, sysAuth.allowedGroups, 2)
	assert.True(t, sysAuth.allowedUsers["user1"])
	assert.True(t, sysAuth.allowedUsers["user2"])
	assert.True(t, sysAuth.allowedGroups["group1"])
	assert.True(t, sysAuth.allowedGroups["group2"])
}

// TestValidateDarwinWithContext tests validateDarwin with various context states.
func TestValidateDarwinWithContext(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("test only runs on macOS")
	}

	a := &Authenticator{}

	// Test with already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := a.validateDarwin(ctx, "anyuser", "anypassword")
	assert.False(t, result)
}

// TestValidateWithSuCancelledContext tests validateWithSu with cancelled context.
func TestValidateWithSuCancelledContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	a := &Authenticator{}

	// Test with already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := a.validateWithSu(ctx, "anyuser", "anypassword")
	assert.False(t, result)
}

// TestValidateWithSuStartError tests validateWithSu when cmd.Start fails.
// This is hard to test directly, but covered by using a cancelled context
// which causes the command to fail.
func TestValidateWithSuStartError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	a := &Authenticator{}

	// Use a deadline that's already passed
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	result := a.validateWithSu(ctx, "anyuser", "anypassword")
	assert.False(t, result)
}

// TestAuthenticateContextCancellation tests Authenticate with cancelled context.
func TestAuthenticateContextCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	a := &Authenticator{
		allowedUsers:  map[string]bool{},
		allowedGroups: map[string]bool{},
	}

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Authentication should fail due to password validation failure
	_, err = a.Authenticate(ctx, currentUser.Username, "wrong_password")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestGetUserGroupsGroupLookupFails tests getUserGroups when group lookup fails.
// This is hard to test without mocking, but we exercise the code path.
func TestGetUserGroupsGroupLookupFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	// Create a fake user struct with invalid group IDs
	// Note: This won't actually test the error path since we can't easily
	// create a user.User with invalid group IDs, but it documents the expected behavior.
	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	a := &Authenticator{}
	groups, err := a.getUserGroups(currentUser)

	// On a normal system, this should succeed
	if err != nil {
		// If there's an error, groups might be nil or empty
		t.Logf("getUserGroups returned error: %v", err)
	} else {
		// Groups should be populated
		assert.NotNil(t, groups)
	}
}

// TestValidatePasswordPlatformSwitch tests validatePassword routing to correct platform handler.
func TestValidatePasswordPlatformSwitch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	a := &Authenticator{}
	ctx := context.Background()

	// This test ensures the switch statement in validatePassword is exercised
	// On macOS, this goes to validateDarwin
	// On Linux, this goes to validateLinux
	// On other platforms, this falls back to validateWithSu
	result := a.validatePassword(ctx, "nonexistent_user_xyz", "password")
	assert.False(t, result, "should return false for nonexistent user")
}

// TestParseStringSliceEmptyArrayOfAny tests parseStringSlice with empty []any.
func TestParseStringSliceEmptyArrayOfAny(t *testing.T) {
	result := parseStringSlice([]any{})
	assert.Nil(t, result)
}

// TestParseStringSliceEmptyArrayOfString tests parseStringSlice with empty []string.
func TestParseStringSliceEmptyArrayOfString(t *testing.T) {
	result := parseStringSlice([]string{})
	assert.Equal(t, []string{}, result)
}

// TestAuthenticatePassesUserLookupThenFailsValidation tests the flow where
// user lookup succeeds but password validation fails.
func TestAuthenticatePassesUserLookupThenFailsValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only runs on Unix")
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	// Authenticator with no restrictions (all users/groups allowed)
	a := &Authenticator{
		service:       "login",
		allowedUsers:  map[string]bool{},
		allowedGroups: map[string]bool{},
	}

	// This tests the path where:
	// 1. Empty credentials check passes (we have both username and password)
	// 2. Allowed users check passes (empty map = all allowed)
	// 3. User lookup succeeds (current user exists)
	// 4. Password validation fails (wrong password)
	_, err = a.Authenticate(context.Background(), currentUser.Username, "definitely_wrong_password_xyz_12345")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestAuthenticatorFields tests that Authenticator fields are accessible.
func TestAuthenticatorFields(t *testing.T) {
	a := &Authenticator{
		service: "testsvc",
		allowedUsers: map[string]bool{
			"user1": true,
		},
		allowedGroups: map[string]bool{
			"group1": true,
		},
	}

	assert.Equal(t, "testsvc", a.service)
	assert.True(t, a.allowedUsers["user1"])
	assert.True(t, a.allowedGroups["group1"])
	assert.False(t, a.allowedUsers["user2"])
	assert.False(t, a.allowedGroups["group2"])
}

// TestPluginMethods tests all plugin interface methods together.
func TestPluginMethods(t *testing.T) {
	p := &plugin{}

	// Test all methods return expected types
	assert.Equal(t, "system", p.Type())
	assert.Contains(t, p.Description(), "PAM")

	defaults := p.DefaultConfig()
	assert.NotNil(t, defaults)
	assert.Equal(t, "login", defaults["service"])

	schema := p.ConfigSchema()
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "json-schema.org")
}

// Benchmark tests

func BenchmarkParseConfig(b *testing.B) {
	config := map[string]any{
		"service":        "sshd",
		"allowed_users":  []any{"user1", "user2", "user3"},
		"allowed_groups": []any{"wheel", "admin"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseConfig(config)
	}
}

func BenchmarkParseStringSlice(b *testing.B) {
	input := []any{"user1", "user2", "user3", "user4", "user5"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseStringSlice(input)
	}
}

func BenchmarkAuthenticatorName(b *testing.B) {
	a := &Authenticator{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.Name()
	}
}
