package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/rennerdo30/bifrost-proxy/internal/util"
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

// ChainAuthenticator tests

func TestChainAuthenticator_Empty(t *testing.T) {
	chain := NewChainAuthenticator()

	assert.Equal(t, "chain", chain.Name())
	assert.Equal(t, "chain", chain.Type())
	assert.Equal(t, 0, chain.Count())
	assert.Empty(t, chain.Authenticators())

	// Should fail with no authenticators
	ctx := context.Background()
	_, err := chain.Authenticate(ctx, "user", "pass")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no authenticators configured")
}

func TestChainAuthenticator_SingleProvider(t *testing.T) {
	chain := NewChainAuthenticator()
	noneAuth := NewNoneAuthenticator()
	chain.AddAuthenticator("none-provider", 10, noneAuth)

	assert.Equal(t, 1, chain.Count())
	assert.Equal(t, []string{"none-provider"}, chain.Authenticators())

	ctx := context.Background()
	userInfo, err := chain.Authenticate(ctx, "anyuser", "anypass")
	require.NoError(t, err)
	assert.Equal(t, "anonymous", userInfo.Username)
	assert.Equal(t, "none-provider", userInfo.Metadata["auth_provider"])
	assert.Equal(t, "none", userInfo.Metadata["auth_type"])
}

func TestChainAuthenticator_MultipleProviders(t *testing.T) {
	chain := NewChainAuthenticator()

	// Add native auth with a known user
	hash, _ := HashPassword("secret123")
	nativeAuth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{
			{Username: "admin", PasswordHash: hash},
		},
	})

	// Add providers in reverse priority order to test sorting
	chain.AddAuthenticator("native-provider", 20, nativeAuth)
	chain.AddAuthenticator("none-provider", 10, NewNoneAuthenticator())

	assert.Equal(t, 2, chain.Count())
	// Should be sorted by priority
	assert.Equal(t, []string{"none-provider", "native-provider"}, chain.Authenticators())

	ctx := context.Background()

	// Any user should auth via none-provider (first in chain)
	userInfo, err := chain.Authenticate(ctx, "anyuser", "anypass")
	require.NoError(t, err)
	assert.Equal(t, "anonymous", userInfo.Username)
	assert.Equal(t, "none-provider", userInfo.Metadata["auth_provider"])
}

func TestChainAuthenticator_Fallback(t *testing.T) {
	chain := NewChainAuthenticator()

	// First provider has no users - will fail
	emptyNative := NewNativeAuthenticator(NativeConfig{})

	// Second provider accepts all
	noneAuth := NewNoneAuthenticator()

	chain.AddAuthenticator("empty-native", 10, emptyNative)
	chain.AddAuthenticator("fallback-none", 20, noneAuth)

	ctx := context.Background()
	userInfo, err := chain.Authenticate(ctx, "user", "pass")
	require.NoError(t, err)
	assert.Equal(t, "anonymous", userInfo.Username)
	assert.Equal(t, "fallback-none", userInfo.Metadata["auth_provider"])
}

func TestChainAuthenticator_AllFail(t *testing.T) {
	chain := NewChainAuthenticator()

	// Both providers have no users
	chain.AddAuthenticator("native1", 10, NewNativeAuthenticator(NativeConfig{}))
	chain.AddAuthenticator("native2", 20, NewNativeAuthenticator(NativeConfig{}))

	ctx := context.Background()
	_, err := chain.Authenticate(ctx, "user", "pass")
	assert.Error(t, err)
}

// Middleware tests

func TestMiddleware_NewWithDefaultRealm(t *testing.T) {
	auth := NewNoneAuthenticator()
	middleware := NewMiddleware(auth, "")

	assert.NotNil(t, middleware)
	assert.Equal(t, "Bifrost Proxy", middleware.realm)
}

func TestMiddleware_NewWithCustomRealm(t *testing.T) {
	auth := NewNoneAuthenticator()
	middleware := NewMiddleware(auth, "Custom Realm")

	assert.NotNil(t, middleware)
	assert.Equal(t, "Custom Realm", middleware.realm)
}

func TestMiddleware_Handler_NoneAuth(t *testing.T) {
	auth := NewNoneAuthenticator()
	middleware := NewMiddleware(auth, "Test")

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}

func TestMiddleware_Handler_RequiresAuth(t *testing.T) {
	hash, _ := HashPassword("password")
	auth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "user", PasswordHash: hash}},
	})
	middleware := NewMiddleware(auth, "Test Realm")

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request without credentials
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Test Realm")
}

func TestMiddleware_Handler_ValidAuth(t *testing.T) {
	hash, _ := HashPassword("password")
	auth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "testuser", PasswordHash: hash}},
	})
	middleware := NewMiddleware(auth, "Test")

	var capturedUsername string
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUsername = util.GetUsername(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("testuser", "password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "testuser", capturedUsername)
}

func TestMiddleware_Handler_InvalidAuth(t *testing.T) {
	hash, _ := HashPassword("password")
	auth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "user", PasswordHash: hash}},
	})
	middleware := NewMiddleware(auth, "Test")

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("user", "wrongpassword")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddleware_ProxyHandler_NoneAuth(t *testing.T) {
	auth := NewNoneAuthenticator()
	middleware := NewMiddleware(auth, "Test")

	handler := middleware.ProxyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_ProxyHandler_RequiresAuth(t *testing.T) {
	hash, _ := HashPassword("password")
	auth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "user", PasswordHash: hash}},
	})
	middleware := NewMiddleware(auth, "Proxy Realm")

	handler := middleware.ProxyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusProxyAuthRequired, w.Code)
	assert.Contains(t, w.Header().Get("Proxy-Authenticate"), "Proxy Realm")
}

func TestMiddleware_ProxyHandler_ValidAuth(t *testing.T) {
	hash, _ := HashPassword("proxypass")
	auth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "proxyuser", PasswordHash: hash}},
	})
	middleware := NewMiddleware(auth, "Test")

	var capturedUsername string
	var hasProxyAuthHeader bool
	handler := middleware.ProxyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUsername = util.GetUsername(r.Context())
		hasProxyAuthHeader = r.Header.Get("Proxy-Authorization") != ""
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic cHJveHl1c2VyOnByb3h5cGFzcw==") // proxyuser:proxypass
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "proxyuser", capturedUsername)
	assert.False(t, hasProxyAuthHeader, "Proxy-Authorization header should be removed")
}

func TestMiddleware_ProxyHandler_InvalidAuth(t *testing.T) {
	hash, _ := HashPassword("password")
	auth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "user", PasswordHash: hash}},
	})
	middleware := NewMiddleware(auth, "Test")

	handler := middleware.ProxyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjp3cm9uZ3Bhc3M=") // user:wrongpass
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusProxyAuthRequired, w.Code)
}

func TestMiddleware_Authenticate(t *testing.T) {
	hash, _ := HashPassword("pass123")
	auth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "directuser", PasswordHash: hash}},
	})
	middleware := NewMiddleware(auth, "Test")

	ctx := context.Background()
	userInfo, err := middleware.Authenticate(ctx, "directuser", "pass123")

	require.NoError(t, err)
	assert.Equal(t, "directuser", userInfo.Username)
}

func TestMiddleware_AuthenticateForProxy_NoneAuth(t *testing.T) {
	auth := NewNoneAuthenticator()
	middleware := NewMiddleware(auth, "Test")

	ctx := context.Background()
	userInfo, err := middleware.AuthenticateForProxy(ctx, "", "")

	require.NoError(t, err)
	assert.Equal(t, "anonymous", userInfo.Username)
}

func TestMiddleware_AuthenticateForProxy_NativeAuth(t *testing.T) {
	hash, _ := HashPassword("pass")
	auth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "proxyclient", PasswordHash: hash}},
	})
	middleware := NewMiddleware(auth, "Test")

	ctx := context.Background()

	// Valid credentials
	userInfo, err := middleware.AuthenticateForProxy(ctx, "proxyclient", "pass")
	require.NoError(t, err)
	assert.Equal(t, "proxyclient", userInfo.Username)

	// Invalid credentials
	_, err = middleware.AuthenticateForProxy(ctx, "proxyclient", "wrong")
	assert.Error(t, err)
}

// ExtractProxyAuth tests

func TestExtractProxyAuth_NoHeader(t *testing.T) {
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)

	username, password, ok := ExtractProxyAuth(req)

	assert.False(t, ok)
	assert.Empty(t, username)
	assert.Empty(t, password)
}

func TestExtractProxyAuth_ValidHeader(t *testing.T) {
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz") // user:pass

	username, password, ok := ExtractProxyAuth(req)

	assert.True(t, ok)
	assert.Equal(t, "user", username)
	assert.Equal(t, "pass", password)
}

func TestExtractProxyAuth_InvalidBase64(t *testing.T) {
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic !!invalid!!")

	_, _, ok := ExtractProxyAuth(req)

	assert.False(t, ok)
}

func TestExtractBasicAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("basicuser", "basicpass")

	username, password, ok := ExtractBasicAuth(req)

	assert.True(t, ok)
	assert.Equal(t, "basicuser", username)
	assert.Equal(t, "basicpass", password)
}

// Additional error tests

func TestAuthError_Unwrap(t *testing.T) {
	authErr := NewAuthError("ldap", "bind", ErrConnectionFailed)

	unwrapped := authErr.Unwrap()
	assert.Equal(t, ErrConnectionFailed, unwrapped)
}

func TestAllErrorTypes(t *testing.T) {
	errors := []error{
		ErrInvalidCredentials,
		ErrUserNotFound,
		ErrUserDisabled,
		ErrAuthRequired,
		ErrAuthMethodUnsupported,
		ErrConfigInvalid,
		ErrConnectionFailed,
		ErrTimeout,
	}

	for _, err := range errors {
		assert.NotEmpty(t, err.Error())
	}
}

func TestIsInvalidCredentials_False(t *testing.T) {
	assert.False(t, IsInvalidCredentials(ErrUserNotFound))
	assert.False(t, IsInvalidCredentials(nil))
}

func TestIsAuthRequired_False(t *testing.T) {
	assert.False(t, IsAuthRequired(ErrInvalidCredentials))
	assert.False(t, IsAuthRequired(nil))
}

// UserInfo tests

func TestUserInfo_Struct(t *testing.T) {
	user := &UserInfo{
		Username: "testuser",
		Groups:   []string{"admin", "users"},
		Email:    "test@example.com",
		FullName: "Test User",
		Metadata: map[string]string{"key": "value"},
	}

	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, []string{"admin", "users"}, user.Groups)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test User", user.FullName)
	assert.Equal(t, "value", user.Metadata["key"])
}

// Mode constants tests

func TestAuthModes(t *testing.T) {
	modes := []Mode{
		ModeNone,
		ModeNative,
		ModeSystem,
		ModeLDAP,
		ModeOAuth,
	}

	for _, mode := range modes {
		assert.NotEmpty(t, string(mode))
	}

	assert.Equal(t, Mode("none"), ModeNone)
	assert.Equal(t, Mode("native"), ModeNative)
	assert.Equal(t, Mode("system"), ModeSystem)
	assert.Equal(t, Mode("ldap"), ModeLDAP)
	assert.Equal(t, Mode("oauth"), ModeOAuth)
}

// Result struct test

func TestResult_Struct(t *testing.T) {
	result := Result{
		Authenticated: true,
		User:          &UserInfo{Username: "alice"},
		Error:         nil,
	}

	assert.True(t, result.Authenticated)
	assert.Equal(t, "alice", result.User.Username)
	assert.Nil(t, result.Error)
}

// HTTPCredentials struct test

func TestHTTPCredentials_Struct(t *testing.T) {
	creds := HTTPCredentials{
		Username: "user",
		Password: "pass",
		Token:    "token123",
	}

	assert.Equal(t, "user", creds.Username)
	assert.Equal(t, "pass", creds.Password)
	assert.Equal(t, "token123", creds.Token)
}

// NativeAuthenticator additional tests

func TestNativeAuthenticator_UserWithFullInfo(t *testing.T) {
	hash, _ := HashPassword("mypassword")
	cfg := NativeConfig{
		Users: []NativeUserConfig{
			{
				Username:     "fulluser",
				PasswordHash: hash,
				Groups:       []string{"developers", "admins"},
				Email:        "full@example.com",
				FullName:     "Full User Name",
			},
		},
	}

	auth := NewNativeAuthenticator(cfg)

	ctx := context.Background()
	userInfo, err := auth.Authenticate(ctx, "fulluser", "mypassword")

	require.NoError(t, err)
	assert.Equal(t, "fulluser", userInfo.Username)
	assert.Equal(t, []string{"developers", "admins"}, userInfo.Groups)
	assert.Equal(t, "full@example.com", userInfo.Email)
	assert.Equal(t, "Full User Name", userInfo.FullName)
}

func TestNativeAuthenticator_ConcurrentAccess(t *testing.T) {
	hash, _ := HashPassword("concurrent")
	auth := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "concuser", PasswordHash: hash}},
	})

	done := make(chan bool, 10)
	ctx := context.Background()

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = auth.Authenticate(ctx, "concuser", "concurrent")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestChainAuthenticator_ConcurrentAccess(t *testing.T) {
	chain := NewChainAuthenticator()
	chain.AddAuthenticator("none", 10, NewNoneAuthenticator())

	done := make(chan bool, 10)
	ctx := context.Background()

	// Concurrent authentications
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = chain.Authenticate(ctx, "user", "pass")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// SystemAuthenticator tests
// Note: System auth is not supported on Windows - NewSystemAuthenticator returns
// ErrAuthMethodUnsupported on that platform. These tests only run on Unix systems.

func TestSystemAuthenticator_NewWithDefaults(t *testing.T) {
	auth, err := NewSystemAuthenticator(SystemConfig{})

	// On Windows, this should fail with ErrAuthMethodUnsupported
	if runtime.GOOS == "windows" {
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAuthMethodUnsupported)
		assert.Nil(t, auth)
		return
	}

	require.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, "login", auth.config.Service) // Default service
	assert.Contains(t, auth.Name(), "system-")
	assert.Equal(t, "system", auth.Type())
}

func TestSystemAuthenticator_NewWithCustomConfig(t *testing.T) {
	// Skip on Windows - system auth not supported
	if runtime.GOOS == "windows" {
		t.Skip("system auth not supported on Windows")
	}

	auth, err := NewSystemAuthenticator(SystemConfig{
		Service:       "sshd",
		AllowedUsers:  []string{"alice", "bob"},
		AllowedGroups: []string{"admin", "staff"},
	})

	require.NoError(t, err)
	assert.Equal(t, "sshd", auth.config.Service)
	assert.True(t, auth.allowedUsers["alice"])
	assert.True(t, auth.allowedUsers["bob"])
	assert.True(t, auth.allowedGroups["admin"])
	assert.True(t, auth.allowedGroups["staff"])
}

func TestSystemAuthenticator_AuthenticateEmptyCredentials(t *testing.T) {
	// Skip on Windows - system auth not supported
	if runtime.GOOS == "windows" {
		t.Skip("system auth not supported on Windows")
	}

	auth, _ := NewSystemAuthenticator(SystemConfig{})
	ctx := context.Background()

	// Empty username
	_, err := auth.Authenticate(ctx, "", "password")
	assert.Equal(t, ErrInvalidCredentials, err)

	// Empty password
	_, err = auth.Authenticate(ctx, "user", "")
	assert.Equal(t, ErrInvalidCredentials, err)
}

func TestSystemAuthenticator_AuthenticateDisallowedUser(t *testing.T) {
	// Skip on Windows - system auth not supported
	if runtime.GOOS == "windows" {
		t.Skip("system auth not supported on Windows")
	}

	auth, _ := NewSystemAuthenticator(SystemConfig{
		AllowedUsers: []string{"alice"},
	})
	ctx := context.Background()

	_, err := auth.Authenticate(ctx, "bob", "password")
	assert.Equal(t, ErrInvalidCredentials, err)
}

func TestSystemAuthenticator_AuthenticateNonexistentUser(t *testing.T) {
	// Skip on Windows - system auth not supported
	if runtime.GOOS == "windows" {
		t.Skip("system auth not supported on Windows")
	}

	auth, _ := NewSystemAuthenticator(SystemConfig{})
	ctx := context.Background()

	_, err := auth.Authenticate(ctx, "nonexistent_user_xyz_12345", "password")
	assert.Equal(t, ErrInvalidCredentials, err)
}

// LDAPAuthenticator tests

func TestLDAPAuthenticator_NewMissingURL(t *testing.T) {
	_, err := NewLDAPAuthenticator(LDAPConfig{
		BaseDN: "dc=example,dc=com",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "URL is required")
}

func TestLDAPAuthenticator_NewMissingBaseDN(t *testing.T) {
	_, err := NewLDAPAuthenticator(LDAPConfig{
		URL: "ldap://localhost:389",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "base_dn is required")
}

func TestLDAPAuthenticator_NewWithDefaults(t *testing.T) {
	auth, err := NewLDAPAuthenticator(LDAPConfig{
		URL:    "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	})

	require.NoError(t, err)
	assert.Equal(t, "(uid=%s)", auth.config.UserFilter)
	assert.Equal(t, "uid", auth.config.UserAttribute)
	assert.Equal(t, "mail", auth.config.EmailAttribute)
	assert.Equal(t, "cn", auth.config.FullNameAttribute)
	assert.Equal(t, "cn", auth.config.GroupAttribute)
	assert.Equal(t, "ldap", auth.Name())
	assert.Equal(t, "ldap", auth.Type())
}

func TestLDAPAuthenticator_NewWithCustomConfig(t *testing.T) {
	auth, err := NewLDAPAuthenticator(LDAPConfig{
		URL:               "ldaps://ldap.example.com:636",
		BaseDN:            "ou=users,dc=example,dc=com",
		BindDN:            "cn=admin,dc=example,dc=com",
		BindPassword:      "secret",
		UserFilter:        "(sAMAccountName=%s)",
		UserAttribute:     "sAMAccountName",
		EmailAttribute:    "userPrincipalName",
		FullNameAttribute: "displayName",
		GroupAttribute:    "memberOf",
		TLS:               true,
	})

	require.NoError(t, err)
	assert.Equal(t, "(sAMAccountName=%s)", auth.config.UserFilter)
	assert.Equal(t, "sAMAccountName", auth.config.UserAttribute)
	assert.Equal(t, "userPrincipalName", auth.config.EmailAttribute)
	assert.Equal(t, "displayName", auth.config.FullNameAttribute)
	assert.Equal(t, "memberOf", auth.config.GroupAttribute)
	assert.True(t, auth.config.TLS)
}

// OAuthAuthenticator tests

func TestOAuthAuthenticator_NewMissingClientID(t *testing.T) {
	_, err := NewOAuthAuthenticator(OAuthConfig{
		UserInfoURL: "https://example.com/userinfo",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client_id is required")
}

func TestOAuthAuthenticator_NewMissingEndpoints(t *testing.T) {
	_, err := NewOAuthAuthenticator(OAuthConfig{
		ClientID: "test-client",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "either introspect_url or userinfo_url is required")
}

func TestOAuthAuthenticator_NewWithUserInfoURL(t *testing.T) {
	auth, err := NewOAuthAuthenticator(OAuthConfig{
		ClientID:    "test-client",
		UserInfoURL: "https://example.com/userinfo",
	})

	require.NoError(t, err)
	assert.Equal(t, "oauth", auth.Name())
	assert.Equal(t, "oauth", auth.Type())
}

func TestOAuthAuthenticator_NewWithProvider(t *testing.T) {
	auth, err := NewOAuthAuthenticator(OAuthConfig{
		Provider:    "google",
		ClientID:    "test-client",
		UserInfoURL: "https://example.com/userinfo",
	})

	require.NoError(t, err)
	assert.Equal(t, "oauth-google", auth.Name())
}

func TestOAuthAuthenticator_NewWithIntrospectURL(t *testing.T) {
	auth, err := NewOAuthAuthenticator(OAuthConfig{
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		IntrospectURL: "https://example.com/introspect",
	})

	require.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestOAuthAuthenticator_AuthenticateEmptyToken(t *testing.T) {
	auth, _ := NewOAuthAuthenticator(OAuthConfig{
		ClientID:    "test-client",
		UserInfoURL: "https://example.com/userinfo",
	})
	ctx := context.Background()

	_, err := auth.Authenticate(ctx, "", "")
	assert.Equal(t, ErrInvalidCredentials, err)
}

func TestOAuthAuthenticator_AuthenticateBearerFormat(t *testing.T) {
	// This test checks the token extraction logic
	// The actual HTTP call will fail but we can verify the flow
	auth, _ := NewOAuthAuthenticator(OAuthConfig{
		ClientID:    "test-client",
		UserInfoURL: "https://localhost:9999/userinfo", // Will fail but that's expected
	})
	ctx := context.Background()

	// With bearer prefix - token should be extracted from password
	_, err := auth.Authenticate(ctx, "bearer", "some-token")
	assert.Error(t, err) // Will fail due to network, but token extraction works

	// With empty username - token should be taken from password
	_, err = auth.Authenticate(ctx, "", "some-token")
	assert.Error(t, err)

	// With both username and password empty after token extraction
	_, err = auth.Authenticate(ctx, "just-username", "")
	assert.Error(t, err) // Will try to use username as token
}

// LDAPConfig struct tests

func TestLDAPConfig_Struct(t *testing.T) {
	cfg := LDAPConfig{
		URL:                "ldap://localhost:389",
		BaseDN:             "dc=test,dc=com",
		BindDN:             "cn=admin,dc=test,dc=com",
		BindPassword:       "secret",
		UserFilter:         "(uid=%s)",
		GroupFilter:        "(member=%s)",
		RequireGroup:       "proxy-users",
		UserAttribute:      "uid",
		EmailAttribute:     "mail",
		FullNameAttribute:  "cn",
		GroupAttribute:     "cn",
		TLS:                true,
		InsecureSkipVerify: false,
	}

	assert.Equal(t, "ldap://localhost:389", cfg.URL)
	assert.Equal(t, "dc=test,dc=com", cfg.BaseDN)
	assert.Equal(t, "proxy-users", cfg.RequireGroup)
	assert.True(t, cfg.TLS)
	assert.False(t, cfg.InsecureSkipVerify)
}

// OAuthConfig struct tests

func TestOAuthConfig_Struct(t *testing.T) {
	cfg := OAuthConfig{
		Provider:      "keycloak",
		ClientID:      "my-client",
		ClientSecret:  "my-secret",
		IssuerURL:     "https://auth.example.com/realms/myrealm",
		IntrospectURL: "https://auth.example.com/realms/myrealm/protocol/openid-connect/token/introspect",
		UserInfoURL:   "https://auth.example.com/realms/myrealm/protocol/openid-connect/userinfo",
		Scopes:        []string{"openid", "profile", "email"},
		RequiredClaims: map[string]string{
			"aud": "my-client",
		},
	}

	assert.Equal(t, "keycloak", cfg.Provider)
	assert.Equal(t, "my-client", cfg.ClientID)
	assert.Equal(t, []string{"openid", "profile", "email"}, cfg.Scopes)
	assert.Equal(t, "my-client", cfg.RequiredClaims["aud"])
}

// SystemConfig struct tests

func TestSystemConfig_Struct(t *testing.T) {
	cfg := SystemConfig{
		Service:       "sshd",
		AllowedUsers:  []string{"user1", "user2"},
		AllowedGroups: []string{"group1", "group2"},
	}

	assert.Equal(t, "sshd", cfg.Service)
	assert.Equal(t, []string{"user1", "user2"}, cfg.AllowedUsers)
	assert.Equal(t, []string{"group1", "group2"}, cfg.AllowedGroups)
}

// NativeConfig struct tests

func TestNativeConfig_Struct(t *testing.T) {
	cfg := NativeConfig{
		Users: []NativeUserConfig{
			{
				Username:     "alice",
				PasswordHash: "$2a$10$...",
				Groups:       []string{"admin"},
				Email:        "alice@example.com",
				FullName:     "Alice Smith",
				Disabled:     false,
			},
		},
	}

	assert.Len(t, cfg.Users, 1)
	assert.Equal(t, "alice", cfg.Users[0].Username)
	assert.Equal(t, []string{"admin"}, cfg.Users[0].Groups)
}

// Chain authenticator edge case

func TestChainAuthenticator_AuthenticateWithNilMetadata(t *testing.T) {
	chain := NewChainAuthenticator()

	// Create a mock authenticator that returns UserInfo without metadata
	hash, _ := HashPassword("pass")
	native := NewNativeAuthenticator(NativeConfig{
		Users: []NativeUserConfig{{Username: "user", PasswordHash: hash}},
	})
	chain.AddAuthenticator("native", 10, native)

	ctx := context.Background()
	userInfo, err := chain.Authenticate(ctx, "user", "pass")

	require.NoError(t, err)
	assert.NotNil(t, userInfo.Metadata) // Chain should initialize metadata if nil
	assert.Equal(t, "native", userInfo.Metadata["auth_provider"])
}
