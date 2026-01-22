package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/apikey"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ldap"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/native"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/none"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/oauth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/system"
	"github.com/rennerdo30/bifrost-proxy/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create authenticators using the factory
func createAuthenticator(t *testing.T, cfg auth.ProviderConfig) auth.Authenticator {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(cfg)
	require.NoError(t, err)
	return authenticator
}

func TestNoneAuthenticator(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name:    "none",
		Type:    "none",
		Enabled: true,
	})

	assert.Equal(t, "none", authenticator.Name())
	assert.Equal(t, "none", authenticator.Type())

	// Should always succeed
	ctx := context.Background()
	user, err := authenticator.Authenticate(ctx, "any", "thing")
	require.NoError(t, err)
	assert.Equal(t, "anonymous", user.Username)
}

func TestNativeAuthenticator(t *testing.T) {
	// Create password hash for "password123"
	hash, err := auth.HashPassword("password123")
	require.NoError(t, err)

	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name:    "native",
		Type:    "native",
		Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{
					"username":      "admin",
					"password_hash": hash,
					"groups":        []string{"admins"},
					"email":         "admin@example.com",
				},
				{
					"username":      "disabled",
					"password_hash": hash,
					"disabled":      true,
				},
			},
		},
	})

	assert.Equal(t, "native", authenticator.Name())
	assert.Equal(t, "native", authenticator.Type())

	ctx := context.Background()

	t.Run("valid credentials", func(t *testing.T) {
		user, err := authenticator.Authenticate(ctx, "admin", "password123")
		require.NoError(t, err)
		assert.Equal(t, "admin", user.Username)
		assert.Equal(t, []string{"admins"}, user.Groups)
		assert.Equal(t, "admin@example.com", user.Email)
	})

	t.Run("wrong password", func(t *testing.T) {
		_, err := authenticator.Authenticate(ctx, "admin", "wrongpassword")
		assert.Error(t, err)
		assert.True(t, auth.IsInvalidCredentials(err))
	})

	t.Run("user not found", func(t *testing.T) {
		_, err := authenticator.Authenticate(ctx, "unknown", "password")
		assert.Error(t, err)
	})

	t.Run("disabled user", func(t *testing.T) {
		_, err := authenticator.Authenticate(ctx, "disabled", "password123")
		assert.Error(t, err)
	})
}

func TestHashPassword(t *testing.T) {
	password := "mysecretpassword"

	hash1, err := auth.HashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash1)

	hash2, err := auth.HashPassword(password)
	require.NoError(t, err)

	// Same password should produce different hashes (due to salt)
	assert.NotEqual(t, hash1, hash2)
}

func TestAuthErrors(t *testing.T) {
	err := auth.NewAuthError("ldap", "connect", auth.ErrConnectionFailed)

	assert.Contains(t, err.Error(), "ldap")
	assert.Contains(t, err.Error(), "connect")

	// Should unwrap
	assert.True(t, auth.IsInvalidCredentials(auth.NewAuthError("test", "op", auth.ErrInvalidCredentials)))
	assert.True(t, auth.IsAuthRequired(auth.NewAuthError("test", "op", auth.ErrAuthRequired)))
}

// ChainAuthenticator tests

func TestChainAuthenticator_Empty(t *testing.T) {
	chain := auth.NewChainAuthenticator()

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
	chain := auth.NewChainAuthenticator()
	noneAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})
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
	chain := auth.NewChainAuthenticator()

	// Add native auth with a known user
	hash, _ := auth.HashPassword("secret123")
	nativeAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "admin", "password_hash": hash},
			},
		},
	})
	noneAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})

	// Add providers in reverse priority order to test sorting
	chain.AddAuthenticator("native-provider", 20, nativeAuth)
	chain.AddAuthenticator("none-provider", 10, noneAuth)

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
	chain := auth.NewChainAuthenticator()

	// First provider has no users - will fail
	emptyNative := createAuthenticator(t, auth.ProviderConfig{
		Name: "empty", Type: "native", Enabled: true,
		Config: map[string]any{"users": []map[string]any{}},
	})

	// Second provider accepts all
	noneAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})

	chain.AddAuthenticator("empty-native", 10, emptyNative)
	chain.AddAuthenticator("fallback-none", 20, noneAuth)

	ctx := context.Background()
	userInfo, err := chain.Authenticate(ctx, "user", "pass")
	require.NoError(t, err)
	assert.Equal(t, "anonymous", userInfo.Username)
	assert.Equal(t, "fallback-none", userInfo.Metadata["auth_provider"])
}

func TestChainAuthenticator_AllFail(t *testing.T) {
	chain := auth.NewChainAuthenticator()

	// Both providers have no users
	native1 := createAuthenticator(t, auth.ProviderConfig{
		Name: "native1", Type: "native", Enabled: true,
		Config: map[string]any{"users": []map[string]any{}},
	})
	native2 := createAuthenticator(t, auth.ProviderConfig{
		Name: "native2", Type: "native", Enabled: true,
		Config: map[string]any{"users": []map[string]any{}},
	})

	chain.AddAuthenticator("native1", 10, native1)
	chain.AddAuthenticator("native2", 20, native2)

	ctx := context.Background()
	_, err := chain.Authenticate(ctx, "user", "pass")
	assert.Error(t, err)
}

// Middleware tests

func TestMiddleware_NewWithDefaultRealm(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})
	middleware := auth.NewMiddleware(authenticator, "")

	assert.NotNil(t, middleware)
}

func TestMiddleware_NewWithCustomRealm(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})
	middleware := auth.NewMiddleware(authenticator, "Custom Realm")

	assert.NotNil(t, middleware)
}

func TestMiddleware_Handler_NoneAuth(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

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
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test Realm")

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
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "testuser", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

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
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

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
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	handler := middleware.ProxyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_ProxyHandler_RequiresAuth(t *testing.T) {
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Proxy Realm")

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
	hash, _ := auth.HashPassword("proxypass")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "proxyuser", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

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
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

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
	hash, _ := auth.HashPassword("pass123")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "directuser", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	ctx := context.Background()
	userInfo, err := middleware.Authenticate(ctx, "directuser", "pass123")

	require.NoError(t, err)
	assert.Equal(t, "directuser", userInfo.Username)
}

func TestMiddleware_AuthenticateForProxy_NoneAuth(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	ctx := context.Background()
	userInfo, err := middleware.AuthenticateForProxy(ctx, "", "")

	require.NoError(t, err)
	assert.Equal(t, "anonymous", userInfo.Username)
}

func TestMiddleware_AuthenticateForProxy_NativeAuth(t *testing.T) {
	hash, _ := auth.HashPassword("pass")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "proxyclient", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

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

	username, password, ok := auth.ExtractProxyAuth(req)

	assert.False(t, ok)
	assert.Empty(t, username)
	assert.Empty(t, password)
}

func TestExtractProxyAuth_ValidHeader(t *testing.T) {
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz") // user:pass

	username, password, ok := auth.ExtractProxyAuth(req)

	assert.True(t, ok)
	assert.Equal(t, "user", username)
	assert.Equal(t, "pass", password)
}

func TestExtractProxyAuth_InvalidBase64(t *testing.T) {
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic !!invalid!!")

	_, _, ok := auth.ExtractProxyAuth(req)

	assert.False(t, ok)
}

func TestExtractBasicAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("basicuser", "basicpass")

	username, password, ok := auth.ExtractBasicAuth(req)

	assert.True(t, ok)
	assert.Equal(t, "basicuser", username)
	assert.Equal(t, "basicpass", password)
}

// Additional error tests

func TestAuthError_Unwrap(t *testing.T) {
	authErr := auth.NewAuthError("ldap", "bind", auth.ErrConnectionFailed)

	unwrapped := authErr.Unwrap()
	assert.Equal(t, auth.ErrConnectionFailed, unwrapped)
}

func TestAllErrorTypes(t *testing.T) {
	errors := []error{
		auth.ErrInvalidCredentials,
		auth.ErrUserNotFound,
		auth.ErrUserDisabled,
		auth.ErrAuthRequired,
		auth.ErrAuthMethodUnsupported,
		auth.ErrConfigInvalid,
		auth.ErrConnectionFailed,
		auth.ErrTimeout,
	}

	for _, err := range errors {
		assert.NotEmpty(t, err.Error())
	}
}

func TestIsInvalidCredentials_False(t *testing.T) {
	assert.False(t, auth.IsInvalidCredentials(auth.ErrUserNotFound))
	assert.False(t, auth.IsInvalidCredentials(nil))
}

func TestIsAuthRequired_False(t *testing.T) {
	assert.False(t, auth.IsAuthRequired(auth.ErrInvalidCredentials))
	assert.False(t, auth.IsAuthRequired(nil))
}

// UserInfo tests

func TestUserInfo_Struct(t *testing.T) {
	user := &auth.UserInfo{
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
	modes := []auth.Mode{
		auth.ModeNone,
		auth.ModeNative,
		auth.ModeSystem,
		auth.ModeLDAP,
		auth.ModeOAuth,
	}

	for _, mode := range modes {
		assert.NotEmpty(t, string(mode))
	}

	assert.Equal(t, auth.Mode("none"), auth.ModeNone)
	assert.Equal(t, auth.Mode("native"), auth.ModeNative)
	assert.Equal(t, auth.Mode("system"), auth.ModeSystem)
	assert.Equal(t, auth.Mode("ldap"), auth.ModeLDAP)
	assert.Equal(t, auth.Mode("oauth"), auth.ModeOAuth)
}

// Result struct test

func TestResult_Struct(t *testing.T) {
	result := auth.Result{
		Authenticated: true,
		User:          &auth.UserInfo{Username: "alice"},
		Error:         nil,
	}

	assert.True(t, result.Authenticated)
	assert.Equal(t, "alice", result.User.Username)
	assert.Nil(t, result.Error)
}

// HTTPCredentials struct test

func TestHTTPCredentials_Struct(t *testing.T) {
	creds := auth.HTTPCredentials{
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
	hash, _ := auth.HashPassword("mypassword")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{
					"username":      "fulluser",
					"password_hash": hash,
					"groups":        []string{"developers", "admins"},
					"email":         "full@example.com",
					"full_name":     "Full User Name",
				},
			},
		},
	})

	ctx := context.Background()
	userInfo, err := authenticator.Authenticate(ctx, "fulluser", "mypassword")

	require.NoError(t, err)
	assert.Equal(t, "fulluser", userInfo.Username)
	assert.Equal(t, []string{"developers", "admins"}, userInfo.Groups)
	assert.Equal(t, "full@example.com", userInfo.Email)
	assert.Equal(t, "Full User Name", userInfo.FullName)
}

func TestNativeAuthenticator_ConcurrentAccess(t *testing.T) {
	hash, _ := auth.HashPassword("concurrent")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "concuser", "password_hash": hash},
			},
		},
	})

	done := make(chan bool, 10)
	ctx := context.Background()

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = authenticator.Authenticate(ctx, "concuser", "concurrent")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestChainAuthenticator_ConcurrentAccess(t *testing.T) {
	chain := auth.NewChainAuthenticator()
	noneAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})
	chain.AddAuthenticator("none", 10, noneAuth)

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
// Note: System auth is not supported on Windows - factory will return error on that platform.

func TestSystemAuthenticator_NewWithDefaults(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name: "system", Type: "system", Enabled: true,
	})

	// On Windows, this should fail with ErrAuthMethodUnsupported
	if runtime.GOOS == "windows" {
		require.Error(t, err)
		assert.Nil(t, authenticator)
		return
	}

	require.NoError(t, err)
	assert.NotNil(t, authenticator)
	assert.Contains(t, authenticator.Name(), "system-")
	assert.Equal(t, "system", authenticator.Type())
}

func TestSystemAuthenticator_NewWithCustomConfig(t *testing.T) {
	// Skip on Windows - system auth not supported
	if runtime.GOOS == "windows" {
		t.Skip("system auth not supported on Windows")
	}

	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "system", Type: "system", Enabled: true,
		Config: map[string]any{
			"service":        "sshd",
			"allowed_users":  []string{"alice", "bob"},
			"allowed_groups": []string{"admin", "staff"},
		},
	})

	assert.NotNil(t, authenticator)
}

func TestSystemAuthenticator_AuthenticateEmptyCredentials(t *testing.T) {
	// Skip on Windows - system auth not supported
	if runtime.GOOS == "windows" {
		t.Skip("system auth not supported on Windows")
	}

	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "system", Type: "system", Enabled: true,
	})
	ctx := context.Background()

	// Empty username
	_, err := authenticator.Authenticate(ctx, "", "password")
	assert.Equal(t, auth.ErrInvalidCredentials, err)

	// Empty password
	_, err = authenticator.Authenticate(ctx, "user", "")
	assert.Equal(t, auth.ErrInvalidCredentials, err)
}

func TestSystemAuthenticator_AuthenticateDisallowedUser(t *testing.T) {
	// Skip on Windows - system auth not supported
	if runtime.GOOS == "windows" {
		t.Skip("system auth not supported on Windows")
	}

	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "system", Type: "system", Enabled: true,
		Config: map[string]any{
			"allowed_users": []string{"alice"},
		},
	})
	ctx := context.Background()

	_, err := authenticator.Authenticate(ctx, "bob", "password")
	assert.Equal(t, auth.ErrInvalidCredentials, err)
}

func TestSystemAuthenticator_AuthenticateNonexistentUser(t *testing.T) {
	// Skip on Windows - system auth not supported
	if runtime.GOOS == "windows" {
		t.Skip("system auth not supported on Windows")
	}

	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "system", Type: "system", Enabled: true,
	})
	ctx := context.Background()

	_, err := authenticator.Authenticate(ctx, "nonexistent_user_xyz_12345", "password")
	assert.Equal(t, auth.ErrInvalidCredentials, err)
}

// LDAPAuthenticator tests

func TestLDAPAuthenticator_NewMissingURL(t *testing.T) {
	factory := auth.NewFactory()
	_, err := factory.Create(auth.ProviderConfig{
		Name: "ldap", Type: "ldap", Enabled: true,
		Config: map[string]any{
			"base_dn": "dc=example,dc=com",
		},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "URL is required")
}

func TestLDAPAuthenticator_NewMissingBaseDN(t *testing.T) {
	factory := auth.NewFactory()
	_, err := factory.Create(auth.ProviderConfig{
		Name: "ldap", Type: "ldap", Enabled: true,
		Config: map[string]any{
			"url": "ldap://localhost:389",
		},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "base_dn is required")
}

func TestLDAPAuthenticator_NewWithDefaults(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "ldap", Type: "ldap", Enabled: true,
		Config: map[string]any{
			"url":     "ldap://localhost:389",
			"base_dn": "dc=example,dc=com",
		},
	})

	assert.Equal(t, "ldap", authenticator.Name())
	assert.Equal(t, "ldap", authenticator.Type())
}

// OAuthAuthenticator tests

func TestOAuthAuthenticator_NewMissingClientID(t *testing.T) {
	factory := auth.NewFactory()
	_, err := factory.Create(auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true,
		Config: map[string]any{
			"userinfo_url": "https://example.com/userinfo",
		},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client_id is required")
}

func TestOAuthAuthenticator_NewMissingEndpoints(t *testing.T) {
	factory := auth.NewFactory()
	_, err := factory.Create(auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true,
		Config: map[string]any{
			"client_id": "test-client",
		},
	})

	assert.Error(t, err)
}

func TestOAuthAuthenticator_NewWithUserInfoURL(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true,
		Config: map[string]any{
			"client_id":    "test-client",
			"userinfo_url": "https://example.com/userinfo",
		},
	})

	assert.Equal(t, "oauth", authenticator.Name())
	assert.Equal(t, "oauth", authenticator.Type())
}

func TestOAuthAuthenticator_NewWithProvider(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true,
		Config: map[string]any{
			"provider":     "google",
			"client_id":    "test-client",
			"userinfo_url": "https://example.com/userinfo",
		},
	})

	assert.Equal(t, "oauth-google", authenticator.Name())
}

func TestOAuthAuthenticator_NewWithIntrospectURL(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true,
		Config: map[string]any{
			"client_id":      "test-client",
			"client_secret":  "test-secret",
			"introspect_url": "https://example.com/introspect",
		},
	})

	assert.NotNil(t, authenticator)
}

func TestOAuthAuthenticator_AuthenticateEmptyToken(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true,
		Config: map[string]any{
			"client_id":    "test-client",
			"userinfo_url": "https://example.com/userinfo",
		},
	})
	ctx := context.Background()

	_, err := authenticator.Authenticate(ctx, "", "")
	assert.Equal(t, auth.ErrInvalidCredentials, err)
}

func TestOAuthAuthenticator_AuthenticateBearerFormat(t *testing.T) {
	// This test checks the token extraction logic
	// The actual HTTP call will fail but we can verify the flow
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true,
		Config: map[string]any{
			"client_id":    "test-client",
			"userinfo_url": "https://localhost:9999/userinfo", // Will fail but that's expected
		},
	})
	ctx := context.Background()

	// With bearer prefix - token should be extracted from password
	_, err := authenticator.Authenticate(ctx, "bearer", "some-token")
	assert.Error(t, err) // Will fail due to network, but token extraction works

	// With empty username - token should be taken from password
	_, err = authenticator.Authenticate(ctx, "", "some-token")
	assert.Error(t, err)

	// With both username and password empty after token extraction
	_, err = authenticator.Authenticate(ctx, "just-username", "")
	assert.Error(t, err) // Will try to use username as token
}

// Plugin registry tests

func TestPluginRegistry(t *testing.T) {
	// Plugins should be registered via init()
	plugins := auth.ListPlugins()
	assert.Contains(t, plugins, "none")
	assert.Contains(t, plugins, "native")
	assert.Contains(t, plugins, "system")
	assert.Contains(t, plugins, "ldap")
	assert.Contains(t, plugins, "oauth")
}

func TestPluginInfo(t *testing.T) {
	info, ok := auth.GetPluginInfo("native")
	assert.True(t, ok)
	assert.Equal(t, "native", info.Name)
	assert.Equal(t, "native", info.Type)
	assert.NotEmpty(t, info.Description)
	assert.NotNil(t, info.DefaultConfig)
	assert.NotEmpty(t, info.ConfigSchema)
}

func TestFactory_ValidateProviders(t *testing.T) {
	factory := auth.NewFactory()

	// Valid config
	err := factory.ValidateProviders([]auth.ProviderConfig{
		{Name: "test1", Type: "none", Enabled: true},
		{Name: "test2", Type: "native", Enabled: true, Config: map[string]any{"users": []map[string]any{}}},
	})
	assert.NoError(t, err)

	// Duplicate names
	err = factory.ValidateProviders([]auth.ProviderConfig{
		{Name: "test", Type: "none", Enabled: true},
		{Name: "test", Type: "none", Enabled: true},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")

	// Unknown type
	err = factory.ValidateProviders([]auth.ProviderConfig{
		{Name: "test", Type: "unknown", Enabled: true},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

// Chain authenticator edge case

func TestChainAuthenticator_AuthenticateWithNilMetadata(t *testing.T) {
	chain := auth.NewChainAuthenticator()

	hash, _ := auth.HashPassword("pass")
	native := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})
	chain.AddAuthenticator("native", 10, native)

	ctx := context.Background()
	userInfo, err := chain.Authenticate(ctx, "user", "pass")

	require.NoError(t, err)
	assert.NotNil(t, userInfo.Metadata) // Chain should initialize metadata if nil
	assert.Equal(t, "native", userInfo.Metadata["auth_provider"])
}

// =====================================================
// Middleware - MultiAuthHandler tests
// =====================================================

func TestMiddleware_MultiAuthHandler_NoneAuth(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	handler := middleware.MultiAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}

func TestMiddleware_MultiAuthHandler_BasicAuth(t *testing.T) {
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "testuser", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	var capturedUserInfo *auth.UserInfo
	handler := middleware.MultiAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserInfo = auth.GetUserInfo(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("testuser", "password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, capturedUserInfo)
	assert.Equal(t, "testuser", capturedUserInfo.Username)
}

func TestMiddleware_MultiAuthHandler_BearerToken(t *testing.T) {
	// Using OAuth authenticator with a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the token was passed correctly
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer valid-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sub": "tokenuser", "email": "token@example.com"}`))
	}))
	defer ts.Close()

	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true,
		Config: map[string]any{
			"client_id":    "test-client",
			"userinfo_url": ts.URL,
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	var capturedUserInfo *auth.UserInfo
	handler := middleware.MultiAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserInfo = auth.GetUserInfo(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, capturedUserInfo)
	assert.Equal(t, "tokenuser", capturedUserInfo.Username)
}

func TestMiddleware_MultiAuthHandler_APIKey(t *testing.T) {
	hash, _ := auth.HashPassword("api-key-value")
	mainAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{},
		},
	})

	// Create a simple authenticator that uses the password field as the API key
	apiKeyAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "apikey", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "apiuser", "password_hash": hash},
			},
		},
	})

	middleware := auth.NewMiddleware(mainAuth, "Test")
	middleware.SetAPIKeyAuth(apiKeyAuth, "X-API-Key")

	handler := middleware.MultiAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = auth.GetUserInfo(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Test with API key that doesn't match the native user (will fail)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "wrong-api-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should fail since no valid auth method succeeded
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddleware_MultiAuthHandler_NoAuth(t *testing.T) {
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test Realm")

	handler := middleware.MultiAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Test Realm")
}

func TestMiddleware_MultiAuthHandler_InvalidBasicAuth(t *testing.T) {
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	handler := middleware.MultiAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("user", "wrongpassword")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// =====================================================
// Middleware - MultiProxyAuthHandler tests
// =====================================================

func TestMiddleware_MultiProxyAuthHandler_NoneAuth(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "none", Type: "none", Enabled: true,
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	handler := middleware.MultiProxyAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_MultiProxyAuthHandler_BasicAuth(t *testing.T) {
	hash, _ := auth.HashPassword("proxypass")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "proxyuser", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	var capturedUserInfo *auth.UserInfo
	var hasProxyAuthHeader bool
	handler := middleware.MultiProxyAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserInfo = auth.GetUserInfo(r.Context())
		hasProxyAuthHeader = r.Header.Get("Proxy-Authorization") != ""
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic cHJveHl1c2VyOnByb3h5cGFzcw==") // proxyuser:proxypass
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, capturedUserInfo)
	assert.Equal(t, "proxyuser", capturedUserInfo.Username)
	assert.False(t, hasProxyAuthHeader, "Proxy-Authorization header should be removed")
}

func TestMiddleware_MultiProxyAuthHandler_BearerToken(t *testing.T) {
	// Using OAuth authenticator with a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer proxy-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sub": "proxyuser", "email": "proxy@example.com"}`))
	}))
	defer ts.Close()

	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true,
		Config: map[string]any{
			"client_id":    "test-client",
			"userinfo_url": ts.URL,
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	var capturedUserInfo *auth.UserInfo
	var hasProxyAuthHeader bool
	handler := middleware.MultiProxyAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserInfo = auth.GetUserInfo(r.Context())
		hasProxyAuthHeader = r.Header.Get("Proxy-Authorization") != ""
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Bearer proxy-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, capturedUserInfo)
	assert.Equal(t, "proxyuser", capturedUserInfo.Username)
	assert.False(t, hasProxyAuthHeader, "Proxy-Authorization header should be removed")
}

func TestMiddleware_MultiProxyAuthHandler_APIKey(t *testing.T) {
	hash, _ := auth.HashPassword("password")
	mainAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})

	// Create an API key authenticator using the apikey plugin (which accepts empty username)
	// The apikey plugin validates the key and returns a user
	apiKeyAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "apikey", Type: "apikey", Enabled: true,
		Config: map[string]any{
			"keys": []map[string]any{
				{
					"key":      "my-api-key-12345",
					"username": "apiuser",
					"groups":   []string{"api-clients"},
				},
			},
		},
	})

	middleware := auth.NewMiddleware(mainAuth, "Test")
	middleware.SetAPIKeyAuth(apiKeyAuth, "X-API-Key")

	var capturedUserInfo *auth.UserInfo
	var hasAPIKeyHeader bool
	handler := middleware.MultiProxyAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserInfo = auth.GetUserInfo(r.Context())
		hasAPIKeyHeader = r.Header.Get("X-API-Key") != ""
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("X-API-Key", "my-api-key-12345")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, capturedUserInfo)
	assert.Equal(t, "apiuser", capturedUserInfo.Username)
	assert.False(t, hasAPIKeyHeader, "X-API-Key header should be removed")
}

func TestMiddleware_MultiProxyAuthHandler_NoAuth(t *testing.T) {
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Proxy Realm")

	handler := middleware.MultiProxyAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusProxyAuthRequired, w.Code)
	assert.Contains(t, w.Header().Get("Proxy-Authenticate"), "Proxy Realm")
}

func TestMiddleware_MultiProxyAuthHandler_InvalidAuth(t *testing.T) {
	hash, _ := auth.HashPassword("password")
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "user", "password_hash": hash},
			},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	handler := middleware.MultiProxyAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjp3cm9uZw==") // user:wrong
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusProxyAuthRequired, w.Code)
}

// =====================================================
// Middleware - Context helper functions
// =====================================================

func TestGetUserInfo_NilContext(t *testing.T) {
	ctx := context.Background()
	userInfo := auth.GetUserInfo(ctx)
	assert.Nil(t, userInfo)
}

func TestGetUserInfo_WithUserInfo(t *testing.T) {
	expectedUser := &auth.UserInfo{Username: "contextuser", Email: "context@example.com"}
	ctx := context.WithValue(context.Background(), auth.UserInfoContextKey, expectedUser)

	userInfo := auth.GetUserInfo(ctx)

	assert.NotNil(t, userInfo)
	assert.Equal(t, "contextuser", userInfo.Username)
	assert.Equal(t, "context@example.com", userInfo.Email)
}

func TestGetUserInfo_WrongType(t *testing.T) {
	// Put a wrong type in the context
	ctx := context.WithValue(context.Background(), auth.UserInfoContextKey, "not a user info")

	userInfo := auth.GetUserInfo(ctx)

	assert.Nil(t, userInfo)
}

func TestGetClientCert_NilContext(t *testing.T) {
	ctx := context.Background()
	cert := auth.GetClientCert(ctx)
	assert.Nil(t, cert)
}

func TestGetClientCert_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), auth.ClientCertContextKey, "not a cert")
	cert := auth.GetClientCert(ctx)
	assert.Nil(t, cert)
}

// =====================================================
// Middleware - Token extraction functions
// =====================================================

func TestExtractBearerToken_Valid(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer mytoken123")

	token, ok := auth.ExtractBearerToken(req)

	assert.True(t, ok)
	assert.Equal(t, "mytoken123", token)
}

func TestExtractBearerToken_NoHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)

	token, ok := auth.ExtractBearerToken(req)

	assert.False(t, ok)
	assert.Empty(t, token)
}

func TestExtractBearerToken_BasicAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("user", "pass")

	token, ok := auth.ExtractBearerToken(req)

	assert.False(t, ok)
	assert.Empty(t, token)
}

func TestExtractBearerToken_InvalidFormat(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Token mytoken")

	token, ok := auth.ExtractBearerToken(req)

	assert.False(t, ok)
	assert.Empty(t, token)
}

func TestExtractProxyBearerToken_Valid(t *testing.T) {
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Bearer proxytoken456")

	token, ok := auth.ExtractProxyBearerToken(req)

	assert.True(t, ok)
	assert.Equal(t, "proxytoken456", token)
}

func TestExtractProxyBearerToken_NoHeader(t *testing.T) {
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)

	token, ok := auth.ExtractProxyBearerToken(req)

	assert.False(t, ok)
	assert.Empty(t, token)
}

func TestExtractProxyBearerToken_BasicAuth(t *testing.T) {
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")

	token, ok := auth.ExtractProxyBearerToken(req)

	assert.False(t, ok)
	assert.Empty(t, token)
}

// =====================================================
// Factory - CreateChain tests
// =====================================================

func TestFactory_CreateChain_Empty(t *testing.T) {
	factory := auth.NewFactory()

	authenticator, err := factory.CreateChain([]auth.ProviderConfig{})

	require.NoError(t, err)
	assert.NotNil(t, authenticator)
	// Should return "none" authenticator
	assert.Equal(t, "none", authenticator.Type())
}

func TestFactory_CreateChain_SingleEnabled(t *testing.T) {
	factory := auth.NewFactory()
	hash, _ := auth.HashPassword("password")

	authenticator, err := factory.CreateChain([]auth.ProviderConfig{
		{
			Name:    "native1",
			Type:    "native",
			Enabled: true,
			Config: map[string]any{
				"users": []map[string]any{
					{"username": "user1", "password_hash": hash},
				},
			},
		},
	})

	require.NoError(t, err)
	assert.NotNil(t, authenticator)
	// Single provider should still return chain (based on current implementation)
	assert.Equal(t, "chain", authenticator.Type())
}

func TestFactory_CreateChain_MultipleEnabled(t *testing.T) {
	factory := auth.NewFactory()
	hash, _ := auth.HashPassword("password")

	authenticator, err := factory.CreateChain([]auth.ProviderConfig{
		{
			Name:     "native1",
			Type:     "native",
			Enabled:  true,
			Priority: 10,
			Config: map[string]any{
				"users": []map[string]any{
					{"username": "user1", "password_hash": hash},
				},
			},
		},
		{
			Name:     "native2",
			Type:     "native",
			Enabled:  true,
			Priority: 20,
			Config: map[string]any{
				"users": []map[string]any{
					{"username": "user2", "password_hash": hash},
				},
			},
		},
	})

	require.NoError(t, err)
	assert.NotNil(t, authenticator)
	assert.Equal(t, "chain", authenticator.Type())

	// Test authentication
	ctx := context.Background()
	user, err := authenticator.Authenticate(ctx, "user1", "password")
	require.NoError(t, err)
	assert.Equal(t, "user1", user.Username)

	user, err = authenticator.Authenticate(ctx, "user2", "password")
	require.NoError(t, err)
	assert.Equal(t, "user2", user.Username)
}

func TestFactory_CreateChain_SomeDisabled(t *testing.T) {
	factory := auth.NewFactory()
	hash, _ := auth.HashPassword("password")

	authenticator, err := factory.CreateChain([]auth.ProviderConfig{
		{
			Name:     "disabled",
			Type:     "native",
			Enabled:  false, // This one is disabled
			Priority: 10,
			Config: map[string]any{
				"users": []map[string]any{
					{"username": "disabled_user", "password_hash": hash},
				},
			},
		},
		{
			Name:     "enabled",
			Type:     "native",
			Enabled:  true,
			Priority: 20,
			Config: map[string]any{
				"users": []map[string]any{
					{"username": "enabled_user", "password_hash": hash},
				},
			},
		},
	})

	require.NoError(t, err)
	assert.NotNil(t, authenticator)

	// Should only be able to auth with enabled user
	ctx := context.Background()
	_, err = authenticator.Authenticate(ctx, "disabled_user", "password")
	assert.Error(t, err)

	user, err := authenticator.Authenticate(ctx, "enabled_user", "password")
	require.NoError(t, err)
	assert.Equal(t, "enabled_user", user.Username)
}

func TestFactory_CreateChain_AllDisabled(t *testing.T) {
	factory := auth.NewFactory()

	authenticator, err := factory.CreateChain([]auth.ProviderConfig{
		{
			Name:    "disabled1",
			Type:    "none",
			Enabled: false,
		},
		{
			Name:    "disabled2",
			Type:    "none",
			Enabled: false,
		},
	})

	require.NoError(t, err)
	assert.NotNil(t, authenticator)
	// All disabled should return "none" authenticator
	assert.Equal(t, "none", authenticator.Type())
}

func TestFactory_CreateChain_PrioritySorting(t *testing.T) {
	factory := auth.NewFactory()

	// Add providers in reverse order to verify sorting
	authenticator, err := factory.CreateChain([]auth.ProviderConfig{
		{
			Name:     "high-priority",
			Type:     "none",
			Enabled:  true,
			Priority: 100, // Lower priority
		},
		{
			Name:     "low-priority",
			Type:     "none",
			Enabled:  true,
			Priority: 10, // Higher priority (will be tried first)
		},
	})

	require.NoError(t, err)
	assert.NotNil(t, authenticator)

	// Both should authenticate since they're "none" type
	ctx := context.Background()
	user, err := authenticator.Authenticate(ctx, "any", "any")
	require.NoError(t, err)
	// First successful auth should win
	assert.Equal(t, "anonymous", user.Username)
}

func TestFactory_CreateChain_InvalidProvider(t *testing.T) {
	factory := auth.NewFactory()

	_, err := factory.CreateChain([]auth.ProviderConfig{
		{
			Name:    "invalid",
			Type:    "unknown-type",
			Enabled: true,
		},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown-type")
}

func TestFactory_CreateChain_InvalidConfig(t *testing.T) {
	factory := auth.NewFactory()

	_, err := factory.CreateChain([]auth.ProviderConfig{
		{
			Name:    "ldap-invalid",
			Type:    "ldap",
			Enabled: true,
			Config: map[string]any{
				// Missing required fields
			},
		},
	})

	assert.Error(t, err)
}

// =====================================================
// Factory - Additional Create tests
// =====================================================

func TestFactory_Create_EmptyType(t *testing.T) {
	factory := auth.NewFactory()

	_, err := factory.Create(auth.ProviderConfig{
		Name:    "test",
		Type:    "",
		Enabled: true,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type is required")
}

func TestFactory_Create_UnknownType(t *testing.T) {
	factory := auth.NewFactory()

	_, err := factory.Create(auth.ProviderConfig{
		Name:    "test",
		Type:    "nonexistent-plugin",
		Enabled: true,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown auth plugin type")
}

// =====================================================
// Factory - ValidateProviders additional tests
// =====================================================

func TestFactory_ValidateProviders_EmptyName(t *testing.T) {
	factory := auth.NewFactory()

	err := factory.ValidateProviders([]auth.ProviderConfig{
		{Name: "", Type: "none", Enabled: true},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestFactory_ValidateProviders_EmptyType(t *testing.T) {
	factory := auth.NewFactory()

	err := factory.ValidateProviders([]auth.ProviderConfig{
		{Name: "test", Type: "", Enabled: true},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type is required")
}

func TestFactory_ValidateProviders_InvalidConfig(t *testing.T) {
	factory := auth.NewFactory()

	err := factory.ValidateProviders([]auth.ProviderConfig{
		{
			Name:    "ldap-test",
			Type:    "ldap",
			Enabled: true,
			Config:  map[string]any{}, // Missing required URL and base_dn
		},
	})

	assert.Error(t, err)
}

// =====================================================
// Registry - GetAllPlugins, ListPluginInfo tests
// =====================================================

func TestRegistry_GetAllPlugins(t *testing.T) {
	plugins := auth.GetAllPlugins()

	assert.NotNil(t, plugins)
	assert.NotEmpty(t, plugins)

	// Verify expected plugins are present
	_, hasNone := plugins["none"]
	assert.True(t, hasNone, "should have none plugin")

	_, hasNative := plugins["native"]
	assert.True(t, hasNative, "should have native plugin")
}

func TestRegistry_GetAllPlugins_IsCopy(t *testing.T) {
	plugins1 := auth.GetAllPlugins()
	plugins2 := auth.GetAllPlugins()

	// Modifying one should not affect the other
	delete(plugins1, "none")

	_, hasNone := plugins2["none"]
	assert.True(t, hasNone, "modifying returned map should not affect registry")
}

func TestRegistry_ListPluginInfo(t *testing.T) {
	infos := auth.ListPluginInfo()

	assert.NotNil(t, infos)
	assert.NotEmpty(t, infos)

	// Verify sorted by name
	for i := 1; i < len(infos); i++ {
		assert.True(t, infos[i-1].Name <= infos[i].Name, "plugins should be sorted by name")
	}

	// Verify each info has required fields
	for _, info := range infos {
		assert.NotEmpty(t, info.Name)
		assert.NotEmpty(t, info.Type)
		assert.NotEmpty(t, info.Description)
	}
}

func TestRegistry_GetPluginInfo_NotFound(t *testing.T) {
	info, ok := auth.GetPluginInfo("nonexistent-plugin")

	assert.False(t, ok)
	assert.Nil(t, info)
}

// =====================================================
// Chain - Additional edge cases
// =====================================================

func TestChainAuthenticator_AuthenticateReturnsLastError(t *testing.T) {
	chain := auth.NewChainAuthenticator()

	// Create authenticators that will fail
	native1 := createAuthenticator(t, auth.ProviderConfig{
		Name: "native1", Type: "native", Enabled: true,
		Config: map[string]any{"users": []map[string]any{}},
	})
	native2 := createAuthenticator(t, auth.ProviderConfig{
		Name: "native2", Type: "native", Enabled: true,
		Config: map[string]any{"users": []map[string]any{}},
	})

	chain.AddAuthenticator("native1", 10, native1)
	chain.AddAuthenticator("native2", 20, native2)

	ctx := context.Background()
	_, err := chain.Authenticate(ctx, "unknown", "pass")

	// Should return the last error
	assert.Error(t, err)
	assert.True(t, auth.IsInvalidCredentials(err))
}

// =====================================================
// ContextKey tests
// =====================================================

func TestContextKey_String(t *testing.T) {
	// Verify that context keys can be used as strings
	key1 := auth.UserInfoContextKey
	key2 := auth.ClientCertContextKey

	assert.Equal(t, auth.ContextKey("auth_user_info"), key1)
	assert.Equal(t, auth.ContextKey("auth_client_cert"), key2)
}

// =====================================================
// SetAPIKeyAuth test
// =====================================================

func TestMiddleware_SetAPIKeyAuth(t *testing.T) {
	authenticator := createAuthenticator(t, auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{},
		},
	})
	middleware := auth.NewMiddleware(authenticator, "Test")

	hash, _ := auth.HashPassword("apikey123")
	apiKeyAuth := createAuthenticator(t, auth.ProviderConfig{
		Name: "apikey", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "apiuser", "password_hash": hash},
			},
		},
	})

	// Set API key auth
	middleware.SetAPIKeyAuth(apiKeyAuth, "X-Custom-API-Key")

	// Verify it's set by using MultiAuthHandler
	handler := middleware.MultiAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := auth.GetUserInfo(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Custom-API-Key", "apikey123")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "apiuser", w.Body.String())
}
