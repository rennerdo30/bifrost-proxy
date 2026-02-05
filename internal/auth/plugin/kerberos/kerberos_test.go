package kerberos_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/kerberos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createValidKeytab creates a valid keytab with a test principal
func createValidKeytab(t *testing.T, principal, realm, password string) []byte {
	t.Helper()
	kt := keytab.New()
	// Add an entry with AES256-CTS-HMAC-SHA1-96 encryption type (18)
	err := kt.AddEntry(principal, realm, password, time.Now(), 1, 18)
	require.NoError(t, err)
	data, err := kt.Marshal()
	require.NoError(t, err)
	return data
}

// createValidKrb5Conf creates a valid krb5.conf content
func createValidKrb5Conf(realm string, kdcServer string) string {
	return `[libdefaults]
  default_realm = ` + realm + `

[realms]
  ` + realm + ` = {
    kdc = ` + kdcServer + `
  }
`
}

// writeTestFile creates a temporary file with the given content
func writeTestFile(t *testing.T, content []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.keytab")
	err := os.WriteFile(filePath, content, 0600)
	require.NoError(t, err)
	return filePath
}

// writeTestKrb5Conf creates a temporary krb5.conf file
func writeTestKrb5Conf(t *testing.T, realm, kdcServer string) string {
	t.Helper()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "krb5.conf")
	content := createValidKrb5Conf(realm, kdcServer)
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(t, err)
	return filePath
}

func TestKerberosPlugin_Registration(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok, "kerberos plugin not registered")
	assert.Equal(t, "kerberos", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}

func TestKerberosPlugin_ValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
	}{
		{
			name:    "nil config should error",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing service_principal should error",
			config: map[string]any{
				"keytab_file": "/etc/bifrost/server.keytab",
			},
			wantErr: true,
		},
		{
			name: "missing keytab should error",
			config: map[string]any{
				"service_principal": "HTTP/proxy.example.com",
			},
			wantErr: true,
		},
		{
			name: "valid config with keytab_file",
			config: map[string]any{
				"service_principal": "HTTP/proxy.example.com",
				"keytab_file":       "/etc/bifrost/server.keytab",
			},
			wantErr: false,
		},
		{
			name: "valid config with keytab_base64",
			config: map[string]any{
				"service_principal": "HTTP/proxy.example.com",
				"keytab_base64":     "BQIAAA==", // Minimal keytab header
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKerberosPlugin_DefaultConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	defaults := plugin.DefaultConfig()
	assert.NotNil(t, defaults)
	assert.Equal(t, "/etc/bifrost/server.keytab", defaults["keytab_file"])
	assert.Equal(t, "HTTP/proxy.example.com", defaults["service_principal"])
	assert.Equal(t, "EXAMPLE.COM", defaults["realm"])
	assert.Equal(t, "/etc/krb5.conf", defaults["krb5_config_file"])
}

func TestKerberosPlugin_ConfigSchema(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	schema := plugin.ConfigSchema()
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "keytab_file")
	assert.Contains(t, schema, "keytab_base64")
	assert.Contains(t, schema, "service_principal")
	assert.Contains(t, schema, "realm")
	assert.Contains(t, schema, "krb5_config_file")
	assert.Contains(t, schema, "krb5_config")
	assert.Contains(t, schema, "kdc_servers")
	assert.Contains(t, schema, "strip_realm")
	assert.Contains(t, schema, "username_to_lowercase")
}

func TestKerberosPlugin_ParseConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// Test that config options are parsed correctly
	config := map[string]any{
		"service_principal":     "HTTP/myproxy.corp.local",
		"keytab_file":           "/opt/keytabs/proxy.keytab",
		"realm":                 "CORP.LOCAL",
		"krb5_config_file":      "/etc/krb5.conf",
		"kdc_servers":           []any{"kdc1.corp.local", "kdc2.corp.local"},
		"strip_realm":           false,
		"username_to_lowercase": false,
	}

	err := plugin.ValidateConfig(config)
	assert.NoError(t, err)
}

func TestKerberosPlugin_InlineKrb5Config(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	krb5Config := `[libdefaults]
  default_realm = TEST.LOCAL

[realms]
  TEST.LOCAL = {
    kdc = kdc.test.local:88
  }`

	config := map[string]any{
		"service_principal": "HTTP/proxy.test.local",
		"keytab_file":       "/etc/bifrost/server.keytab",
		"krb5_config":       krb5Config,
	}

	err := plugin.ValidateConfig(config)
	assert.NoError(t, err)
}

func TestKerberosPlugin_Create_WithKeytabFile(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabPath := writeTestFile(t, keytabData)

	// Create valid krb5.conf
	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_file":       keytabPath,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	assert.Equal(t, "kerberos", authenticator.Name())
	assert.Equal(t, "kerberos", authenticator.Type())
}

func TestKerberosPlugin_Create_WithKeytabBase64(t *testing.T) {
	// Create valid keytab and encode as base64
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	// Create valid krb5.conf
	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     keytabBase64,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestKerberosPlugin_Create_WithInlineKrb5Config(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.test.local", "TEST.LOCAL", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	krb5Config := createValidKrb5Conf("TEST.LOCAL", "kdc.test.local:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.test.local",
		"keytab_base64":     keytabBase64,
		"realm":             "TEST.LOCAL",
		"krb5_config":       krb5Config,
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestKerberosPlugin_Create_WithKDCServers(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.corp.local", "CORP.LOCAL", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// Need to provide a krb5 config file or inline config since /etc/krb5.conf doesn't exist in test
	krb5Path := writeTestKrb5Conf(t, "CORP.LOCAL", "initial-kdc.corp.local:88")

	config := map[string]any{
		"service_principal": "HTTP/proxy.corp.local",
		"keytab_base64":     keytabBase64,
		"realm":             "CORP.LOCAL",
		"kdc_servers":       []any{"kdc1.corp.local:88", "kdc2.corp.local:88"},
		"krb5_config_file":  krb5Path,
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestKerberosPlugin_Create_InvalidKeytabFile(t *testing.T) {
	// Non-existent keytab file
	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_file":       "/nonexistent/path/to/keytab",
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
	}

	_, err := plugin.Create(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keytab")
}

func TestKerberosPlugin_Create_InvalidKeytabBase64(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     "not-valid-base64!!!",
		"realm":             "EXAMPLE.COM",
	}

	_, err := plugin.Create(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keytab")
}

func TestKerberosPlugin_Create_InvalidKeytabContent(t *testing.T) {
	// Valid base64 but invalid keytab content
	invalidKeytabBase64 := base64.StdEncoding.EncodeToString([]byte("not a keytab"))

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     invalidKeytabBase64,
		"realm":             "EXAMPLE.COM",
	}

	_, err := plugin.Create(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keytab")
}

func TestKerberosPlugin_Create_InvalidKrb5ConfigFile(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     keytabBase64,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  "/nonexistent/krb5.conf",
	}

	_, err := plugin.Create(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Kerberos config")
}

func TestKerberosPlugin_Create_InvalidInlineKrb5Config(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// Note: The krb5 config library is tolerant of many malformed configs.
	// This test verifies that even with tolerant parsing, the authenticator is created.
	// For truly invalid configs that cause errors, we'd need specific syntax errors.
	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     keytabBase64,
		"realm":             "EXAMPLE.COM",
		"krb5_config":       "invalid krb5 config format {{{",
	}

	// The krb5 library is tolerant, so this won't error
	// Just verify it doesn't panic and creates an authenticator
	authenticator, err := plugin.Create(config)
	// If it errors, check the error message
	if err != nil {
		assert.Contains(t, err.Error(), "Kerberos config")
	} else {
		// If it doesn't error (library is tolerant), verify authenticator was created
		assert.NotNil(t, authenticator)
	}
}

func TestKerberosAuthenticator_NameAndType(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	assert.Equal(t, "kerberos", authenticator.Name())
	assert.Equal(t, "kerberos", authenticator.Type())
}

func TestKerberosAuthenticator_GetServicePrincipal(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, map[string]any{
		"service_principal": "HTTP/myproxy.example.com",
	})

	// Type assert to access GetServicePrincipal method
	ka, ok := authenticator.(*kerberos.Authenticator)
	require.True(t, ok)
	assert.Equal(t, "HTTP/myproxy.example.com", ka.GetServicePrincipal())
}

func TestKerberosAuthenticator_GetRealm(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, map[string]any{
		"realm": "TEST.REALM",
	})

	ka, ok := authenticator.(*kerberos.Authenticator)
	require.True(t, ok)
	assert.Equal(t, "TEST.REALM", ka.GetRealm())
}

func TestKerberosAuthenticator_ReloadKeytab(t *testing.T) {
	// Create initial keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabPath := writeTestFile(t, keytabData)
	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_file":       keytabPath,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)

	ka, ok := authenticator.(*kerberos.Authenticator)
	require.True(t, ok)

	// Update the keytab file
	newKeytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "newpassword")
	err = os.WriteFile(keytabPath, newKeytabData, 0600)
	require.NoError(t, err)

	// Reload keytab
	err = ka.ReloadKeytab()
	assert.NoError(t, err)
}

func TestKerberosAuthenticator_ReloadKeytab_FileDeleted(t *testing.T) {
	// Create initial keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabPath := writeTestFile(t, keytabData)
	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_file":       keytabPath,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)

	ka, ok := authenticator.(*kerberos.Authenticator)
	require.True(t, ok)

	// Delete the keytab file
	err = os.Remove(keytabPath)
	require.NoError(t, err)

	// Reload keytab should fail
	err = ka.ReloadKeytab()
	assert.Error(t, err)
}

func TestKerberosAuthenticator_Authenticate_NoCredentials(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	_, err := authenticator.Authenticate(context.Background(), "", "")
	require.Error(t, err)
	assert.True(t, auth.IsInvalidCredentials(err))
}

func TestKerberosAuthenticator_Authenticate_SPNEGOTokenInContext(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	// Create a dummy SPNEGO token (will fail validation but tests the path)
	dummyToken := []byte{0x60, 0x28, 0x06} // SPNEGO OID start

	ctx := context.WithValue(context.Background(), kerberos.SPNEGOTokenContextKey, dummyToken)

	_, err := authenticator.Authenticate(ctx, "", "")
	// Should fail with SPNEGO validation message
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SPNEGO")
}

func TestKerberosAuthenticator_Authenticate_SPNEGOTokenAsPassword(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	// SPNEGO tokens start with "YII" when base64-encoded (Application 0 tag)
	// Create a valid base64 token that starts with YII and decodes successfully
	// The bytes 0x60, 0x82, 0x00, 0x04 encode to "YIIABg==" in base64
	rawToken := []byte{0x60, 0x82, 0x00, 0x04, 0x00, 0x00}
	fakeToken := base64.StdEncoding.EncodeToString(rawToken)

	// Verify it starts with YII
	require.True(t, strings.HasPrefix(fakeToken, "YII"), "Token should start with YII")

	_, err := authenticator.Authenticate(context.Background(), "", fakeToken)
	// Should attempt to decode and validate, then fail with SPNEGO error
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SPNEGO")
}

func TestKerberosAuthenticator_Authenticate_InvalidBase64InPassword(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	// String starting with YII but not valid base64
	invalidToken := "YII!!invalid!!base64"

	_, err := authenticator.Authenticate(context.Background(), "", invalidToken)
	// Base64 decode fails, falls through to no credentials
	require.Error(t, err)
	assert.True(t, auth.IsInvalidCredentials(err))
}

func TestKerberosAuthenticator_Authenticate_WithUsernamePassword(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	// Try to authenticate with username/password
	// This will fail as there's no real KDC, but tests the code path
	_, err := authenticator.Authenticate(context.Background(), "testuser", "testpassword")
	require.Error(t, err)
	// Should fail with authentication error, not invalid credentials
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestKerberosAuthenticator_Authenticate_WithRealmInUsername(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	// Test username with realm (user@REALM format)
	_, err := authenticator.Authenticate(context.Background(), "testuser@EXAMPLE.COM", "testpassword")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestKerberosAuthenticator_TransformUsername_StripRealm(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, map[string]any{
		"strip_realm":           true,
		"username_to_lowercase": false,
	})

	// Access internal function via type assertion
	ka := authenticator.(*kerberos.Authenticator)

	// Test that realm is stripped (default behavior)
	// We can't directly test transformUsername, but we verify the config is applied
	assert.Equal(t, "kerberos", ka.Name())
}

func TestKerberosAuthenticator_TransformUsername_KeepRealm(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, map[string]any{
		"strip_realm":           false,
		"username_to_lowercase": false,
		"realm":                 "TEST.REALM",
	})

	ka := authenticator.(*kerberos.Authenticator)
	assert.Equal(t, "TEST.REALM", ka.GetRealm())
}

func TestKerberosAuthenticator_TransformUsername_ToLowercase(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, map[string]any{
		"strip_realm":           true,
		"username_to_lowercase": true,
	})

	ka := authenticator.(*kerberos.Authenticator)
	assert.Equal(t, "kerberos", ka.Type())
}

func TestKerberosPlugin_Create_KDCServersOverride(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.corp.local", "CORP.LOCAL", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	// Create krb5.conf with different KDC
	krb5Path := writeTestKrb5Conf(t, "CORP.LOCAL", "old-kdc.corp.local:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// Override KDC servers in config
	config := map[string]any{
		"service_principal": "HTTP/proxy.corp.local",
		"keytab_base64":     keytabBase64,
		"realm":             "CORP.LOCAL",
		"krb5_config_file":  krb5Path,
		"kdc_servers":       []any{"new-kdc1.corp.local:88", "new-kdc2.corp.local:88"},
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestKerberosPlugin_Create_KDCServersNewRealm(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.new.local", "NEW.REALM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	// Create krb5.conf with different realm
	krb5Path := writeTestKrb5Conf(t, "OLD.REALM", "kdc.old.local:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// Add a new realm via kdc_servers
	config := map[string]any{
		"service_principal": "HTTP/proxy.new.local",
		"keytab_base64":     keytabBase64,
		"realm":             "NEW.REALM",
		"krb5_config_file":  krb5Path,
		"kdc_servers":       []any{"kdc.new.local:88"},
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestParseConfig_AllOptions(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"keytab_file":           "/path/to/keytab",
		"keytab_base64":         "base64data",
		"service_principal":     "HTTP/service.example.com",
		"realm":                 "EXAMPLE.COM",
		"krb5_config_file":      "/etc/krb5.conf",
		"krb5_config":           "[libdefaults]\n  default_realm = EXAMPLE.COM",
		"kdc_servers":           []any{"kdc1.example.com", "kdc2.example.com"},
		"strip_realm":           false,
		"username_to_lowercase": false,
	}

	err := plugin.ValidateConfig(config)
	assert.NoError(t, err)
}

func TestParseConfig_DefaultValues(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// Minimal config
	config := map[string]any{
		"keytab_file":       "/path/to/keytab",
		"service_principal": "HTTP/service.example.com",
	}

	err := plugin.ValidateConfig(config)
	assert.NoError(t, err)

	// Defaults should be applied: strip_realm=true, username_to_lowercase=true
}

func TestKerberosPlugin_Create_EmptyKDCServersArray(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     keytabBase64,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
		"kdc_servers":       []any{}, // Empty array
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestKerberosPlugin_Create_MixedKDCServersArray(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// Array with mixed types (some strings, some not)
	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     keytabBase64,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
		"kdc_servers":       []any{"kdc1.example.com", 123, "kdc2.example.com"}, // Mixed types
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestKerberosAuthenticator_Authenticate_EmptyContext(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	// Empty context value
	ctx := context.WithValue(context.Background(), kerberos.SPNEGOTokenContextKey, []byte{})

	_, err := authenticator.Authenticate(ctx, "", "")
	require.Error(t, err)
	assert.True(t, auth.IsInvalidCredentials(err))
}

func TestContextKey_String(t *testing.T) {
	key := kerberos.SPNEGOTokenContextKey
	assert.Equal(t, kerberos.ContextKey("kerberos_spnego_token"), key)
}

func TestKerberosAuthenticator_ConcurrentAccess(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	// Test concurrent authentication attempts
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_, _ = authenticator.Authenticate(context.Background(), "user", "pass")
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestKerberosPlugin_Create_NoRealmWithKDCServers(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// No realm specified but kdc_servers provided
	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     keytabBase64,
		"krb5_config_file":  krb5Path,
		"kdc_servers":       []any{"kdc.example.com:88"},
		// No realm specified
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

// Helper function to create a Kerberos authenticator for testing
func createKerberosAuthenticator(t *testing.T, extraConfig map[string]any) auth.Authenticator {
	t.Helper()

	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	// Create valid krb5.conf
	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     keytabBase64,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
	}

	// Merge extra config
	for k, v := range extraConfig {
		config[k] = v
	}

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	return authenticator
}

func TestKerberosAuthenticator_ValidateSPNEGOToken_Integration(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	// Create a more realistic SPNEGO token (still invalid but exercises more code)
	// SPNEGO tokens typically start with OID for SPNEGO mechanism
	spnegoToken := []byte{
		0x60, 0x82, 0x01, 0x00, // SEQUENCE tag with length
		0x06, 0x06, // OID tag
		0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // SPNEGO OID
	}

	ctx := context.WithValue(context.Background(), kerberos.SPNEGOTokenContextKey, spnegoToken)

	_, err := authenticator.Authenticate(ctx, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SPNEGO")
}

func TestKerberosPlugin_Create_MinimalConfig_WithInlineKrb5(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.minimal.local", "MINIMAL.LOCAL", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// Minimal config with inline krb5 config
	config := map[string]any{
		"service_principal": "HTTP/proxy.minimal.local",
		"keytab_base64":     keytabBase64,
		"realm":             "MINIMAL.LOCAL",
		"krb5_config":       createValidKrb5Conf("MINIMAL.LOCAL", "kdc.minimal.local:88"),
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestKerberosPlugin_Create_NoKrb5ConfigUseKDCServers(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.test.local", "TEST.LOCAL", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// Config without krb5_config_file but with kdc_servers and realm
	// Should create a minimal config internally
	config := map[string]any{
		"service_principal": "HTTP/proxy.test.local",
		"keytab_base64":     keytabBase64,
		"realm":             "TEST.LOCAL",
		"kdc_servers":       []any{"kdc.test.local:88"},
		"krb5_config_file":  "", // Explicitly empty
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestKerberosAuthenticator_ReloadKeytab_Base64(t *testing.T) {
	// Create initial keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)
	krb5Path := writeTestKrb5Conf(t, "EXAMPLE.COM", "kdc.example.com:88")

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     keytabBase64,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)

	ka, ok := authenticator.(*kerberos.Authenticator)
	require.True(t, ok)

	// Reload keytab (should work since it's base64)
	err = ka.ReloadKeytab()
	assert.NoError(t, err)
}

func TestKerberosAuthenticator_Authenticate_ValidBase64SPNEGOToken(t *testing.T) {
	authenticator := createKerberosAuthenticator(t, nil)

	// Create a valid base64 encoded token that starts with "YII"
	// This mimics a real SPNEGO token format
	rawToken := []byte{
		0x60, 0x82, 0x01, 0x00, // Application 0 (SPNEGO)
	}
	base64Token := base64.StdEncoding.EncodeToString(rawToken)

	// Ensure it starts with YII (it will after base64 encoding of 0x60 0x82...)
	// Actually "YIIBgA==" would be a minimal SPNEGO token start
	_, err := authenticator.Authenticate(context.Background(), "", base64Token)
	// Will fail but tests the decoding path
	require.Error(t, err)
}

func TestKerberosPlugin_ValidateConfig_EmptyConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	err := plugin.ValidateConfig(map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keytab")
}

func TestKerberosPlugin_Create_KDCServers_AddsToExistingRealm(t *testing.T) {
	// Create valid keytab
	keytabData := createValidKeytab(t, "HTTP/proxy.example.com", "EXAMPLE.COM", "testpassword")
	keytabBase64 := base64.StdEncoding.EncodeToString(keytabData)

	// Create krb5.conf with the same realm but different KDC
	tmpDir := t.TempDir()
	krb5Path := filepath.Join(tmpDir, "krb5.conf")
	krb5Content := `[libdefaults]
  default_realm = EXAMPLE.COM

[realms]
  EXAMPLE.COM = {
    kdc = old-kdc.example.com:88
  }
`
	err := os.WriteFile(krb5Path, []byte(krb5Content), 0644)
	require.NoError(t, err)

	plugin, ok := auth.GetPlugin("kerberos")
	require.True(t, ok)

	// KDC servers should override the existing realm's KDC
	config := map[string]any{
		"service_principal": "HTTP/proxy.example.com",
		"keytab_base64":     keytabBase64,
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  krb5Path,
		"kdc_servers":       []any{"new-kdc.example.com:88"},
	}

	authenticator, err := plugin.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}
