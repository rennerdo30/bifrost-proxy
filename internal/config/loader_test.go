package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// writeConfig writes content to a temp file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

const validServerConfig = `server:
  http:
    listen: ":7080"
backends:
  - name: direct
    type: direct
    enabled: true
routes:
  - domains: ["*"]
    backend: direct
`

func TestLoad_RejectsUnknownKeys(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantKeys    []string
		wantLines   []int
		wantSection string
	}{
		{
			name: "misspelled listener key",
			content: `server:
  http:
    listem: ":9999"
`,
			wantKeys:    []string{"listem"},
			wantLines:   []int{3},
			wantSection: "ListenerConfig",
		},
		{
			name:        "unknown top-level key",
			content:     "nonsense: 1\n",
			wantKeys:    []string{"nonsense"},
			wantLines:   []int{1},
			wantSection: "ServerConfig",
		},
		{
			name: "unknown key inside a list element",
			content: `backends:
  - name: direct
    type: direct
    prioritty: 5
`,
			wantKeys:    []string{"prioritty"},
			wantLines:   []int{4},
			wantSection: "BackendConfig",
		},
		{
			name: "obsolete key that no struct reads",
			content: `logging:
  max_age_days: 7
`,
			wantKeys:    []string{"max_age_days"},
			wantLines:   []int{2},
			wantSection: "logging.Config",
		},
		{
			name: "several unknown keys are all reported",
			content: `server:
  http:
    listem: ":9999"
nonsense: 1
`,
			wantKeys:  []string{"listem", "nonsense"},
			wantLines: []int{3, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.content)

			var cfg ServerConfig
			err := Load(path, &cfg)
			require.Error(t, err, "an unknown key must not load silently")

			var unknownErr *UnknownKeysError
			require.ErrorAs(t, err, &unknownErr)
			require.Len(t, unknownErr.Keys, len(tt.wantKeys))

			for i, wantKey := range tt.wantKeys {
				assert.Equal(t, wantKey, unknownErr.Keys[i].Key)
				assert.Equal(t, tt.wantLines[i], unknownErr.Keys[i].Line)
				assert.Contains(t, err.Error(), wantKey, "the message must name the key")
			}
			if tt.wantSection != "" {
				assert.Equal(t, tt.wantSection, unknownErr.Keys[0].Section)
			}
			assert.Equal(t, path, unknownErr.Path)
			assert.Contains(t, err.Error(), EnvAllowUnknownKeys, "the message must offer a way forward")
		})
	}
}

func TestLoad_UnknownKeyIsNotAcceptedForValidClients(t *testing.T) {
	path := writeConfig(t, "server:\n  addres: \"proxy:7080\"\n")

	var cfg ClientConfig
	err := Load(path, &cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "addres")
	assert.Empty(t, cfg.Server.Address)
}

func TestLoad_UnknownKeysDowngradedWhenOptedIn(t *testing.T) {
	t.Setenv(EnvAllowUnknownKeys, "1")

	path := writeConfig(t, `server:
  http:
    listen: ":7080"
    listem: ":9999"
nonsense: 1
`)

	var cfg ServerConfig
	require.NoError(t, Load(path, &cfg), "the escape hatch must keep a deployment bootable")
	assert.Equal(t, ":7080", cfg.Server.HTTP.Listen, "known keys still apply")
}

func TestLoad_TypeMismatchStillFails(t *testing.T) {
	// A genuine type error must fail whether or not unknown keys are tolerated.
	for _, allow := range []string{"", "1"} {
		t.Run("allow_unknown="+allow, func(t *testing.T) {
			t.Setenv(EnvAllowUnknownKeys, allow)

			path := writeConfig(t, "server:\n  http:\n    max_connections: \"not-a-number\"\n")

			var cfg ServerConfig
			err := Load(path, &cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to parse config file")
		})
	}
}

func TestLoad_TypeMismatchReportedAlongsideUnknownKey(t *testing.T) {
	path := writeConfig(t, `server:
  http:
    listem: ":9999"
    max_connections: "not-a-number"
`)

	var cfg ServerConfig
	err := Load(path, &cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listem")
	assert.Contains(t, err.Error(), "additional problems")

	var unknownErr *UnknownKeysError
	assert.ErrorAs(t, err, &unknownErr)
}

func TestLoad_ValidConfigUnaffected(t *testing.T) {
	path := writeConfig(t, validServerConfig)

	var cfg ServerConfig
	require.NoError(t, Load(path, &cfg))
	assert.Equal(t, ":7080", cfg.Server.HTTP.Listen)
	assert.Len(t, cfg.Backends, 1)
}

func TestLoad_EmptyAndCommentOnlyFiles(t *testing.T) {
	for name, content := range map[string]string{
		"empty":        "",
		"comment only": "# nothing to see here\n",
		"null doc":     "---\n",
	} {
		t.Run(name, func(t *testing.T) {
			var cfg ServerConfig
			require.NoError(t, Load(writeConfig(t, content), &cfg))
			assert.Empty(t, cfg.Server.HTTP.Listen)
		})
	}
}

// The shipped configs and the templates written by `bifrost-* init` must load
// under strict key checking, or the first thing a new operator sees is an error.
func TestLoad_ShippedConfigsAndTemplatesAreStrictClean(t *testing.T) {
	files := map[string]func() any{
		"../../configs/server-config.example.yaml": func() any { return &ServerConfig{} },
		"../../configs/server-config.openwrt.yaml": func() any { return &ServerConfig{} },
		"../../configs/client-config.example.yaml": func() any { return &ClientConfig{} },
		"../../configs/client-config.docker.yaml":  func() any { return &ClientConfig{} },
	}
	for path, newCfg := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path) //nolint:gosec // G304: fixed test fixture paths
			require.NoError(t, err)
			require.NoError(t, decodeStrict(path, data, newCfg()))
		})
	}

	t.Run("server template", func(t *testing.T) {
		require.NoError(t, decodeStrict("server template", []byte(DefaultServerConfigTemplate), &ServerConfig{}))
	})
	t.Run("client template", func(t *testing.T) {
		require.NoError(t, decodeStrict("client template", []byte(DefaultClientConfigTemplate), &ClientConfig{}))
	})
}

func TestLoad_EnvExpansionEndToEnd(t *testing.T) {
	t.Setenv("BIFROST_TEST_PASSWORD", "from-env")

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "literal dollar survives", value: "\"p@ss$word123\"", want: "p@ss$word123"},
		{name: "bcrypt hash survives", value: "\"$2a$10$abcdef\"", want: "$2a$10$abcdef"},
		{name: "reference expands", value: "\"${BIFROST_TEST_PASSWORD}\"", want: "from-env"},
		{name: "default form expands", value: "\"${BIFROST_TEST_MISSING:-fallback}\"", want: "fallback"},
		{name: "escaped dollar", value: "\"a$${NOPE}b\"", want: "a${NOPE}b"},
		{name: "unset reference expands empty", value: "\"${BIFROST_TEST_MISSING}\"", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "server:\n  address: \"proxy:7080\"\n  password: "+tt.value+"\n")

			var cfg ClientConfig
			require.NoError(t, Load(path, &cfg))
			assert.Equal(t, tt.want, cfg.Server.Password)
		})
	}
}

func TestSaveLoad_RoundTripsDollarValues(t *testing.T) {
	values := []string{"p@ss$word123", "$2a$10$abcdef", "a${NOT_A_VAR}b", "$$literal"}

	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			t.Setenv("NOT_A_VAR", "expanded")

			path := filepath.Join(t.TempDir(), "config.yaml")
			saved := &ClientConfig{}
			saved.Server.Address = "proxy:7080"
			saved.Server.Password = v
			require.NoError(t, Save(path, saved))

			var loaded ClientConfig
			require.NoError(t, Load(path, &loaded))
			assert.Equal(t, v, loaded.Server.Password)
		})
	}
}

func TestDecodeStrict(t *testing.T) {
	var cfg ServerConfig
	require.NoError(t, DecodeStrict("request body", []byte(validServerConfig), &cfg))
	assert.Equal(t, ":7080", cfg.Server.HTTP.Listen)

	var bad ServerConfig
	err := DecodeStrict("request body", []byte("server:\n  http:\n    listem: \":1\"\n"), &bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request body")
	assert.Contains(t, err.Error(), "listem")
}

func TestAllowUnknownKeys(t *testing.T) {
	truthy := []string{"1", "true", "TRUE", "yes", "on", " 1 "}
	falsy := []string{"", "0", "false", "no", "off", "maybe"}

	for _, v := range truthy {
		t.Setenv(EnvAllowUnknownKeys, v)
		assert.True(t, allowUnknownKeys(), "%q should enable the escape hatch", v)
	}
	for _, v := range falsy {
		t.Setenv(EnvAllowUnknownKeys, v)
		assert.False(t, allowUnknownKeys(), "%q should not enable the escape hatch", v)
	}
}

func TestSplitUnknownFieldErrors(t *testing.T) {
	unknown, other := splitUnknownFieldErrors([]string{
		"line 3: field listem not found in type config.ListenerConfig",
		"field orphan not found in type config.ServerConfig",
		"line 9: cannot unmarshal !!str `abc` into int",
	})

	require.Len(t, unknown, 2)
	assert.Equal(t, UnknownKey{Key: "listem", Section: "ListenerConfig", Line: 3}, unknown[0])
	assert.Equal(t, UnknownKey{Key: "orphan", Section: "ServerConfig", Line: 0}, unknown[1])
	require.Len(t, other, 1)
	assert.Contains(t, other[0], "cannot unmarshal")
}

func TestUnknownKey_String(t *testing.T) {
	assert.Equal(t, `line 3: "listem" (in ListenerConfig)`,
		UnknownKey{Key: "listem", Section: "ListenerConfig", Line: 3}.String())
	assert.Equal(t, `"orphan"`, UnknownKey{Key: "orphan"}.String())
}

func TestUnknownKeysError_Unwrap(t *testing.T) {
	typeErr := &yaml.TypeError{Errors: []string{"line 1: field x not found in type config.ServerConfig"}}
	err := &UnknownKeysError{Path: "c.yaml", Keys: []UnknownKey{{Key: "x", Line: 1}}, err: typeErr}

	assert.Contains(t, err.Error(), "c.yaml")
	assert.Contains(t, err.Error(), `"x"`)

	var target *yaml.TypeError
	assert.ErrorAs(t, err, &target)
	assert.True(t, errors.Is(err.Unwrap(), typeErr))
}
