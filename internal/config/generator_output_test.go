package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConfigGeneratorDefaultOutputValidates pins the contract between the
// server dashboard's Config Generator and the client loader: the YAML below
// is exactly what the generator emits with its default form values
// (web/server/src/components/ConfigGenerator/GeneratorForm.tsx buildYaml).
// The previous generator invented a schema (local.*, routes[].pattern,
// action: proxy) whose untouched default output failed validation with
// "route must have at least one domain pattern". If the generator's shape
// changes, update this fixture in the same commit.
const generatorDefaultOutput = `server:
  address: proxy.example.com:7080
  protocol: http
proxy:
  http:
    listen: 127.0.0.1:7380
  socks5:
    listen: 127.0.0.1:7381
routes:
  - domains:
      - '*.local'
      - localhost
    action: direct
  - domains:
      - '*'
    action: server
logging:
  level: info
  format: text
`

// generatorAuthOutput is the same document with authentication enabled.
const generatorAuthOutput = `server:
  address: proxy.example.com:7080
  protocol: http
  username: alice
  password: secret
proxy:
  http:
    listen: 127.0.0.1:7380
  socks5:
    listen: 127.0.0.1:7381
routes:
  - domains:
      - '*'
    action: server
logging:
  level: info
  format: text
`

func loadGeneratorOutput(t *testing.T, content string) *ClientConfig {
	t.Helper()

	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	cfg := DefaultClientConfig()
	if err := Load(path, &cfg); err != nil {
		t.Fatalf("generator output failed to load: %v", err)
	}
	return &cfg
}

func TestConfigGeneratorDefaultOutputValidates(t *testing.T) {
	cfg := loadGeneratorOutput(t, generatorDefaultOutput)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("generator default output failed validation: %v", err)
	}

	if cfg.Server.Address != "proxy.example.com:7080" {
		t.Errorf("server address = %q", cfg.Server.Address)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(cfg.Routes))
	}
	if got := cfg.Routes[0].Domains; len(got) != 2 || got[0] != "*.local" || got[1] != "localhost" {
		t.Errorf("route 0 domains = %v", got)
	}
	if cfg.Routes[0].Action != "direct" || cfg.Routes[1].Action != "server" {
		t.Errorf("route actions = %q, %q", cfg.Routes[0].Action, cfg.Routes[1].Action)
	}
	if cfg.Proxy.HTTP.Listen != "127.0.0.1:7380" || cfg.Proxy.SOCKS5.Listen != "127.0.0.1:7381" {
		t.Errorf("proxy listeners = %q, %q", cfg.Proxy.HTTP.Listen, cfg.Proxy.SOCKS5.Listen)
	}
}

func TestConfigGeneratorAuthOutputValidates(t *testing.T) {
	cfg := loadGeneratorOutput(t, generatorAuthOutput)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("generator auth output failed validation: %v", err)
	}
	if cfg.Server.Username != "alice" || cfg.Server.Password != "secret" {
		t.Errorf("credentials not applied: %q / %q", cfg.Server.Username, cfg.Server.Password)
	}
}
