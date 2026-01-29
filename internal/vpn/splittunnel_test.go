package vpn

import (
	"net/netip"
	"testing"
	"time"
)

func TestSplitTunnelEngineExcludeMode(t *testing.T) {
	cfg := SplitTunnelConfig{
		Mode: "exclude",
		Apps: []AppRule{
			{Name: "slack"},
			{Name: "zoom"},
		},
		Domains: []string{
			"*.local",
			"*.company.internal",
		},
		IPs: []string{
			"10.0.0.0/8",
			"192.168.1.1",
		},
		AlwaysBypass: []string{
			"127.0.0.0/8",
		},
	}

	engine, err := NewSplitTunnelEngine(cfg, nil)
	if err != nil {
		t.Fatalf("NewSplitTunnelEngine failed: %v", err)
	}

	tests := []struct {
		name       string
		dstIP      string
		procInfo   *ProcessInfo
		wantAction Action
		wantMatch  string
	}{
		{
			name:       "localhost should bypass",
			dstIP:      "127.0.0.1",
			procInfo:   nil,
			wantAction: ActionBypass,
			wantMatch:  "always_bypass",
		},
		{
			name:       "10.x.x.x should bypass (exclude list)",
			dstIP:      "10.1.2.3",
			procInfo:   nil,
			wantAction: ActionBypass,
			wantMatch:  "ip",
		},
		{
			name:       "specific IP should bypass",
			dstIP:      "192.168.1.1",
			procInfo:   nil,
			wantAction: ActionBypass,
			wantMatch:  "ip",
		},
		{
			name:       "excluded app should bypass",
			dstIP:      "8.8.8.8",
			procInfo:   &ProcessInfo{Name: "slack"},
			wantAction: ActionBypass,
			wantMatch:  "app",
		},
		{
			name:       "unknown destination should tunnel",
			dstIP:      "93.184.216.34",
			procInfo:   nil,
			wantAction: ActionTunnel,
			wantMatch:  "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &IPPacket{
				DstIP: netip.MustParseAddr(tt.dstIP),
			}

			decision := engine.Decide(pkt, tt.procInfo)

			if decision.Action != tt.wantAction {
				t.Errorf("Decide() action = %v, want %v", decision.Action, tt.wantAction)
			}
			if decision.MatchedBy != tt.wantMatch {
				t.Errorf("Decide() matchedBy = %v, want %v", decision.MatchedBy, tt.wantMatch)
			}
		})
	}
}

func TestSplitTunnelEngineIncludeMode(t *testing.T) {
	cfg := SplitTunnelConfig{
		Mode: "include",
		IPs: []string{
			"93.184.216.0/24", // example.com range
		},
	}

	engine, err := NewSplitTunnelEngine(cfg, nil)
	if err != nil {
		t.Fatalf("NewSplitTunnelEngine failed: %v", err)
	}

	tests := []struct {
		name       string
		dstIP      string
		wantAction Action
	}{
		{
			name:       "included IP should tunnel",
			dstIP:      "93.184.216.34",
			wantAction: ActionTunnel,
		},
		{
			name:       "non-included IP should bypass",
			dstIP:      "8.8.8.8",
			wantAction: ActionBypass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &IPPacket{
				DstIP: netip.MustParseAddr(tt.dstIP),
			}

			decision := engine.Decide(pkt, nil)

			if decision.Action != tt.wantAction {
				t.Errorf("Decide() action = %v, want %v", decision.Action, tt.wantAction)
			}
		})
	}
}

func TestAppMatcher(t *testing.T) {
	matcher := NewAppMatcher()
	matcher.AddRule(AppRule{Name: "firefox"})
	matcher.AddRule(AppRule{Name: "Chrome", Path: "/Applications/Google Chrome.app"})

	tests := []struct {
		name    string
		proc    *ProcessInfo
		wantMatch bool
	}{
		{
			name:    "exact name match",
			proc:    &ProcessInfo{Name: "firefox"},
			wantMatch: true,
		},
		{
			name:    "case insensitive match",
			proc:    &ProcessInfo{Name: "FIREFOX"},
			wantMatch: true,
		},
		{
			name:    "path match",
			proc:    &ProcessInfo{Name: "chrome", Path: "/Applications/Google Chrome.app"},
			wantMatch: true,
		},
		{
			name:    "no match",
			proc:    &ProcessInfo{Name: "curl"},
			wantMatch: false,
		},
		{
			name:    "nil process",
			proc:    nil,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matcher.Match(tt.proc)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestIPMatcher(t *testing.T) {
	matcher := NewIPMatcher()
	matcher.Add("192.168.1.0/24")
	matcher.Add("10.0.0.1")
	matcher.Add("2001:db8::/32")

	tests := []struct {
		name    string
		ip      string
		wantMatch bool
	}{
		{
			name:    "CIDR match",
			ip:      "192.168.1.100",
			wantMatch: true,
		},
		{
			name:    "exact IP match",
			ip:      "10.0.0.1",
			wantMatch: true,
		},
		{
			name:    "IPv6 CIDR match",
			ip:      "2001:db8::1",
			wantMatch: true,
		},
		{
			name:    "no match",
			ip:      "8.8.8.8",
			wantMatch: false,
		},
		{
			name:    "outside CIDR",
			ip:      "192.168.2.1",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.ip)
			got := matcher.Match(addr)
			if got != tt.wantMatch {
				t.Errorf("Match(%s) = %v, want %v", tt.ip, got, tt.wantMatch)
			}
		})
	}
}

func TestSplitTunnelConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SplitTunnelConfig
		wantErr bool
	}{
		{
			name:    "empty mode defaults to exclude",
			cfg:     SplitTunnelConfig{},
			wantErr: false,
		},
		{
			name:    "valid exclude mode",
			cfg:     SplitTunnelConfig{Mode: "exclude"},
			wantErr: false,
		},
		{
			name:    "valid include mode",
			cfg:     SplitTunnelConfig{Mode: "include"},
			wantErr: false,
		},
		{
			name:    "invalid mode",
			cfg:     SplitTunnelConfig{Mode: "invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSplitTunnelEngine_RemoveDomain(t *testing.T) {
	cfg := SplitTunnelConfig{
		Mode:    "exclude",
		Domains: []string{"*.example.com", "*.test.com"},
	}

	dnsCache := NewDNSCache(5 * time.Minute)

	// Add an entry to the cache so we can test domain matching
	dnsCache.Put("test.example.com", []netip.Addr{netip.MustParseAddr("192.168.1.100")}, 5*time.Minute)

	engine, err := NewSplitTunnelEngine(cfg, dnsCache)
	if err != nil {
		t.Fatalf("NewSplitTunnelEngine failed: %v", err)
	}

	// Verify domain matches initially
	pkt := &IPPacket{DstIP: netip.MustParseAddr("192.168.1.100")}
	decision := engine.Decide(pkt, nil)
	if decision.MatchedBy != "domain" {
		t.Errorf("Expected domain match, got %s", decision.MatchedBy)
	}

	// Remove the domain pattern
	engine.RemoveDomain("*.example.com")

	// Should no longer match by domain (will match by default instead)
	decision = engine.Decide(pkt, nil)
	if decision.MatchedBy == "domain" {
		t.Errorf("Expected no domain match after removal, but still matching by domain")
	}
}

func TestSplitTunnelEngine_RemoveIP(t *testing.T) {
	cfg := SplitTunnelConfig{
		Mode: "exclude",
		IPs:  []string{"10.0.0.0/8", "192.168.1.1"},
	}

	engine, err := NewSplitTunnelEngine(cfg, nil)
	if err != nil {
		t.Fatalf("NewSplitTunnelEngine failed: %v", err)
	}

	// Verify IP matches initially
	pkt := &IPPacket{DstIP: netip.MustParseAddr("10.1.2.3")}
	decision := engine.Decide(pkt, nil)
	if decision.MatchedBy != "ip" {
		t.Errorf("Expected IP match, got %s", decision.MatchedBy)
	}

	// Remove the IP CIDR
	engine.RemoveIP("10.0.0.0/8")

	// Should no longer match by IP
	decision = engine.Decide(pkt, nil)
	if decision.MatchedBy == "ip" {
		t.Errorf("Expected no IP match after removal, but still matching by IP")
	}

	// Test removing exact IP
	pkt2 := &IPPacket{DstIP: netip.MustParseAddr("192.168.1.1")}
	decision = engine.Decide(pkt2, nil)
	if decision.MatchedBy != "ip" {
		t.Errorf("Expected IP match for exact IP, got %s", decision.MatchedBy)
	}

	engine.RemoveIP("192.168.1.1")
	decision = engine.Decide(pkt2, nil)
	if decision.MatchedBy == "ip" {
		t.Errorf("Expected no IP match after removal of exact IP")
	}
}

func TestSplitTunnelEngine_SetMode(t *testing.T) {
	cfg := SplitTunnelConfig{
		Mode: "exclude",
		IPs:  []string{"10.0.0.0/8"},
	}

	engine, err := NewSplitTunnelEngine(cfg, nil)
	if err != nil {
		t.Fatalf("NewSplitTunnelEngine failed: %v", err)
	}

	// In exclude mode, matched IPs bypass
	pkt := &IPPacket{DstIP: netip.MustParseAddr("10.1.2.3")}
	decision := engine.Decide(pkt, nil)
	if decision.Action != ActionBypass {
		t.Errorf("Expected bypass in exclude mode, got %v", decision.Action)
	}

	// Switch to include mode
	engine.SetMode("include")

	// In include mode, matched IPs tunnel
	decision = engine.Decide(pkt, nil)
	if decision.Action != ActionTunnel {
		t.Errorf("Expected tunnel in include mode, got %v", decision.Action)
	}

	// Switch back to exclude mode
	engine.SetMode("exclude")
	decision = engine.Decide(pkt, nil)
	if decision.Action != ActionBypass {
		t.Errorf("Expected bypass after switching back to exclude mode, got %v", decision.Action)
	}
}

func TestAppMatcher_RemoveRule(t *testing.T) {
	matcher := NewAppMatcher()
	matcher.AddRule(AppRule{Name: "firefox"})
	matcher.AddRule(AppRule{Name: "chrome"})
	matcher.AddRule(AppRule{Name: "slack"})

	// Verify all rules exist
	rules := matcher.Rules()
	if len(rules) != 3 {
		t.Fatalf("Expected 3 rules, got %d", len(rules))
	}

	// Remove chrome
	matcher.RemoveRule("chrome")

	rules = matcher.Rules()
	if len(rules) != 2 {
		t.Errorf("Expected 2 rules after removal, got %d", len(rules))
	}

	// Verify chrome no longer matches
	proc := &ProcessInfo{Name: "chrome"}
	if matcher.Match(proc) {
		t.Errorf("chrome should not match after removal")
	}

	// Verify firefox still matches
	proc = &ProcessInfo{Name: "firefox"}
	if !matcher.Match(proc) {
		t.Errorf("firefox should still match")
	}

	// Remove non-existent rule should not error
	matcher.RemoveRule("nonexistent")
	if len(matcher.Rules()) != 2 {
		t.Errorf("Removing non-existent rule should not affect count")
	}
}

func TestAppMatcher_Rules(t *testing.T) {
	matcher := NewAppMatcher()

	// Empty matcher
	rules := matcher.Rules()
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules, got %d", len(rules))
	}

	// Add rules
	matcher.AddRule(AppRule{Name: "firefox"})
	matcher.AddRule(AppRule{Name: "chrome", Path: "/usr/bin/chrome"})

	rules = matcher.Rules()
	if len(rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(rules))
	}

	// Verify the rules are copies (modifying returned slice doesn't affect matcher)
	rules[0].Name = "modified"
	originalRules := matcher.Rules()
	if originalRules[0].Name == "modified" {
		t.Errorf("Rules() should return a copy, not the original slice")
	}
}

func TestIPMatcher_Remove(t *testing.T) {
	matcher := NewIPMatcher()
	matcher.Add("10.0.0.0/8")
	matcher.Add("192.168.1.1")
	matcher.Add("2001:db8::/32")

	// Verify all entries match
	if !matcher.Match(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("10.1.2.3 should match 10.0.0.0/8")
	}
	if !matcher.Match(netip.MustParseAddr("192.168.1.1")) {
		t.Errorf("192.168.1.1 should match")
	}
	if !matcher.Match(netip.MustParseAddr("2001:db8::1")) {
		t.Errorf("2001:db8::1 should match")
	}

	// Remove CIDR
	matcher.Remove("10.0.0.0/8")
	if matcher.Match(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("10.1.2.3 should not match after CIDR removal")
	}

	// Remove exact IP
	matcher.Remove("192.168.1.1")
	if matcher.Match(netip.MustParseAddr("192.168.1.1")) {
		t.Errorf("192.168.1.1 should not match after removal")
	}

	// Remove IPv6 CIDR
	matcher.Remove("2001:db8::/32")
	if matcher.Match(netip.MustParseAddr("2001:db8::1")) {
		t.Errorf("2001:db8::1 should not match after CIDR removal")
	}

	// Remove non-existent entry should not panic
	matcher.Remove("8.8.8.8")
	matcher.Remove("172.16.0.0/12")
}

func TestIPMatcher_Entries(t *testing.T) {
	matcher := NewIPMatcher()

	// Empty matcher
	entries := matcher.Entries()
	if len(entries) != 0 {
		t.Errorf("Expected 0 entries, got %d", len(entries))
	}

	// Add entries
	matcher.Add("10.0.0.0/8")
	matcher.Add("192.168.1.1")
	matcher.Add("2001:db8::/32")

	entries = matcher.Entries()
	if len(entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(entries))
	}

	// Verify entries contain expected values
	hasIP := false
	hasCIDR := false
	hasIPv6CIDR := false

	for _, entry := range entries {
		switch entry {
		case "192.168.1.1":
			hasIP = true
		case "10.0.0.0/8":
			hasCIDR = true
		case "2001:db8::/32":
			hasIPv6CIDR = true
		}
	}

	if !hasIP {
		t.Errorf("Entries should contain 192.168.1.1")
	}
	if !hasCIDR {
		t.Errorf("Entries should contain 10.0.0.0/8")
	}
	if !hasIPv6CIDR {
		t.Errorf("Entries should contain 2001:db8::/32")
	}
}

func TestIPMatcher_AddLegacyFormat(t *testing.T) {
	matcher := NewIPMatcher()

	// Add using legacy net.IP compatible string format
	matcher.Add("192.168.1.1")

	// Should still match
	if !matcher.Match(netip.MustParseAddr("192.168.1.1")) {
		t.Errorf("Should match IP added in string format")
	}
}

func TestSplitTunnelEngine_AddRemoveApp(t *testing.T) {
	cfg := SplitTunnelConfig{Mode: "exclude"}

	engine, err := NewSplitTunnelEngine(cfg, nil)
	if err != nil {
		t.Fatalf("NewSplitTunnelEngine failed: %v", err)
	}

	// Initially no apps match
	pkt := &IPPacket{DstIP: netip.MustParseAddr("8.8.8.8")}
	proc := &ProcessInfo{Name: "firefox"}

	decision := engine.Decide(pkt, proc)
	if decision.MatchedBy == "app" {
		t.Errorf("Expected no app match initially")
	}

	// Add app rule
	engine.AddApp(AppRule{Name: "firefox"})

	decision = engine.Decide(pkt, proc)
	if decision.MatchedBy != "app" {
		t.Errorf("Expected app match after adding rule, got %s", decision.MatchedBy)
	}

	// Remove app rule
	engine.RemoveApp("firefox")

	decision = engine.Decide(pkt, proc)
	if decision.MatchedBy == "app" {
		t.Errorf("Expected no app match after removal")
	}
}

func TestConfigError(t *testing.T) {
	err := &ConfigError{Field: "test.field", Message: "test message"}
	expected := "config error: test.field: test message"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}
