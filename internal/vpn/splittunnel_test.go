package vpn

import (
	"net/netip"
	"testing"
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
