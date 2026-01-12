package util

import (
	"net"
	"testing"
)

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{
			name:     "host with port",
			addr:     "example.com:8080",
			wantHost: "example.com",
			wantPort: 8080,
			wantErr:  false,
		},
		{
			name:     "IP with port",
			addr:     "192.168.1.1:443",
			wantHost: "192.168.1.1",
			wantPort: 443,
			wantErr:  false,
		},
		{
			name:     "localhost with port",
			addr:     "localhost:3000",
			wantHost: "localhost",
			wantPort: 3000,
			wantErr:  false,
		},
		{
			name:     "host without port",
			addr:     "example.com",
			wantHost: "example.com",
			wantPort: 0,
			wantErr:  false,
		},
		{
			name:     "IPv6 with port",
			addr:     "[::1]:8080",
			wantHost: "::1",
			wantPort: 8080,
			wantErr:  false,
		},
		{
			name:     "colon only",
			addr:     ":8080",
			wantHost: "",
			wantPort: 8080,
			wantErr:  false,
		},
		{
			name:    "invalid port",
			addr:    "example.com:invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := SplitHostPort(tt.addr)

			if tt.wantErr {
				if err == nil {
					t.Error("SplitHostPort() should return error")
				}
				return
			}

			if err != nil {
				t.Errorf("SplitHostPort() error = %v", err)
				return
			}

			if host != tt.wantHost {
				t.Errorf("SplitHostPort() host = %s, want %s", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("SplitHostPort() port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestJoinHostPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{
			name: "simple host",
			host: "example.com",
			port: 8080,
			want: "example.com:8080",
		},
		{
			name: "IP address",
			host: "192.168.1.1",
			port: 443,
			want: "192.168.1.1:443",
		},
		{
			name: "IPv6",
			host: "::1",
			port: 8080,
			want: "[::1]:8080",
		},
		{
			name: "empty host",
			host: "",
			port: 3000,
			want: ":3000",
		},
		{
			name: "port zero",
			host: "localhost",
			port: 0,
			want: "localhost:0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := JoinHostPort(tt.host, tt.port)
			if result != tt.want {
				t.Errorf("JoinHostPort() = %s, want %s", result, tt.want)
			}
		})
	}
}

func TestIsLocalAddress(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{"localhost", "localhost", true},
		{"localhost with port", "localhost:8080", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1 with port", "127.0.0.1:3000", true},
		{"::1", "::1", true},
		{"0.0.0.0", "0.0.0.0", true},
		{"public IP", "8.8.8.8", false},
		{"public IP with port", "8.8.8.8:53", false},
		{"domain", "example.com", false},
		{"LOCALHOST uppercase", "LOCALHOST", true},
		{"127.0.0.x range", "127.0.0.255", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsLocalAddress(tt.addr)
			if result != tt.want {
				t.Errorf("IsLocalAddress(%s) = %v, want %v", tt.addr, result, tt.want)
			}
		})
	}
}

func TestGetOutboundIP(t *testing.T) {
	ip, err := GetOutboundIP()

	// This test might fail in isolated environments without network
	if err != nil {
		t.Skipf("GetOutboundIP() failed (may be network issue): %v", err)
	}

	if ip == nil {
		t.Error("GetOutboundIP() returned nil IP")
	}

	// Should be a valid IP, not loopback
	if ip.IsLoopback() {
		t.Error("GetOutboundIP() returned loopback address")
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantIP  string
		wantErr bool
	}{
		{
			name:   "valid CIDR IPv4",
			cidr:   "192.168.1.0/24",
			wantIP: "192.168.1.0",
		},
		{
			name:   "valid CIDR IPv6",
			cidr:   "2001:db8::/32",
			wantIP: "2001:db8::",
		},
		{
			name:   "single IPv4",
			cidr:   "192.168.1.1",
			wantIP: "192.168.1.1",
		},
		{
			name:   "single IPv6",
			cidr:   "::1",
			wantIP: "::1",
		},
		{
			name:    "invalid CIDR",
			cidr:    "invalid",
			wantErr: true,
		},
		{
			name:    "invalid IP format",
			cidr:    "256.256.256.256",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, err := ParseCIDR(tt.cidr)

			if tt.wantErr {
				if err == nil {
					t.Error("ParseCIDR() should return error")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseCIDR() error = %v", err)
				return
			}

			if network == nil {
				t.Fatal("ParseCIDR() returned nil network")
			}

			// Check the network IP contains expected IP
			expectedIP := net.ParseIP(tt.wantIP)
			if !network.Contains(expectedIP) {
				t.Errorf("ParseCIDR() network doesn't contain expected IP %s", tt.wantIP)
			}
		})
	}
}

func TestIPInNetworks(t *testing.T) {
	// Create some test networks
	net1, _ := ParseCIDR("192.168.1.0/24")
	net2, _ := ParseCIDR("10.0.0.0/8")
	networks := []*net.IPNet{net1, net2}

	tests := []struct {
		name     string
		ip       string
		networks []*net.IPNet
		want     bool
	}{
		{
			name:     "IP in first network",
			ip:       "192.168.1.100",
			networks: networks,
			want:     true,
		},
		{
			name:     "IP in second network",
			ip:       "10.20.30.40",
			networks: networks,
			want:     true,
		},
		{
			name:     "IP not in any network",
			ip:       "8.8.8.8",
			networks: networks,
			want:     false,
		},
		{
			name:     "empty networks",
			ip:       "192.168.1.1",
			networks: nil,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IPInNetworks(ip, tt.networks)
			if result != tt.want {
				t.Errorf("IPInNetworks() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestGetHostFromRequest(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "simple host",
			host: "example.com",
			want: "example.com",
		},
		{
			name: "host with port",
			host: "example.com:8080",
			want: "example.com",
		},
		{
			name: "uppercase host",
			host: "EXAMPLE.COM",
			want: "example.com",
		},
		{
			name: "IPv6 with brackets",
			host: "[::1]",
			want: "::1",
		},
		{
			name: "IPv6 with brackets and port",
			host: "[::1]:8080",
			want: "::1",
		},
		{
			name: "IPv6 no brackets",
			host: "2001:db8::1",
			want: "2001:db8:",
		},
		{
			name: "empty string",
			host: "",
			want: "",
		},
		{
			name: "IP with port",
			host: "192.168.1.1:443",
			want: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHostFromRequest(tt.host)
			if result != tt.want {
				t.Errorf("GetHostFromRequest(%q) = %q, want %q", tt.host, result, tt.want)
			}
		})
	}
}
