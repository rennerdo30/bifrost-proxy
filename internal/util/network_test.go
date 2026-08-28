package util

import (
	"testing"
)

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
			host: "example.com:7080",
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
			host: "[::1]:7080",
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
