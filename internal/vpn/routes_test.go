package vpn

import "testing"

func TestNormalizeCIDR(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"10.0.0.0/8", "10.0.0.0/8", false},
		{"192.168.1.5/24", "192.168.1.0/24", false}, // host bits masked off
		{"1.2.3.4", "1.2.3.4/32", false},            // bare IPv4 -> /32
		{"2001:db8::1", "2001:db8::1/128", false},   // bare IPv6 -> /128
		{"2001:db8::/32", "2001:db8::/32", false},
		{"not-an-ip", "", true},
		{"10.0.0.0/99", "", true},
	}

	for _, tt := range tests {
		got, err := normalizeCIDR(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("normalizeCIDR(%q) expected error, got %q", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeCIDR(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("normalizeCIDR(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
