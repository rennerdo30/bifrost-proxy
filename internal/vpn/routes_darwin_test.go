//go:build darwin

package vpn

import "testing"

func TestIPv4MaskString(t *testing.T) {
	tests := []struct {
		bits int
		want string
	}{
		{0, "0.0.0.0"},
		{1, "128.0.0.0"},
		{8, "255.0.0.0"},
		{16, "255.255.0.0"},
		{24, "255.255.255.0"},
		{25, "255.255.255.128"},
		{32, "255.255.255.255"},
	}

	for _, tt := range tests {
		if got := ipv4MaskString(tt.bits); got != tt.want {
			t.Errorf("ipv4MaskString(%d) = %q, want %q", tt.bits, got, tt.want)
		}
	}
}
