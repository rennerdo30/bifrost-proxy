//go:build darwin

package vpn

// This file is kept for backwards compatibility.
// TUN device creation is now handled by the device package.
// The CreateTUN function in tun.go delegates to device.Create().
