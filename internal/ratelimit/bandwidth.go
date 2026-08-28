package ratelimit

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// BandwidthConfig holds bandwidth throttling configuration.
type BandwidthConfig struct {
	Upload   int64 // bytes per second
	Download int64 // bytes per second
}

// ParseBandwidth parses a bandwidth string like "10Mbps" or "1024kbps".
func ParseBandwidth(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0, nil
	}

	multiplier := int64(1)

	// Check for unit suffixes
	if strings.HasSuffix(s, "gbps") {
		multiplier = 1000 * 1000 * 1000 / 8 // bits to bytes
		s = strings.TrimSuffix(s, "gbps")
	} else if strings.HasSuffix(s, "mbps") {
		multiplier = 1000 * 1000 / 8
		s = strings.TrimSuffix(s, "mbps")
	} else if strings.HasSuffix(s, "kbps") {
		multiplier = 1000 / 8
		s = strings.TrimSuffix(s, "kbps")
	} else if strings.HasSuffix(s, "bps") {
		// bps (bits per second) - use float to avoid integer division resulting in zero
		s = strings.TrimSuffix(s, "bps")
		value, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid bandwidth value: %w", err)
		}
		return int64(value / 8), nil
	} else if strings.HasSuffix(s, "gb/s") || strings.HasSuffix(s, "gbyte/s") {
		multiplier = 1000 * 1000 * 1000
		s = strings.TrimSuffix(strings.TrimSuffix(s, "gbyte/s"), "gb/s")
	} else if strings.HasSuffix(s, "mb/s") || strings.HasSuffix(s, "mbyte/s") {
		multiplier = 1000 * 1000
		s = strings.TrimSuffix(strings.TrimSuffix(s, "mbyte/s"), "mb/s")
	} else if strings.HasSuffix(s, "kb/s") || strings.HasSuffix(s, "kbyte/s") {
		multiplier = 1000
		s = strings.TrimSuffix(strings.TrimSuffix(s, "kbyte/s"), "kb/s")
	} else if strings.HasSuffix(s, "b/s") || strings.HasSuffix(s, "byte/s") {
		multiplier = 1
		s = strings.TrimSuffix(strings.TrimSuffix(s, "byte/s"), "b/s")
	}

	value, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid bandwidth value: %w", err)
	}

	return int64(value * float64(multiplier)), nil
}

// ThrottledConn wraps a net.Conn with bandwidth throttling.
type ThrottledConn struct {
	net.Conn
	readLimiter  *TokenBucket
	writeLimiter *TokenBucket
}

// NewThrottledConn wraps a connection with bandwidth limits.
func NewThrottledConn(conn net.Conn, download, upload int64) *ThrottledConn {
	tc := &ThrottledConn{
		Conn: conn,
	}

	if download > 0 {
		// Use download rate as tokens per second, burst of 1 second
		tc.readLimiter = NewTokenBucket(float64(download), int(download))
	}

	if upload > 0 {
		tc.writeLimiter = NewTokenBucket(float64(upload), int(upload))
	}

	return tc
}

// Read reads data with bandwidth throttling.
func (tc *ThrottledConn) Read(b []byte) (int, error) {
	if tc.readLimiter == nil {
		return tc.Conn.Read(b)
	}

	// Limit read size to available tokens or a minimum chunk
	maxRead := len(b)
	available := int(tc.readLimiter.Tokens())
	if available > 0 && available < maxRead {
		maxRead = available
	}
	if maxRead < 1 {
		maxRead = 1
	}

	n, err := tc.Conn.Read(b[:maxRead])
	if n > 0 {
		// Wait for tokens to be available
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = tc.readLimiter.WaitN(ctx, n) //nolint:errcheck // Best effort rate limiting after successful read
	}

	return n, err
}

// Write writes data with bandwidth throttling.
func (tc *ThrottledConn) Write(b []byte) (int, error) {
	if tc.writeLimiter == nil {
		return tc.Conn.Write(b)
	}

	written := 0
	remaining := b

	for len(remaining) > 0 {
		// Wait for tokens
		chunkSize := len(remaining)
		available := int(tc.writeLimiter.Tokens())
		if available > 0 && available < chunkSize {
			chunkSize = available
		}
		if chunkSize < 1 {
			chunkSize = 1
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := tc.writeLimiter.WaitN(ctx, chunkSize); err != nil {
			cancel()
			return written, err
		}
		cancel()

		n, err := tc.Conn.Write(remaining[:chunkSize])
		written += n
		remaining = remaining[n:]

		if err != nil {
			return written, err
		}
	}

	return written, nil
}
