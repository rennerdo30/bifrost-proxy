package ratelimit

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
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
		multiplier = 1 / 8
		s = strings.TrimSuffix(s, "bps")
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

// FormatBandwidth formats a bandwidth value to a human-readable string.
func FormatBandwidth(bytesPerSecond int64) string {
	bps := bytesPerSecond * 8

	if bps >= 1000*1000*1000 {
		return fmt.Sprintf("%.2f Gbps", float64(bps)/(1000*1000*1000))
	} else if bps >= 1000*1000 {
		return fmt.Sprintf("%.2f Mbps", float64(bps)/(1000*1000))
	} else if bps >= 1000 {
		return fmt.Sprintf("%.2f Kbps", float64(bps)/1000)
	}
	return fmt.Sprintf("%d bps", bps)
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
		tc.readLimiter.WaitN(ctx, n)
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

// ThrottledReader wraps an io.Reader with bandwidth throttling.
type ThrottledReader struct {
	reader  io.Reader
	limiter *TokenBucket
	mu      sync.Mutex
}

// NewThrottledReader creates a new throttled reader.
func NewThrottledReader(r io.Reader, bytesPerSecond int64) *ThrottledReader {
	return &ThrottledReader{
		reader:  r,
		limiter: NewTokenBucket(float64(bytesPerSecond), int(bytesPerSecond)),
	}
}

// Read implements io.Reader with throttling.
func (tr *ThrottledReader) Read(p []byte) (int, error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	// Limit read size
	maxRead := len(p)
	available := int(tr.limiter.Tokens())
	if available > 0 && available < maxRead {
		maxRead = available
	}
	if maxRead < 1 {
		maxRead = 1
	}

	n, err := tr.reader.Read(p[:maxRead])
	if n > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tr.limiter.WaitN(ctx, n)
	}

	return n, err
}

// ThrottledWriter wraps an io.Writer with bandwidth throttling.
type ThrottledWriter struct {
	writer  io.Writer
	limiter *TokenBucket
	mu      sync.Mutex
}

// NewThrottledWriter creates a new throttled writer.
func NewThrottledWriter(w io.Writer, bytesPerSecond int64) *ThrottledWriter {
	return &ThrottledWriter{
		writer:  w,
		limiter: NewTokenBucket(float64(bytesPerSecond), int(bytesPerSecond)),
	}
}

// Write implements io.Writer with throttling.
func (tw *ThrottledWriter) Write(p []byte) (int, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	written := 0
	remaining := p

	for len(remaining) > 0 {
		chunkSize := len(remaining)
		available := int(tw.limiter.Tokens())
		if available > 0 && available < chunkSize {
			chunkSize = available
		}
		if chunkSize < 1 {
			chunkSize = 1
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := tw.limiter.WaitN(ctx, chunkSize); err != nil {
			cancel()
			return written, err
		}
		cancel()

		n, err := tw.writer.Write(remaining[:chunkSize])
		written += n
		remaining = remaining[n:]

		if err != nil {
			return written, err
		}
	}

	return written, nil
}
