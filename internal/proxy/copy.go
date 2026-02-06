package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// CopyBidirectional copies data bidirectionally between two connections.
func CopyBidirectional(ctx context.Context, conn1, conn2 net.Conn) (sent, received int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy conn1 -> conn2
	go func() {
		defer wg.Done()
		sent, _ = copyWithContext(ctx, conn2, conn1) //nolint:errcheck // Error is not returned, bytes count suffices
		// Close write side of conn2 to signal EOF
		if c, ok := conn2.(interface{ CloseWrite() error }); ok {
			if err := c.CloseWrite(); err != nil {
				slog.Debug("failed to close write side of destination connection", "error", err)
			}
		}
	}()

	// Copy conn2 -> conn1
	go func() {
		defer wg.Done()
		received, _ = copyWithContext(ctx, conn1, conn2) //nolint:errcheck // Error is not returned, bytes count suffices
		// Close write side of conn1 to signal EOF
		if c, ok := conn1.(interface{ CloseWrite() error }); ok {
			if err := c.CloseWrite(); err != nil {
				slog.Debug("failed to close write side of source connection", "error", err)
			}
		}
	}()

	wg.Wait()
	return sent, received
}

// copyWithContext copies from src to dst until src returns EOF or ctx is canceled.
func copyWithContext(ctx context.Context, dst, src net.Conn) (int64, error) {
	// Use a simple io.Copy - it will be interrupted when connections are closed
	// by the caller or when EOF is reached
	type result struct {
		n   int64
		err error
	}

	done := make(chan result, 1)

	go func() {
		n, err := io.Copy(dst, src)
		done <- result{n, err}
	}()

	select {
	case r := <-done:
		if r.err == io.EOF {
			return r.n, nil
		}
		return r.n, r.err
	case <-ctx.Done():
		// Context canceled - set deadline to force io.Copy to return
		// This ensures the goroutine doesn't leak
		deadline := time.Now().Add(100 * time.Millisecond)
		if err := src.SetReadDeadline(deadline); err != nil {
			slog.Debug("failed to set read deadline on source connection", "error", err)
		}
		if err := dst.SetWriteDeadline(deadline); err != nil {
			slog.Debug("failed to set write deadline on destination connection", "error", err)
		}

		// Wait for the goroutine to finish
		select {
		case r := <-done:
			// Return the bytes copied so far
			return r.n, ctx.Err()
		case <-time.After(time.Second):
			// Force close connections to unblock the goroutine
			src.Close()
			dst.Close()
			// Drain the result with timeout to prevent blocking forever
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				slog.Debug("io.Copy goroutine did not exit after force close")
			}
			return 0, ctx.Err()
		}
	}
}

// CopyBidirectionalWithStats copies data and returns statistics.
func CopyBidirectionalWithStats(ctx context.Context, conn1, conn2 net.Conn) CopyStats {
	start := time.Now()
	sent, received := CopyBidirectional(ctx, conn1, conn2)

	return CopyStats{
		BytesSent:     sent,
		BytesReceived: received,
		Duration:      time.Since(start),
	}
}

// CopyStats holds statistics about a bidirectional copy operation.
type CopyStats struct {
	BytesSent     int64
	BytesReceived int64
	Duration      time.Duration
}

// TotalBytes returns the total bytes transferred.
func (s CopyStats) TotalBytes() int64 {
	return s.BytesSent + s.BytesReceived
}

// Throughput returns the average throughput in bytes per second.
func (s CopyStats) Throughput() float64 {
	if s.Duration == 0 {
		return 0
	}
	return float64(s.TotalBytes()) / s.Duration.Seconds()
}
