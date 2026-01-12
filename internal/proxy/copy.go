package proxy

import (
	"context"
	"io"
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
		sent, _ = copyWithContext(ctx, conn2, conn1)
		// Close write side of conn2 to signal EOF
		if c, ok := conn2.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()

	// Copy conn2 -> conn1
	go func() {
		defer wg.Done()
		received, _ = copyWithContext(ctx, conn1, conn2)
		// Close write side of conn1 to signal EOF
		if c, ok := conn1.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()

	wg.Wait()
	return sent, received
}

// copyWithContext copies from src to dst until src returns EOF or ctx is cancelled.
func copyWithContext(ctx context.Context, dst, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024) // 32KB buffer
	var total int64

	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}

		// Set read deadline for interruptibility
		src.SetReadDeadline(time.Now().Add(5 * time.Second))

		n, err := src.Read(buf)
		if n > 0 {
			// Clear deadline for write
			dst.SetWriteDeadline(time.Time{})

			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout is expected, continue
				continue
			}
			if err == io.EOF {
				return total, nil
			}
			return total, err
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
