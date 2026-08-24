package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// CopyBidirectionalWithIdle copies data bidirectionally between two
// connections and tears the pair down when neither has carried any data for
// idleTimeout. It is the enforcement point for a listener's idle_timeout on an
// established tunnel or relay.
//
// The idle test is deliberately about the pair, not about either connection on
// its own: a large download leaves the client->target direction silent for
// minutes, and a per-socket read deadline would tear that down. Only a tunnel
// that has gone quiet in BOTH directions is reaped, so an actively transferring
// tunnel is never interrupted no matter how long it lives.
//
// idleTimeout <= 0 disables reaping and behaves exactly like
// CopyBidirectional, which is what an operator who sets idle_timeout: 0 asks
// for.
func CopyBidirectionalWithIdle(ctx context.Context, conn1, conn2 net.Conn, idleTimeout time.Duration) (sent, received int64) {
	if idleTimeout <= 0 {
		return CopyBidirectional(ctx, conn1, conn2)
	}

	clock := newActivityClock()
	// The write-progress window is half the idle timeout so that a slow but
	// progressing transfer marks the clock strictly more often than the
	// watchdog's reap threshold — a window equal to the timeout would race the
	// watchdog at the boundary.
	window := idleTimeout / 2
	watched1 := &activityConn{Conn: conn1, clock: clock, window: window}
	watched2 := &activityConn{Conn: conn2, clock: clock, window: window}

	stop := make(chan struct{})
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		ticker := time.NewTicker(idleCheckInterval(idleTimeout))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				idle := clock.idleFor()
				if idle < idleTimeout {
					continue
				}
				slog.Debug("reaping idle proxied connection",
					"idle_timeout", idleTimeout,
					"idle_for", idle,
					"remote_addr", conn1.RemoteAddr(),
				)
				// Expire both ends rather than closing them. An expired
				// deadline unblocks the in-flight io.Copy calls just as well,
				// but leaves the actual Close to the copy loop's caller --
				// closing a connection from this goroutine would race the copy
				// goroutines still reading and writing it. The expired flag is
				// set first so a progress-aware write cannot re-arm its window
				// and undo the expiry.
				clock.expired.Store(true)
				expireDeadlines(conn1)
				expireDeadlines(conn2)
				return
			}
		}
	}()

	sent, received = CopyBidirectional(ctx, watched1, watched2)
	close(stop)
	<-watchdogDone
	return sent, received
}

// deadlineBackdate is how far into the past expireDeadlines sets a deadline.
// Any value in the past works; a second of margin keeps it unambiguous against
// clock granularity.
const deadlineBackdate = time.Second

// expireDeadlines sets both deadlines on conn into the past, which makes any
// in-flight and subsequent read or write fail immediately. It is the
// thread-safe way to unblock a copy loop from outside its goroutines.
func expireDeadlines(conn net.Conn) {
	past := time.Now().Add(-deadlineBackdate)
	if err := conn.SetReadDeadline(past); err != nil {
		slog.Debug("failed to expire read deadline on idle connection", "error", err)
	}
	if err := conn.SetWriteDeadline(past); err != nil {
		slog.Debug("failed to expire write deadline on idle connection", "error", err)
	}
}

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
