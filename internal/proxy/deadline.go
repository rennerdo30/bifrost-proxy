package proxy

import (
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// Idle-watchdog tuning. The watchdog samples a shared activity clock rather
// than relying on socket deadlines, because a tunnel is only truly idle when
// *neither* direction has moved data: a large download legitimately leaves the
// client->target direction silent for minutes.
const (
	// idleCheckDivisor divides the configured idle timeout to derive the
	// watchdog tick, so a connection that goes quiet is reaped within roughly
	// idleTimeout + idleTimeout/idleCheckDivisor.
	idleCheckDivisor = 4

	// minIdleCheckInterval floors the watchdog tick so a very small
	// idle_timeout cannot spin the watchdog goroutine.
	minIdleCheckInterval = 5 * time.Millisecond

	// maxIdleCheckInterval caps the watchdog tick so a large idle_timeout still
	// reaps promptly once it has elapsed.
	maxIdleCheckInterval = 5 * time.Second
)

// readMode selects which listener timeout governs reads from the client on a
// deadlineConn. The mode changes as a connection moves through its phases;
// getting this wrong in either direction is a real bug, so each value records
// why it exists.
type readMode int32

const (
	// readModeNone applies no read deadline at all. It is the state of an
	// established opaque tunnel, where the client may legitimately stay silent
	// for as long as the peer keeps talking. Reaping such a connection is the
	// idle watchdog's job, not a socket deadline's.
	readModeNone readMode = iota

	// readModeRequest bounds the wait for the first byte of an inbound request
	// with idle_timeout: the connection is established but carries no request,
	// which is exactly what "idle" means. On the first byte the mode advances
	// to readModeHeader.
	readModeRequest

	// readModeHeader means an absolute read_timeout deadline is already armed
	// and must NOT be re-armed: the complete request line and header block has
	// to arrive within read_timeout of the first byte. A rolling deadline here
	// would leave slowloris open, since a client trickling one byte per
	// interval would refresh it forever.
	readModeHeader

	// readModeBody applies read_timeout to each individual read. A large
	// request body may take arbitrarily long in total as long as it keeps
	// making progress.
	readModeBody

	// readModeIdle applies idle_timeout to each individual read. It is used for
	// a kept-alive exchange loop (the MITM data path), where the wait between
	// one response and the next request is genuine idle time.
	readModeIdle
)

// deadlineConn wraps a client connection and applies the listener's
// read_timeout, write_timeout and idle_timeout as real socket deadlines.
//
// Deadlines are applied per call rather than as one absolute deadline for the
// whole connection, except during the request header phase. That distinction is
// the whole design:
//
//   - A single absolute deadline over the header block is what closes
//     slowloris.
//   - Per-call deadlines everywhere else are what keep long-lived traffic
//     working: an absolute write deadline would kill a streaming (SSE,
//     chunked, large-file) response mid-flight, and an absolute read deadline
//     would kill a slow-but-progressing upload.
//   - An established tunnel gets no deadline at all and is bounded by the idle
//     watchdog instead, which only fires when both directions are quiet.
//
// A zero timeout disables that deadline, preserving the historical unbounded
// behavior for operators who set it to 0.
type deadlineConn struct {
	net.Conn

	// readTimeout, writeTimeout and idleTimeout are the listener's configured
	// values. They are set once at construction and never mutated.
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration

	// mode is the current readMode, mutated as the connection changes phase
	// (possibly from a different goroutine than the one reading, which is why
	// it is atomic).
	mode atomic.Int32

	// writeDeadlines enables the per-write deadline. It is disabled for
	// tunnels, where the connection has been handed to an opaque copy loop.
	writeDeadlines atomic.Bool
}

// newDeadlineConn wraps conn with the supplied listener timeouts. All three may
// be zero, in which case the wrapper is inert and behavior is unchanged.
func newDeadlineConn(conn net.Conn, read, write, idle time.Duration) *deadlineConn {
	return &deadlineConn{
		Conn:         conn,
		readTimeout:  read,
		writeTimeout: write,
		idleTimeout:  idle,
	}
}

// connDeadlines walks the wrapper chain around conn and returns the
// deadlineConn, or nil when the connection is not deadline-managed (which is
// the case in tests that hand a bare net.Conn to a handler's internals). Every
// method on *deadlineConn used to change phase is nil-safe, so callers do not
// need to check.
func connDeadlines(conn net.Conn) *deadlineConn {
	for {
		switch v := conn.(type) {
		case *deadlineConn:
			return v
		case *countingConn:
			conn = v.Conn
		default:
			return nil
		}
	}
}

// idleWait returns the timeout that bounds a connection with no request in
// flight. idle_timeout owns this; read_timeout stands in when idle_timeout is
// unset so that configuring only read_timeout still bounds a client that
// connects and then says nothing.
func (c *deadlineConn) idleWait() time.Duration {
	if c.idleTimeout > 0 {
		return c.idleTimeout
	}
	return c.readTimeout
}

// beginHandshake bounds the TLS handshake that must complete before the first
// request can be read. The handshake happens inside the tls.Conn, below this
// wrapper's Read, so the deadline is armed directly on the socket; without it
// a client could complete a TCP connect, start a handshake and stall forever,
// pinning a goroutine and a file descriptor — the original slowloris finding,
// resurfacing one layer down on TLS-enabled listeners. Returns whether a
// deadline was armed so the caller knows to clear it afterwards.
func (c *deadlineConn) beginHandshake() bool {
	if c == nil {
		return false
	}
	d := c.readTimeout
	if d <= 0 {
		d = c.idleWait()
	}
	if d <= 0 {
		return false
	}
	c.arm(c.Conn.SetReadDeadline, d)
	c.arm(c.Conn.SetWriteDeadline, d)
	return true
}

// endHandshake clears the absolute deadlines beginHandshake armed, so they
// cannot fire later inside a long response or an established tunnel.
func (c *deadlineConn) endHandshake() {
	if c == nil {
		return
	}
	c.arm(c.Conn.SetReadDeadline, 0)
	c.arm(c.Conn.SetWriteDeadline, 0)
}

// beginRequest arms the inbound-request deadlines: idle_timeout until the first
// byte arrives, then read_timeout for the rest of the header block, with
// per-write deadlines active so an error response cannot block forever.
func (c *deadlineConn) beginRequest() {
	if c == nil {
		return
	}
	c.writeDeadlines.Store(true)
	if c.idleWait() > 0 {
		c.setMode(readModeRequest)
		return
	}
	c.setMode(readModeNone)
}

// beginBody switches to per-read deadlines, for the request body and anything
// else read from the client after its headers.
func (c *deadlineConn) beginBody() {
	if c == nil {
		return
	}
	c.setMode(readModeBody)
	c.arm(c.Conn.SetReadDeadline, 0)
}

// enterTunnel hands the connection to an opaque copy loop: all deadlines are
// cleared and no new ones are armed. Both the pending absolute header deadline
// and the per-write deadline must go, or a long-lived CONNECT tunnel would be
// torn down the moment either elapsed.
func (c *deadlineConn) enterTunnel() {
	if c == nil {
		return
	}
	c.setMode(readModeNone)
	c.writeDeadlines.Store(false)
	c.arm(c.Conn.SetReadDeadline, 0)
	c.arm(c.Conn.SetWriteDeadline, 0)
}

// enterKeptAlive hands the connection to a kept-alive exchange loop (the MITM
// data path). Reads are bounded by idle_timeout, because the wait between one
// response and the next request on that loop is idle time; writes keep their
// per-write deadline.
func (c *deadlineConn) enterKeptAlive() {
	if c == nil {
		return
	}
	c.writeDeadlines.Store(true)
	c.arm(c.Conn.SetReadDeadline, 0)
	if c.idleWait() > 0 {
		c.setMode(readModeIdle)
		return
	}
	c.setMode(readModeNone)
}

func (c *deadlineConn) setMode(m readMode) {
	c.mode.Store(int32(m))
}

// arm sets or clears a deadline. A zero duration clears it.
func (c *deadlineConn) arm(set func(time.Time) error, d time.Duration) {
	var t time.Time
	if d > 0 {
		t = time.Now().Add(d)
	}
	if err := set(t); err != nil {
		slog.Debug("failed to set connection deadline",
			"error", err,
			"timeout", d,
			"remote_addr", c.Conn.RemoteAddr(),
		)
	}
}

// Read applies the read deadline for the current phase, then reads.
func (c *deadlineConn) Read(b []byte) (int, error) {
	switch readMode(c.mode.Load()) {
	case readModeRequest:
		c.arm(c.Conn.SetReadDeadline, c.idleWait())
	case readModeBody:
		c.arm(c.Conn.SetReadDeadline, c.readTimeout)
	case readModeIdle:
		c.arm(c.Conn.SetReadDeadline, c.idleWait())
	case readModeNone, readModeHeader:
		// readModeNone: deliberately unbounded. readModeHeader: an absolute
		// deadline is already armed and re-arming it would defeat it.
	}

	n, err := c.Conn.Read(b)

	// The first byte of a request means the connection is no longer idle: swap
	// the idle bound for a single absolute read_timeout covering the remainder
	// of the header block.
	if n > 0 && readMode(c.mode.Load()) == readModeRequest {
		c.setMode(readModeHeader)
		c.arm(c.Conn.SetReadDeadline, c.readTimeout)
	}
	return n, err
}

// Write applies write_timeout as a NO-PROGRESS bound: each window of
// write_timeout must move at least one byte toward the client, so a slow but
// steadily consuming receiver is never cut off, while a receiver that has
// stopped reading entirely still times out. A single fixed deadline over the
// whole Write call — the previous behavior — killed a large response to a slow
// consumer even though every window carried data.
//
// One documented caveat: on a TLS-terminated listener a timed-out window is
// fatal, because crypto/tls corrupts its record state on a write timeout and
// rejects all further writes. There the semantics degrade to a per-window
// absolute bound; a progressing plaintext response is never truncated.
func (c *deadlineConn) Write(b []byte) (int, error) {
	if !c.writeDeadlines.Load() || c.writeTimeout <= 0 {
		return c.Conn.Write(b)
	}
	total := 0
	for {
		c.arm(c.Conn.SetWriteDeadline, c.writeTimeout)
		n, err := c.Conn.Write(b[total:])
		total += n
		if err == nil {
			return total, nil
		}
		if n > 0 && isTimeoutErr(err) {
			// Progress inside the window: keep pushing the remainder.
			continue
		}
		return total, err
	}
}

// isTimeoutErr reports whether err is a network timeout.
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// CloseWrite forwards a write half-close when the underlying connection
// supports it. Without this forwarder the wrapper would hide CloseWrite from
// the tunnel copy loop and a half-closed peer would never see EOF.
func (c *deadlineConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead forwards a read half-close when the underlying connection supports
// it.
func (c *deadlineConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// activityClock records when a set of connections last carried any data, and
// whether the watchdog has already condemned the pair. The expired flag exists
// because progress-aware writes re-arm their own deadlines: without it, a
// write making progress could silently override the watchdog's expiry and keep
// a condemned tunnel alive.
type activityClock struct {
	last    atomic.Int64
	expired atomic.Bool
}

func newActivityClock() *activityClock {
	c := &activityClock{}
	c.mark()
	return c
}

func (c *activityClock) mark() {
	c.last.Store(time.Now().UnixNano())
}

func (c *activityClock) idleFor() time.Duration {
	return time.Since(time.Unix(0, c.last.Load()))
}

// activityConn marks a shared activity clock after every successful read or
// write, so an idle watchdog can tell a quiet connection from a busy one.
//
// window, when positive, makes Write progress-aware: each window must move at
// least one byte or the write fails as timed out. Marking the clock only after
// a whole Write returned — the previous behavior — misclassified a large
// transfer to a slow receiver as idle, because one multi-second Write never
// updated the clock while it steadily drained.
type activityConn struct {
	net.Conn
	clock  *activityClock
	window time.Duration
}

func (c *activityConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.clock.mark()
	}
	return n, err
}

func (c *activityConn) Write(b []byte) (int, error) {
	if c.window <= 0 {
		n, err := c.Conn.Write(b)
		if n > 0 {
			c.clock.mark()
		}
		return n, err
	}
	total := 0
	for {
		if err := c.Conn.SetWriteDeadline(time.Now().Add(c.window)); err != nil {
			slog.Debug("failed to arm tunnel write window", "error", err)
		}
		n, err := c.Conn.Write(b[total:])
		if n > 0 {
			c.clock.mark()
		}
		total += n
		if err == nil {
			// Leave no stale deadline behind for the next unbounded read/write.
			if clearErr := c.Conn.SetWriteDeadline(time.Time{}); clearErr != nil {
				slog.Debug("failed to clear tunnel write window", "error", clearErr)
			}
			return total, nil
		}
		if n > 0 && isTimeoutErr(err) && !c.clock.expired.Load() {
			// Progress inside the window and the watchdog has not condemned
			// the pair: keep pushing the remainder.
			continue
		}
		return total, err
	}
}

// CloseWrite forwards a write half-close so the tunnel copy loop can still
// signal EOF through this wrapper.
func (c *activityConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead forwards a read half-close.
func (c *activityConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// idleCheckInterval derives the watchdog tick for a configured idle timeout.
func idleCheckInterval(idle time.Duration) time.Duration {
	interval := idle / idleCheckDivisor
	if interval < minIdleCheckInterval {
		interval = minIdleCheckInterval
	}
	if interval > maxIdleCheckInterval {
		interval = maxIdleCheckInterval
	}
	return interval
}
