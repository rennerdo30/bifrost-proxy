package vpn

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// bufConn is a net.Conn whose Write calls are appended (unlike the shared
// mockConn, which overwrites), so we can assert the exact upstream byte stream
// produced by reassembly.
type bufConn struct {
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *bufConn) Read(b []byte) (int, error) { return 0, nil }
func (c *bufConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.Write(b)
}
func (c *bufConn) Close() error                       { return nil }
func (c *bufConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *bufConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *bufConn) SetDeadline(t time.Time) error      { return nil }
func (c *bufConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *bufConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *bufConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written.Bytes()...)
}

// collect feeds a sequence of (seq, data) segments to the reassembler and
// concatenates everything it emits, returning the assembled stream.
func collect(r *TCPReassembler, segs []struct {
	seq  uint32
	data string
}) []byte {
	var out []byte
	for _, s := range segs {
		out = append(out, r.Process(s.seq, []byte(s.data))...)
	}
	return out
}

func TestReassembler_InOrder(t *testing.T) {
	r := NewTCPReassembler(0, 0)
	r.Reset(1000)

	out := collect(r, []struct {
		seq  uint32
		data string
	}{
		{1000, "hello "},
		{1006, "world"},
		{1011, "!"},
	})

	if string(out) != "hello world!" {
		t.Fatalf("in-order: got %q want %q", out, "hello world!")
	}
	if b, segs, _, _ := r.Stats(); b != 0 || segs != 0 {
		t.Fatalf("buffer should be empty after in-order delivery, got bytes=%d segs=%d", b, segs)
	}
	if next, _ := r.NextSeq(); next != 1012 {
		t.Fatalf("nextSeq = %d, want 1012", next)
	}
}

func TestReassembler_FirstSegmentSeedsSeq(t *testing.T) {
	r := NewTCPReassembler(0, 0)
	// No Reset: first segment should seed nextSeq.
	out := r.Process(5000, []byte("abc"))
	if string(out) != "abc" {
		t.Fatalf("got %q want abc", out)
	}
	out = append([]byte(nil), r.Process(5003, []byte("def"))...)
	if string(out) != "def" {
		t.Fatalf("got %q want def", out)
	}
}

func TestReassembler_OutOfOrder(t *testing.T) {
	r := NewTCPReassembler(0, 0)
	r.Reset(1000)

	// Future segment arrives first; nothing should be emitted yet.
	if out := r.Process(1006, []byte("world")); len(out) != 0 {
		t.Fatalf("out-of-order future segment should not emit, got %q", out)
	}
	if b, segs, _, _ := r.Stats(); b != 5 || segs != 1 {
		t.Fatalf("expected 5 buffered bytes in 1 seg, got bytes=%d segs=%d", b, segs)
	}

	// Another future segment beyond the gap.
	if out := r.Process(1011, []byte("!")); len(out) != 0 {
		t.Fatalf("second future segment should not emit, got %q", out)
	}

	// Now the gap-filling segment arrives: everything flushes in order.
	out := r.Process(1000, []byte("hello "))
	if string(out) != "hello world!" {
		t.Fatalf("gap fill: got %q want %q", out, "hello world!")
	}
	if b, segs, _, _ := r.Stats(); b != 0 || segs != 0 {
		t.Fatalf("buffer should be drained, got bytes=%d segs=%d", b, segs)
	}
	if next, _ := r.NextSeq(); next != 1012 {
		t.Fatalf("nextSeq = %d, want 1012", next)
	}
}

func TestReassembler_OutOfOrderInterleaved(t *testing.T) {
	r := NewTCPReassembler(0, 0)
	r.Reset(0)

	// Segments: [0:4]=AAAA [8:12]=CCCC [4:8]=BBBB then [12:16]=DDDD
	var out []byte
	out = append(out, r.Process(0, []byte("AAAA"))...) // in order -> "AAAA"
	out = append(out, r.Process(8, []byte("CCCC"))...) // gap, buffer
	out = append(out, r.Process(4, []byte("BBBB"))...) // fills gap -> "BBBBCCCC"
	out = append(out, r.Process(12, []byte("DDDD"))...)

	if string(out) != "AAAABBBBCCCCDDDD" {
		t.Fatalf("interleaved: got %q want AAAABBBBCCCCDDDD", out)
	}
}

func TestReassembler_DuplicateExact(t *testing.T) {
	r := NewTCPReassembler(0, 0)
	r.Reset(100)

	out := r.Process(100, []byte("data"))
	if string(out) != "data" {
		t.Fatalf("first: got %q want data", out)
	}
	// Exact duplicate of already-consumed data: emit nothing.
	if dup := r.Process(100, []byte("data")); len(dup) != 0 {
		t.Fatalf("duplicate should emit nothing, got %q", dup)
	}
	if next, _ := r.NextSeq(); next != 104 {
		t.Fatalf("nextSeq = %d, want 104", next)
	}
}

func TestReassembler_PartialOverlapWithConsumed(t *testing.T) {
	r := NewTCPReassembler(0, 0)
	r.Reset(0)

	out := r.Process(0, []byte("ABCDE")) // consumes [0:5]
	if string(out) != "ABCDE" {
		t.Fatalf("got %q want ABCDE", out)
	}
	// Retransmit overlapping [2:7] = "CDEFG"; only "FG" is new.
	out = r.Process(2, []byte("CDEFG"))
	if string(out) != "FG" {
		t.Fatalf("partial overlap: got %q want FG", out)
	}
	if next, _ := r.NextSeq(); next != 7 {
		t.Fatalf("nextSeq = %d, want 7", next)
	}
}

func TestReassembler_OverlappingBufferedSegments(t *testing.T) {
	r := NewTCPReassembler(0, 0)
	r.Reset(0)

	// Buffer [4:8]="EFGH" (gap at 0:4).
	r.Process(4, []byte("EFGH"))
	// Buffer an overlapping segment [2:10]="CDEFGHIJ". Overlap with the buffered
	// segment must be trimmed so no byte is duplicated on flush.
	r.Process(2, []byte("CDEFGHIJ"))
	// Fill the head gap [0:2]="AB".
	out := r.Process(0, []byte("AB"))

	if string(out) != "ABCDEFGHIJ" {
		t.Fatalf("overlapping buffered: got %q want ABCDEFGHIJ", out)
	}
	if next, _ := r.NextSeq(); next != 10 {
		t.Fatalf("nextSeq = %d, want 10", next)
	}
}

func TestReassembler_DuplicateBufferedSegment(t *testing.T) {
	r := NewTCPReassembler(0, 0)
	r.Reset(0)

	r.Process(4, []byte("EFGH"))
	// Exact duplicate of buffered segment: should not grow the buffer.
	r.Process(4, []byte("EFGH"))
	if _, segs, _, _ := r.Stats(); segs != 1 {
		t.Fatalf("duplicate buffered segment should not add a segment, segs=%d", segs)
	}
	out := r.Process(0, []byte("ABCD"))
	if string(out) != "ABCDEFGH" {
		t.Fatalf("got %q want ABCDEFGH", out)
	}
}

func TestReassembler_BoundsBytesDropFuture(t *testing.T) {
	// Tiny byte budget: only a few buffered bytes allowed.
	r := NewTCPReassembler(8, 100)
	r.Reset(0)

	// Gap at [0:4]; buffer [4:8] (4 bytes) and [8:12] (4 bytes) = 8 bytes, at cap.
	r.Process(4, []byte("EFGH"))
	r.Process(8, []byte("IJKL"))
	if b, _, dseg, _ := r.Stats(); b != 8 || dseg != 0 {
		t.Fatalf("expected 8 buffered, 0 dropped; got bytes=%d dropped=%d", b, dseg)
	}
	// Next future segment must be dropped (would exceed 8-byte cap).
	r.Process(12, []byte("MNOP"))
	if _, _, dseg, dby := r.Stats(); dseg != 1 || dby != 4 {
		t.Fatalf("expected 1 dropped seg / 4 bytes, got segs=%d bytes=%d", dseg, dby)
	}

	// Fill the gap: only the bytes we actually buffered come through. The dropped
	// segment's bytes are NOT emitted (sender must retransmit).
	out := r.Process(0, []byte("ABCD"))
	if string(out) != "ABCDEFGHIJKL" {
		t.Fatalf("bounded flush: got %q want ABCDEFGHIJKL", out)
	}
}

func TestReassembler_BoundsSegmentCountDropFuture(t *testing.T) {
	// Allow many bytes but only 2 buffered segments.
	r := NewTCPReassembler(1<<20, 2)
	r.Reset(0)

	r.Process(4, []byte("E"))
	r.Process(6, []byte("G"))
	// Third distinct future segment exceeds the 2-segment cap -> dropped.
	r.Process(8, []byte("I"))
	if _, segs, dseg, _ := r.Stats(); segs != 2 || dseg != 1 {
		t.Fatalf("expected 2 segs, 1 dropped; got segs=%d dropped=%d", segs, dseg)
	}
}

func TestReassembler_DroppedSegmentRetransmitFillsStream(t *testing.T) {
	// Verify the documented recovery model: a future segment dropped due to
	// bounds is later retransmitted and then accepted once there is room.
	r := NewTCPReassembler(4, 100)
	r.Reset(0)

	r.Process(4, []byte("EFGH")) // buffers, fills the 4-byte budget
	// This future segment is dropped (budget full).
	if dropped := r.Process(8, []byte("IJKL")); len(dropped) != 0 {
		t.Fatalf("expected no emit, got %q", dropped)
	}
	// Fill the head gap; [4:8] flushes, freeing the buffer.
	out := r.Process(0, []byte("ABCD"))
	if string(out) != "ABCDEFGH" {
		t.Fatalf("got %q want ABCDEFGH", out)
	}
	// Sender retransmits [8:12]; now it is in order and accepted.
	out = r.Process(8, []byte("IJKL"))
	if string(out) != "IJKL" {
		t.Fatalf("retransmit: got %q want IJKL", out)
	}
}

func TestReassembler_EmptyPayloadNoOp(t *testing.T) {
	r := NewTCPReassembler(0, 0)
	r.Reset(10)
	if out := r.Process(10, nil); out != nil {
		t.Fatalf("empty payload should emit nothing, got %q", out)
	}
	if out := r.Process(10, []byte{}); len(out) != 0 {
		t.Fatalf("empty payload should emit nothing, got %q", out)
	}
}

func TestReassembler_SequenceWraparound(t *testing.T) {
	// Start near the 32-bit boundary so sequence numbers wrap during the stream.
	start := uint32(0xFFFFFFFE)
	r := NewTCPReassembler(0, 0)
	r.Reset(start)

	// Buffer the wrapped future segment first: seq = start+2 = 0x00000000.
	if out := r.Process(start+2, []byte("CD")); len(out) != 0 {
		t.Fatalf("future wrapped segment should buffer, got %q", out)
	}
	// Now the in-order segment at the boundary [start:start+2] = "AB".
	out := r.Process(start, []byte("AB"))
	if string(out) != "ABCD" {
		t.Fatalf("wraparound: got %q want ABCD", out)
	}
	if next, _ := r.NextSeq(); next != start+4 {
		t.Fatalf("nextSeq = %d, want %d", next, start+4)
	}
}

func TestReassembler_LargeShuffledStreamReassemblesExactly(t *testing.T) {
	// Build a deterministic payload and feed fixed-size segments in a shuffled
	// order; the reassembled output must equal the original byte-for-byte.
	const total = 64 * 1024
	const segSize = 200
	orig := make([]byte, total)
	for i := range orig {
		orig[i] = byte(i*31 + 7)
	}

	r := NewTCPReassembler(0, 0)
	r.Reset(0)

	// Segment offsets.
	var offsets []int
	for off := 0; off < total; off += segSize {
		offsets = append(offsets, off)
	}
	// Deterministic shuffle (no math/rand dependency / nondeterminism).
	for i := range offsets {
		j := (i*7 + 3) % len(offsets)
		offsets[i], offsets[j] = offsets[j], offsets[i]
	}

	var assembled []byte
	for _, off := range offsets {
		end := off + segSize
		if end > total {
			end = total
		}
		assembled = append(assembled, r.Process(uint32(off), orig[off:end])...)
	}

	if !bytes.Equal(assembled, orig) {
		t.Fatalf("shuffled reassembly mismatch: len got=%d want=%d", len(assembled), len(orig))
	}
	if b, segs, _, _ := r.Stats(); b != 0 || segs != 0 {
		t.Fatalf("buffer should be empty after full reassembly, bytes=%d segs=%d", b, segs)
	}
}

// makeReasmConn builds a tracked TCP connection wired with a reassembler seeded
// at the given clientNext, using a buffering upstream conn.
func makeReasmConn(clientNext uint32) (*TrackedConnection, *bufConn) {
	bc := &bufConn{}
	conn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    netip.MustParseAddr("192.168.1.100"),
			DstIP:    netip.MustParseAddr("93.184.216.34"),
			SrcPort:  12345,
			DstPort:  443,
			Protocol: ProtocolTCP,
		},
		ProxyConn: bc,
		TCP: &TCPState{
			ClientNext: clientNext,
			ServerNext: 1,
			Reasm:      NewTCPReassembler(0, 0),
		},
	}
	conn.TCP.Reasm.Reset(clientNext)
	return conn, bc
}

// TestForwardOnConnectionReassembles verifies forwardOnConnection only forwards
// in-order data to the upstream conn, buffering out-of-order client segments and
// flushing them once the gap is filled.
func TestForwardOnConnectionReassembles(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)
	m.connTracker = NewConnTracker()
	defer m.connTracker.Close()
	m.tun = &mockTUNDevice{name: "test0", mtu: 1400}

	const isn = uint32(1000)
	conn, bc := makeReasmConn(isn)
	m.connTracker.Add(conn)

	// Out-of-order: send [1006:1011]="world" first, then [1000:1006]="hello ".
	m.forwardOnConnection(conn, &IPPacket{SeqNum: 1006, Payload: []byte("world"), TCPFlags: TCPFlagACK | TCPFlagPSH})
	require.Empty(t, bc.Bytes(), "future segment must not be forwarded before the gap is filled")

	m.forwardOnConnection(conn, &IPPacket{SeqNum: 1000, Payload: []byte("hello "), TCPFlags: TCPFlagACK | TCPFlagPSH})
	require.Equal(t, "hello world", string(bc.Bytes()), "upstream stream must be in order after gap fill")

	// ACK position must reflect the cumulative in-order sequence, not the highest seen.
	conn.TCP.mu.Lock()
	clientNext := conn.TCP.ClientNext
	conn.TCP.mu.Unlock()
	require.Equal(t, uint32(1011), clientNext)
}

// TestForwardOnConnectionDropsDuplicate verifies a duplicate client segment is
// not forwarded twice upstream.
func TestForwardOnConnectionDropsDuplicate(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)
	m.connTracker = NewConnTracker()
	defer m.connTracker.Close()
	m.tun = &mockTUNDevice{name: "test0", mtu: 1400}

	conn, bc := makeReasmConn(2000)
	m.connTracker.Add(conn)

	m.forwardOnConnection(conn, &IPPacket{SeqNum: 2000, Payload: []byte("abc"), TCPFlags: TCPFlagACK | TCPFlagPSH})
	m.forwardOnConnection(conn, &IPPacket{SeqNum: 2000, Payload: []byte("abc"), TCPFlags: TCPFlagACK | TCPFlagPSH})

	require.Equal(t, "abc", string(bc.Bytes()), "duplicate segment must not be forwarded twice")
}

func TestReassembler_OutputOwnership(t *testing.T) {
	// The returned slice must be caller-owned; mutating it must not corrupt
	// internal state of subsequent reads.
	r := NewTCPReassembler(0, 0)
	r.Reset(0)
	out := r.Process(0, []byte("ABCD"))
	out[0] = 'X'
	out2 := r.Process(4, []byte("EFGH"))
	if string(out2) != "EFGH" {
		t.Fatalf("mutating returned slice affected later output: %q", out2)
	}
}
