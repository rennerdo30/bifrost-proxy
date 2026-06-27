package vpn

import "sync"

// Default bounds for the out-of-order reassembly buffer. These keep memory usage
// per connection bounded even under adversarial reordering or loss.
const (
	// DefaultReasmMaxBytes is the maximum number of bytes that may be buffered
	// out-of-order for a single connection before further early segments are
	// dropped. 256 KiB is comfortably above a typical TCP receive window for the
	// userspace shim while still being a hard cap against memory blowup.
	DefaultReasmMaxBytes = 256 * 1024
	// DefaultReasmMaxSegments is the maximum number of distinct out-of-order
	// segments that may be buffered for a single connection. This bounds the
	// per-connection overhead independently of segment size (e.g. many tiny
	// segments) and limits worst-case CPU during insertion/merge.
	DefaultReasmMaxSegments = 1024
)

// reasmSegment is a buffered TCP segment that could not yet be delivered because
// it sits ahead of the next expected sequence number. seq is the sequence number
// of the first byte in data.
type reasmSegment struct {
	seq  uint32
	data []byte
}

// TCPReassembler reorders TCP segments arriving from the client (TUN) side into a
// correct, gap-free byte stream before they are forwarded to the upstream proxy
// connection.
//
// It is NOT a full TCP stack: it does not generate retransmissions, manage a
// receive window, or implement SACK/congestion control. It solves one specific
// correctness problem from the previous implementation, which wrote client
// payloads straight to the upstream socket assuming strict in-order delivery:
//
//   - Out-of-order segments are buffered (keyed by sequence number) until the
//     intervening gap is filled, then flushed in order.
//   - Fully duplicate / already-consumed segments are dropped.
//   - Partially overlapping segments are trimmed so each byte is delivered once.
//   - The buffer is bounded by both total bytes and segment count; once the cap
//     is reached, further early (out-of-order) segments are dropped rather than
//     growing memory without limit. Dropped segments rely on the sender's normal
//     TCP retransmission (we never ACK data we have not accepted) to be resent
//     later, at which point the gap can be filled.
//
// All methods are safe for concurrent use.
type TCPReassembler struct {
	mu sync.Mutex

	// nextSeq is the sequence number of the next byte we expect to deliver
	// in order. Everything before this has already been handed upstream.
	nextSeq uint32
	// initialized records whether nextSeq has been seeded from the first
	// segment (or an explicit Reset). Until then we adopt the first segment's
	// sequence number as the stream origin.
	initialized bool

	// segments holds buffered out-of-order segments sorted ascending by seq.
	segments []reasmSegment
	// bufferedBytes is the total length of data held in segments.
	bufferedBytes int

	maxBytes    int
	maxSegments int

	droppedSegments uint64
	droppedBytes    uint64
}

// NewTCPReassembler creates a reassembler with the given bounds. Non-positive
// bounds fall back to the package defaults.
func NewTCPReassembler(maxBytes, maxSegments int) *TCPReassembler {
	if maxBytes <= 0 {
		maxBytes = DefaultReasmMaxBytes
	}
	if maxSegments <= 0 {
		maxSegments = DefaultReasmMaxSegments
	}
	return &TCPReassembler{
		maxBytes:    maxBytes,
		maxSegments: maxSegments,
	}
}

// Reset seeds the reassembler with the initial sequence number of the stream
// (typically clientISN+1 after the SYN). Any buffered data is discarded.
func (r *TCPReassembler) Reset(nextSeq uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextSeq = nextSeq
	r.initialized = true
	r.segments = nil
	r.bufferedBytes = 0
}

// NextSeq returns the sequence number of the next in-order byte expected.
func (r *TCPReassembler) NextSeq() (seq uint32, initialized bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nextSeq, r.initialized
}

// Stats returns reassembly bookkeeping useful for tests and diagnostics.
func (r *TCPReassembler) Stats() (bufferedBytes, bufferedSegments int, droppedSegments, droppedBytes uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bufferedBytes, len(r.segments), r.droppedSegments, r.droppedBytes
}

// Process accepts a TCP segment with sequence number seq carrying payload, and
// returns the in-order bytes (if any) that are now ready to be delivered
// upstream. The returned slice is freshly allocated and owned by the caller.
//
// Behaviour:
//   - The first segment seen (when uninitialized) seeds nextSeq to its seq.
//   - In-order data is returned immediately, then any contiguous buffered
//     segments are appended.
//   - Out-of-order (future) data is buffered, subject to the configured bounds.
//   - Already-consumed (past) bytes are trimmed/dropped.
//   - Duplicate segments produce no output.
//
// A nil/empty payload (e.g. a pure ACK) yields no output.
func (r *TCPReassembler) Process(seq uint32, payload []byte) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.initialized {
		r.nextSeq = seq
		r.initialized = true
	}

	if len(payload) == 0 {
		return nil
	}

	seq, payload = r.trimConsumed(seq, payload)
	if len(payload) == 0 {
		// Entirely old/duplicate data.
		return nil
	}

	if seq == r.nextSeq {
		// In-order: deliver immediately, advancing past any data we already
		// hold so we never emit a byte twice.
		out := append([]byte(nil), payload...)
		r.nextSeq += uint32(len(payload)) //nolint:gosec // G115: payload length bounded by MTU/window
		out = r.drainContiguousLocked(out)
		return out
	}

	if seqLess(seq, r.nextSeq) {
		// Should not happen after trimConsumed, but guard defensively.
		return nil
	}

	// Future data: buffer it for later, within bounds.
	r.bufferLocked(seq, payload)
	return nil
}

// trimConsumed removes any leading bytes of the segment that are at or before
// nextSeq (already delivered). Returns the adjusted seq and payload.
func (r *TCPReassembler) trimConsumed(seq uint32, payload []byte) (uint32, []byte) {
	if seqLess(seq, r.nextSeq) {
		// Some or all of this segment is in the past.
		offset := r.nextSeq - seq
		if uint32(len(payload)) <= offset { //nolint:gosec // G115: len bounded by MTU
			// Entirely consumed already.
			return r.nextSeq, nil
		}
		return r.nextSeq, payload[offset:]
	}
	return seq, payload
}

// drainContiguousLocked appends any buffered segments that are now contiguous
// with nextSeq onto out, advancing nextSeq accordingly. Must hold r.mu.
func (r *TCPReassembler) drainContiguousLocked(out []byte) []byte {
	for len(r.segments) > 0 {
		seg := r.segments[0]
		if seqLess(r.nextSeq, seg.seq) {
			// Still a gap before the first buffered segment.
			break
		}
		// seg.seq <= nextSeq: trim any overlap with what we've delivered.
		data := seg.data
		if seqLess(seg.seq, r.nextSeq) {
			offset := r.nextSeq - seg.seq
			if uint32(len(data)) <= offset { //nolint:gosec // G115: len bounded
				// Fully overlapped; drop it.
				r.removeFirstLocked()
				continue
			}
			data = data[offset:]
		}
		out = append(out, data...)
		r.nextSeq += uint32(len(data)) //nolint:gosec // G115: len bounded
		r.removeFirstLocked()
	}
	return out
}

// removeFirstLocked removes segments[0] and updates accounting. Must hold r.mu.
func (r *TCPReassembler) removeFirstLocked() {
	r.bufferedBytes -= len(r.segments[0].data)
	r.segments = r.segments[1:]
	// Reclaim the backing array once fully drained to avoid retaining memory.
	if len(r.segments) == 0 {
		r.segments = nil
	}
}

// bufferLocked inserts a future segment into the sorted buffer, trimming
// overlaps with neighbouring segments and enforcing the size bounds. Must hold
// r.mu.
func (r *TCPReassembler) bufferLocked(seq uint32, payload []byte) {
	// Find insertion index (first segment with seq strictly greater).
	idx := r.insertIndexLocked(seq)

	// Trim against the previous segment to avoid storing overlapping bytes.
	if idx > 0 {
		prev := r.segments[idx-1]
		prevEnd := prev.seq + uint32(len(prev.data)) //nolint:gosec // G115: len bounded
		if !seqLess(seq, prevEnd) {
			// seq >= prevEnd: no overlap with prev.
		} else {
			// Overlap: advance seq past prev's coverage.
			overlap := prevEnd - seq
			if uint32(len(payload)) <= overlap { //nolint:gosec // G115: len bounded
				return // entirely covered by prev
			}
			seq += overlap
			payload = payload[overlap:]
			idx = r.insertIndexLocked(seq)
		}
	}

	// Trim against following segments so we never duplicate bytes they hold.
	for idx < len(r.segments) {
		next := r.segments[idx]
		if seqLess(seq, next.seq) {
			// There is a portion of payload strictly before next; keep only
			// up to next.seq for this insertion, deferring the rest.
			head := next.seq - seq
			if uint32(len(payload)) <= head { //nolint:gosec // G115: len bounded
				break // payload entirely before next; insert whole
			}
			r.storeSegmentLocked(idx, seq, payload[:head])
			// Continue with the remainder after next's start.
			rest := payload[head:]
			r.bufferLockedRemainder(next.seq, rest)
			return
		}
		// seq >= next.seq: skip the part covered by next.
		nextEnd := next.seq + uint32(len(next.data)) //nolint:gosec // G115: len bounded
		if seqLess(seq, nextEnd) {
			covered := nextEnd - seq
			if uint32(len(payload)) <= covered { //nolint:gosec // G115: len bounded
				return // fully covered by next
			}
			seq += covered
			payload = payload[covered:]
		}
		idx++
	}

	r.storeSegmentLocked(idx, seq, payload)
}

// bufferLockedRemainder re-buffers the tail of a split segment. It is a thin
// wrapper that re-runs the insertion logic for the remainder.
func (r *TCPReassembler) bufferLockedRemainder(seq uint32, payload []byte) {
	if len(payload) == 0 {
		return
	}
	r.bufferLocked(seq, payload)
}

// insertIndexLocked returns the index at which a segment starting at seq should
// be inserted to keep r.segments sorted ascending. Must hold r.mu.
func (r *TCPReassembler) insertIndexLocked(seq uint32) int {
	// Linear scan; segment counts are bounded by maxSegments.
	for i := range r.segments {
		if seqLess(seq, r.segments[i].seq) {
			return i
		}
	}
	return len(r.segments)
}

// storeSegmentLocked inserts a copy of payload at index idx, enforcing bounds.
// Must hold r.mu.
func (r *TCPReassembler) storeSegmentLocked(idx int, seq uint32, payload []byte) {
	if len(payload) == 0 {
		return
	}

	// Enforce bounds: if adding this segment would exceed either cap, drop it.
	// We never ACK unaccepted data, so the sender will retransmit later.
	if len(r.segments) >= r.maxSegments || r.bufferedBytes+len(payload) > r.maxBytes {
		r.droppedSegments++
		r.droppedBytes += uint64(len(payload))
		return
	}

	seg := reasmSegment{seq: seq, data: append([]byte(nil), payload...)}
	r.segments = append(r.segments, reasmSegment{})
	copy(r.segments[idx+1:], r.segments[idx:])
	r.segments[idx] = seg
	r.bufferedBytes += len(seg.data)
}

// seqLess reports whether sequence number a is strictly before b using
// wraparound-safe 32-bit serial number arithmetic (RFC 1982).
func seqLess(a, b uint32) bool {
	return int32(a-b) < 0 //nolint:gosec // G115: intentional wraparound for TCP seq comparison
}
