package accesslog

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errWriterFull = errors.New("no space left on device")

// failingWriter fails every write, standing in for a full disk or a revoked
// permission on the access log file.
type failingWriter struct{ closed bool }

func (w *failingWriter) Write([]byte) (int, error) { return 0, errWriterFull }

func (w *failingWriter) Close() error {
	w.closed = true
	return nil
}

func sampleEntry() Entry {
	return Entry{
		Timestamp:  time.Now(),
		ClientIP:   "192.0.2.10",
		Method:     "CONNECT",
		Host:       "example.com:443",
		Protocol:   "HTTP/1.1",
		StatusCode: 200,
		BytesSent:  1234,
		UserAgent:  "bifrost-test",
	}
}

// TestJSONLogger_CountsWriteFailures guards the reason the proxy may drop the
// error from Log: the logger has to notice failures itself. Callers log from a
// deferred block on every request and cannot act per entry, so if the logger
// stayed silent a full disk would stop the audit trail with no trace.
func TestJSONLogger_CountsWriteFailures(t *testing.T) {
	w := &failingWriter{}
	l := NewJSONLogger(w)

	assert.Zero(t, l.WriteFailureCount(), "a fresh logger has no failures")

	for i := 1; i <= 3; i++ {
		err := l.Log(sampleEntry())
		require.ErrorIs(t, err, errWriterFull,
			"Log must still return the error for callers that can use it")
		assert.Equal(t, int64(i), l.WriteFailureCount())
	}
}

// TestApacheLogger_CountsWriteFailures is the same guard for the Apache format.
func TestApacheLogger_CountsWriteFailures(t *testing.T) {
	w := &failingWriter{}
	l := NewApacheLogger(w)

	assert.Zero(t, l.WriteFailureCount())

	require.ErrorIs(t, l.Log(sampleEntry()), errWriterFull)
	assert.Equal(t, int64(1), l.WriteFailureCount())

	require.ErrorIs(t, l.Log(sampleEntry()), errWriterFull)
	assert.Equal(t, int64(2), l.WriteFailureCount(),
		"every dropped entry must be counted, not just the first")
}

// TestLoggers_SuccessfulWritesAreNotCounted asserts the counter tracks failures
// only, so a non-zero value is always actionable.
func TestLoggers_SuccessfulWritesAreNotCounted(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		w := &countingWriteCloser{}
		l := NewJSONLogger(w)
		require.NoError(t, l.Log(sampleEntry()))
		assert.Zero(t, l.WriteFailureCount())
		assert.Positive(t, w.bytes)
	})

	t.Run("apache", func(t *testing.T) {
		w := &countingWriteCloser{}
		l := NewApacheLogger(w)
		require.NoError(t, l.Log(sampleEntry()))
		assert.Zero(t, l.WriteFailureCount())
		assert.Positive(t, w.bytes)
	})
}

// countingWriteCloser accepts every write and records how much it received.
type countingWriteCloser struct{ bytes int }

func (w *countingWriteCloser) Write(p []byte) (int, error) {
	w.bytes += len(p)
	return len(p), nil
}

func (w *countingWriteCloser) Close() error { return nil }

// TestJSONLogger_MarshalFailureIsCounted covers the other failure path: an
// entry that cannot be encoded is a dropped log line just as much as one that
// cannot be written.
func TestJSONLogger_MarshalFailureIsCounted(t *testing.T) {
	l := NewJSONLogger(&countingWriteCloser{})
	l.marshaler = func(any) ([]byte, error) { return nil, errWriterFull }

	err := l.Log(sampleEntry())
	require.ErrorIs(t, err, errWriterFull)
	assert.Equal(t, int64(1), l.WriteFailureCount())
}
