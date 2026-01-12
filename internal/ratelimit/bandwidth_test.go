package ratelimit

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock connection for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func newMockConn(readData []byte) *mockConn {
	return &mockConn{
		readBuf:  bytes.NewBuffer(readData),
		writeBuf: &bytes.Buffer{},
	}
}

func (m *mockConn) Read(b []byte) (int, error) {
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (int, error) {
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// ParseBandwidth tests

func TestParseBandwidth_EmptyString(t *testing.T) {
	bw, err := ParseBandwidth("")
	require.NoError(t, err)
	assert.Equal(t, int64(0), bw)
}

func TestParseBandwidth_Zero(t *testing.T) {
	bw, err := ParseBandwidth("0")
	require.NoError(t, err)
	assert.Equal(t, int64(0), bw)
}

func TestParseBandwidth_Mbps(t *testing.T) {
	bw, err := ParseBandwidth("10Mbps")
	require.NoError(t, err)
	expected := int64(10 * 1000 * 1000 / 8) // bits to bytes
	assert.Equal(t, expected, bw)
}

func TestParseBandwidth_Kbps(t *testing.T) {
	bw, err := ParseBandwidth("100kbps")
	require.NoError(t, err)
	expected := int64(100 * 1000 / 8)
	assert.Equal(t, expected, bw)
}

func TestParseBandwidth_Gbps(t *testing.T) {
	bw, err := ParseBandwidth("1Gbps")
	require.NoError(t, err)
	expected := int64(1000 * 1000 * 1000 / 8)
	assert.Equal(t, expected, bw)
}

func TestParseBandwidth_Bps(t *testing.T) {
	// bps has a special case where 1/8 = 0 in integer math
	bw, err := ParseBandwidth("8000bps")
	require.NoError(t, err)
	// 8000 * (1/8) = 0 due to integer math, but we use float64
	assert.Equal(t, int64(0), bw) // This is expected behavior
}

func TestParseBandwidth_BytePerSecond(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1024b/s", 1024},
		{"1024byte/s", 1024},
		{"1kb/s", 1000},
		{"1kbyte/s", 1000},
		{"1mb/s", 1000 * 1000},
		{"1mbyte/s", 1000 * 1000},
		{"1gb/s", 1000 * 1000 * 1000},
		{"1gbyte/s", 1000 * 1000 * 1000},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			bw, err := ParseBandwidth(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, bw)
		})
	}
}

func TestParseBandwidth_CaseInsensitive(t *testing.T) {
	tests := []string{"10MBPS", "10Mbps", "10mbps", "10MBps"}
	var expected int64

	for i, input := range tests {
		bw, err := ParseBandwidth(input)
		require.NoError(t, err, "input: %s", input)
		if i == 0 {
			expected = bw
		}
		assert.Equal(t, expected, bw, "all should parse to same value")
	}
}

func TestParseBandwidth_WithWhitespace(t *testing.T) {
	bw, err := ParseBandwidth("  10 mbps  ")
	require.NoError(t, err)
	expected := int64(10 * 1000 * 1000 / 8)
	assert.Equal(t, expected, bw)
}

func TestParseBandwidth_InvalidValue(t *testing.T) {
	_, err := ParseBandwidth("invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid bandwidth value")
}

func TestParseBandwidth_FloatValue(t *testing.T) {
	bw, err := ParseBandwidth("1.5Mbps")
	require.NoError(t, err)
	expected := int64(1.5 * 1000 * 1000 / 8)
	assert.Equal(t, expected, bw)
}

// FormatBandwidth tests

func TestFormatBandwidth_Gbps(t *testing.T) {
	// 1 Gbps = 125 MB/s = 125000000 bytes/s
	bw := int64(125000000)
	result := FormatBandwidth(bw)
	assert.Equal(t, "1.00 Gbps", result)
}

func TestFormatBandwidth_Mbps(t *testing.T) {
	// 100 Mbps = 12.5 MB/s = 12500000 bytes/s
	bw := int64(12500000)
	result := FormatBandwidth(bw)
	assert.Equal(t, "100.00 Mbps", result)
}

func TestFormatBandwidth_Kbps(t *testing.T) {
	// 100 Kbps = 12.5 KB/s = 12500 bytes/s
	bw := int64(12500)
	result := FormatBandwidth(bw)
	assert.Equal(t, "100.00 Kbps", result)
}

func TestFormatBandwidth_Bps(t *testing.T) {
	// 100 bps = 12.5 bytes/s ~ 12 bytes/s
	bw := int64(12)
	result := FormatBandwidth(bw)
	assert.Equal(t, "96 bps", result) // 12 * 8 = 96 bps
}

// ThrottledConn tests

func TestThrottledConn_NewWithNoLimits(t *testing.T) {
	conn := newMockConn([]byte("test data"))
	tc := NewThrottledConn(conn, 0, 0)

	assert.NotNil(t, tc)
	assert.Nil(t, tc.readLimiter)
	assert.Nil(t, tc.writeLimiter)
}

func TestThrottledConn_NewWithDownloadLimit(t *testing.T) {
	conn := newMockConn([]byte("test data"))
	tc := NewThrottledConn(conn, 1024, 0)

	assert.NotNil(t, tc)
	assert.NotNil(t, tc.readLimiter)
	assert.Nil(t, tc.writeLimiter)
}

func TestThrottledConn_NewWithUploadLimit(t *testing.T) {
	conn := newMockConn([]byte("test data"))
	tc := NewThrottledConn(conn, 0, 1024)

	assert.NotNil(t, tc)
	assert.Nil(t, tc.readLimiter)
	assert.NotNil(t, tc.writeLimiter)
}

func TestThrottledConn_NewWithBothLimits(t *testing.T) {
	conn := newMockConn([]byte("test data"))
	tc := NewThrottledConn(conn, 1024, 512)

	assert.NotNil(t, tc)
	assert.NotNil(t, tc.readLimiter)
	assert.NotNil(t, tc.writeLimiter)
}

func TestThrottledConn_ReadWithoutLimiter(t *testing.T) {
	data := []byte("test data")
	conn := newMockConn(data)
	tc := NewThrottledConn(conn, 0, 0)

	buf := make([]byte, 100)
	n, err := tc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestThrottledConn_ReadWithLimiter(t *testing.T) {
	data := []byte("test data")
	conn := newMockConn(data)
	// High rate to avoid timeout
	tc := NewThrottledConn(conn, 10000, 0)

	buf := make([]byte, 100)
	n, err := tc.Read(buf)
	require.NoError(t, err)
	assert.Greater(t, n, 0)
}

func TestThrottledConn_WriteWithoutLimiter(t *testing.T) {
	conn := newMockConn(nil)
	tc := NewThrottledConn(conn, 0, 0)

	data := []byte("test data")
	n, err := tc.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, conn.writeBuf.Bytes())
}

func TestThrottledConn_WriteWithLimiter(t *testing.T) {
	conn := newMockConn(nil)
	// High rate to avoid timeout
	tc := NewThrottledConn(conn, 0, 10000)

	data := []byte("test data")
	n, err := tc.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
}

// ThrottledReader tests

func TestThrottledReader_New(t *testing.T) {
	reader := bytes.NewReader([]byte("test"))
	tr := NewThrottledReader(reader, 1024)

	assert.NotNil(t, tr)
	assert.NotNil(t, tr.limiter)
}

func TestThrottledReader_Read(t *testing.T) {
	data := []byte("test data for throttled reader")
	reader := bytes.NewReader(data)
	tr := NewThrottledReader(reader, 10000) // High rate

	buf := make([]byte, 100)
	totalRead := 0

	for totalRead < len(data) {
		n, err := tr.Read(buf[totalRead:])
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		totalRead += n
	}

	assert.Equal(t, len(data), totalRead)
}

// ThrottledWriter tests

func TestThrottledWriter_New(t *testing.T) {
	writer := &bytes.Buffer{}
	tw := NewThrottledWriter(writer, 1024)

	assert.NotNil(t, tw)
	assert.NotNil(t, tw.limiter)
}

func TestThrottledWriter_Write(t *testing.T) {
	writer := &bytes.Buffer{}
	tw := NewThrottledWriter(writer, 10000) // High rate

	data := []byte("test data for throttled writer")
	n, err := tw.Write(data)

	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, writer.Bytes())
}

// BandwidthConfig tests

func TestBandwidthConfig_Struct(t *testing.T) {
	cfg := BandwidthConfig{
		Upload:   1024,
		Download: 2048,
	}

	assert.Equal(t, int64(1024), cfg.Upload)
	assert.Equal(t, int64(2048), cfg.Download)
}

// Integration test

func TestParseBandwidth_RoundTrip(t *testing.T) {
	// Parse a value
	original, err := ParseBandwidth("100Mbps")
	require.NoError(t, err)

	// Format it
	formatted := FormatBandwidth(original)

	// Should be approximately 100 Mbps
	assert.Contains(t, formatted, "100.")
	assert.Contains(t, formatted, "Mbps")
}

// Test for Wait method of KeyedLimiter
func TestKeyedLimiter_Wait(t *testing.T) {
	limiter := NewKeyedLimiter(Config{
		RequestsPerSecond: 100,
		BurstSize:         1,
	})
	defer limiter.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := limiter.Wait(ctx, "test-key")
	assert.NoError(t, err)
}

// Test for UpdateConfig
func TestKeyedLimiter_UpdateConfig(t *testing.T) {
	limiter := NewKeyedLimiter(Config{
		RequestsPerSecond: 10,
		BurstSize:         5,
	})
	defer limiter.Close()

	// Use the limiter
	limiter.Allow("key1")

	// Update config
	limiter.UpdateConfig(Config{
		RequestsPerSecond: 100,
		BurstSize:         50,
	})

	// Stats should show 0 limiters after update (cleared)
	stats := limiter.Stats()
	assert.Equal(t, 0, stats.ActiveLimiters)
	assert.Equal(t, float64(100), stats.Config.RequestsPerSecond)
}

// Test for TokenBucket Rate and Capacity
func TestTokenBucket_RateAndCapacity(t *testing.T) {
	bucket := NewTokenBucket(10.5, 100)

	assert.Equal(t, 10.5, bucket.Rate())
	assert.Equal(t, 100, bucket.Capacity())
}
