package debug

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogInterceptedRequest(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10, CaptureBody: true, MaxBodySize: 4})
	logger.LogInterceptedRequest(context.Background(), "example.com", "GET", "/x",
		map[string]string{"Accept": "*/*"}, []byte("hello-body"))

	entries := logger.GetEntries()
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, EntryTypeRequest, e.Type)
	assert.Equal(t, "https", e.Protocol)
	assert.Equal(t, "GET", e.Method)
	assert.Equal(t, "/x", e.Path)
	// Body truncated to MaxBodySize.
	assert.Equal(t, "hell", string(e.RequestBody))
}

func TestLogInterceptedRequest_NoBodyCapture(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10, CaptureBody: false})
	logger.LogInterceptedRequest(context.Background(), "example.com", "POST", "/y", nil, []byte("data"))
	entries := logger.GetEntries()
	require.Len(t, entries, 1)
	assert.Nil(t, entries[0].RequestBody)
	assert.Equal(t, "https", entries[0].Protocol)
}

func TestLogInterceptedResponse(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10, CaptureBody: true, MaxBodySize: 1024})
	logger.LogInterceptedResponse(context.Background(), "example.com", 200,
		map[string]string{"Content-Type": "text/html"}, []byte("<html>"), 5*time.Millisecond, 10, 20)

	entries := logger.GetEntries()
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, EntryTypeResponse, e.Type)
	assert.Equal(t, "https", e.Protocol)
	assert.Equal(t, 200, e.StatusCode)
	assert.Equal(t, "<html>", string(e.ResponseBody))
	assert.Equal(t, int64(10), e.BytesSent)
	assert.Equal(t, int64(20), e.BytesReceived)
}
