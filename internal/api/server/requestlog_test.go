package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRequestLog(t *testing.T) {
	log := NewRequestLog(100, true)
	require.NotNil(t, log)
	assert.Equal(t, 100, log.maxSize)
	assert.True(t, log.enabled)
	assert.Equal(t, int64(1), log.nextID)
}

func TestNewRequestLog_DefaultSize(t *testing.T) {
	log := NewRequestLog(0, true)
	assert.Equal(t, 1000, log.maxSize)
}

func TestNewRequestLog_NegativeSize(t *testing.T) {
	log := NewRequestLog(-100, true)
	assert.Equal(t, 1000, log.maxSize)
}

func TestRequestLog_Add(t *testing.T) {
	log := NewRequestLog(100, true)

	log.Add(RequestLogEntry{
		Method:   "GET",
		Host:     "example.com",
		Path:     "/test",
		ClientIP: "127.0.0.1",
	})

	entries := log.GetAll()
	require.Len(t, entries, 1)
	assert.Equal(t, int64(1), entries[0].ID)
	assert.Equal(t, "GET", entries[0].Method)
	assert.Equal(t, "example.com", entries[0].Host)
}

func TestRequestLog_Add_Disabled(t *testing.T) {
	log := NewRequestLog(100, false)

	log.Add(RequestLogEntry{
		Method: "GET",
		Host:   "example.com",
	})

	entries := log.GetAll()
	assert.Empty(t, entries)
}

func TestRequestLog_Add_RingBuffer(t *testing.T) {
	log := NewRequestLog(5, true)

	// Add more entries than maxSize
	for i := 0; i < 10; i++ {
		log.Add(RequestLogEntry{
			Method: "GET",
			Host:   "example.com",
		})
	}

	entries := log.GetAll()
	assert.Len(t, entries, 5)

	// Oldest should be ID 6 (first 5 were evicted)
	assert.Equal(t, int64(6), entries[4].ID)
	// Newest should be ID 10
	assert.Equal(t, int64(10), entries[0].ID)
}

func TestRequestLog_Add_IncrementingIDs(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 5; i++ {
		log.Add(RequestLogEntry{
			Method: "GET",
		})
	}

	entries := log.GetAll()
	// Entries are returned newest first
	assert.Equal(t, int64(5), entries[0].ID)
	assert.Equal(t, int64(4), entries[1].ID)
	assert.Equal(t, int64(3), entries[2].ID)
	assert.Equal(t, int64(2), entries[3].ID)
	assert.Equal(t, int64(1), entries[4].ID)
}

func TestRequestLog_GetRecent(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 10; i++ {
		log.Add(RequestLogEntry{
			Method: "GET",
			Host:   "example.com",
		})
	}

	// Get last 3
	entries := log.GetRecent(3)
	assert.Len(t, entries, 3)

	// Should be newest first
	assert.Equal(t, int64(10), entries[0].ID)
	assert.Equal(t, int64(9), entries[1].ID)
	assert.Equal(t, int64(8), entries[2].ID)
}

func TestRequestLog_GetRecent_MoreThanExists(t *testing.T) {
	log := NewRequestLog(100, true)

	log.Add(RequestLogEntry{Method: "GET"})
	log.Add(RequestLogEntry{Method: "POST"})

	entries := log.GetRecent(100)
	assert.Len(t, entries, 2)
}

func TestRequestLog_GetRecent_Zero(t *testing.T) {
	log := NewRequestLog(100, true)

	log.Add(RequestLogEntry{Method: "GET"})
	log.Add(RequestLogEntry{Method: "POST"})

	entries := log.GetRecent(0)
	assert.Len(t, entries, 2) // Returns all
}

func TestRequestLog_GetRecent_Negative(t *testing.T) {
	log := NewRequestLog(100, true)

	log.Add(RequestLogEntry{Method: "GET"})

	entries := log.GetRecent(-5)
	assert.Len(t, entries, 1) // Returns all
}

func TestRequestLog_GetSince(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 10; i++ {
		log.Add(RequestLogEntry{Method: "GET"})
	}

	// Get entries since ID 7
	entries := log.GetSince(7)
	assert.Len(t, entries, 3) // IDs 8, 9, 10

	// Should be newest first
	assert.Equal(t, int64(10), entries[0].ID)
	assert.Equal(t, int64(9), entries[1].ID)
	assert.Equal(t, int64(8), entries[2].ID)
}

func TestRequestLog_GetSince_AllNewer(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 5; i++ {
		log.Add(RequestLogEntry{Method: "GET"})
	}

	// Get entries since ID 0 (all entries)
	entries := log.GetSince(0)
	assert.Len(t, entries, 5)
}

func TestRequestLog_GetSince_NoneNewer(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 5; i++ {
		log.Add(RequestLogEntry{Method: "GET"})
	}

	// Get entries since ID 10 (none newer)
	entries := log.GetSince(10)
	assert.Empty(t, entries)
}

func TestRequestLog_GetAll(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 5; i++ {
		log.Add(RequestLogEntry{Method: "GET"})
	}

	entries := log.GetAll()
	assert.Len(t, entries, 5)

	// Should be in reverse order (newest first)
	assert.Equal(t, int64(5), entries[0].ID)
	assert.Equal(t, int64(1), entries[4].ID)
}

func TestRequestLog_GetAll_Empty(t *testing.T) {
	log := NewRequestLog(100, true)

	entries := log.GetAll()
	assert.Empty(t, entries)
}

func TestRequestLog_Clear(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 5; i++ {
		log.Add(RequestLogEntry{Method: "GET"})
	}

	log.Clear()

	entries := log.GetAll()
	assert.Empty(t, entries)
}

func TestRequestLog_IsEnabled(t *testing.T) {
	log := NewRequestLog(100, true)
	assert.True(t, log.IsEnabled())

	log = NewRequestLog(100, false)
	assert.False(t, log.IsEnabled())
}

func TestRequestLog_SetEnabled(t *testing.T) {
	log := NewRequestLog(100, false)
	assert.False(t, log.IsEnabled())

	log.SetEnabled(true)
	assert.True(t, log.IsEnabled())

	log.SetEnabled(false)
	assert.False(t, log.IsEnabled())
}

func TestRequestLog_Stats(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 10; i++ {
		log.Add(RequestLogEntry{Method: "GET"})
	}

	stats := log.Stats()
	assert.True(t, stats["enabled"].(bool))
	assert.Equal(t, 10, stats["count"])
	assert.Equal(t, 100, stats["max_size"])
}

func TestRequestLog_Stats_Empty(t *testing.T) {
	log := NewRequestLog(50, false)

	stats := log.Stats()
	assert.False(t, stats["enabled"].(bool))
	assert.Equal(t, 0, stats["count"])
	assert.Equal(t, 50, stats["max_size"])
}

func TestRequestLogEntry_Struct(t *testing.T) {
	now := time.Now()
	entry := RequestLogEntry{
		ID:         1,
		Timestamp:  now,
		Method:     "POST",
		Host:       "example.com",
		Path:       "/api/test",
		URL:        "https://example.com/api/test",
		UserAgent:  "test-agent",
		ClientIP:   "192.168.1.1",
		Username:   "testuser",
		Backend:    "default",
		StatusCode: 200,
		BytesSent:  1024,
		BytesRecv:  2048,
		Duration:   150,
		Error:      "",
		Protocol:   "HTTP",
	}

	assert.Equal(t, int64(1), entry.ID)
	assert.Equal(t, now, entry.Timestamp)
	assert.Equal(t, "POST", entry.Method)
	assert.Equal(t, "example.com", entry.Host)
	assert.Equal(t, "/api/test", entry.Path)
	assert.Equal(t, "https://example.com/api/test", entry.URL)
	assert.Equal(t, "test-agent", entry.UserAgent)
	assert.Equal(t, "192.168.1.1", entry.ClientIP)
	assert.Equal(t, "testuser", entry.Username)
	assert.Equal(t, "default", entry.Backend)
	assert.Equal(t, 200, entry.StatusCode)
	assert.Equal(t, int64(1024), entry.BytesSent)
	assert.Equal(t, int64(2048), entry.BytesRecv)
	assert.Equal(t, int64(150), entry.Duration)
	assert.Equal(t, "HTTP", entry.Protocol)
}

func TestRequestLogEntry_WithError(t *testing.T) {
	entry := RequestLogEntry{
		Method:     "GET",
		Host:       "example.com",
		Error:      "connection refused",
		StatusCode: 0,
	}

	assert.Equal(t, "connection refused", entry.Error)
	assert.Equal(t, 0, entry.StatusCode)
}

func TestRequestLog_ConcurrentAccess(t *testing.T) {
	log := NewRequestLog(1000, true)
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			log.Add(RequestLogEntry{Method: "GET"})
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			_ = log.GetRecent(10)
			_ = log.GetAll()
			_ = log.Stats()
		}
		done <- true
	}()

	<-done
	<-done

	// Should not panic
	entries := log.GetAll()
	assert.LessOrEqual(t, len(entries), 100)
}

func TestRequestLog_ClearPreservesCapacity(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 50; i++ {
		log.Add(RequestLogEntry{Method: "GET"})
	}

	log.Clear()

	// Should be able to add again
	log.Add(RequestLogEntry{Method: "POST"})

	entries := log.GetAll()
	require.Len(t, entries, 1)
	assert.Equal(t, "POST", entries[0].Method)
}

func TestRequestLog_IDsIncrementAfterClear(t *testing.T) {
	log := NewRequestLog(100, true)

	for i := 0; i < 5; i++ {
		log.Add(RequestLogEntry{Method: "GET"})
	}

	// Last ID should be 5
	entries := log.GetAll()
	assert.Equal(t, int64(5), entries[0].ID)

	log.Clear()

	// Add more entries - IDs should continue from 6
	log.Add(RequestLogEntry{Method: "POST"})

	entries = log.GetAll()
	require.Len(t, entries, 1)
	assert.Equal(t, int64(6), entries[0].ID)
}

func TestRequestLog_SetEnabled_StopsAdding(t *testing.T) {
	log := NewRequestLog(100, true)

	log.Add(RequestLogEntry{Method: "GET"})

	log.SetEnabled(false)

	log.Add(RequestLogEntry{Method: "POST"})
	log.Add(RequestLogEntry{Method: "PUT"})

	entries := log.GetAll()
	assert.Len(t, entries, 1)
	assert.Equal(t, "GET", entries[0].Method)
}

func TestRequestLog_ReEnable(t *testing.T) {
	log := NewRequestLog(100, true)

	log.Add(RequestLogEntry{Method: "GET"})

	log.SetEnabled(false)
	log.Add(RequestLogEntry{Method: "POST"})

	log.SetEnabled(true)
	log.Add(RequestLogEntry{Method: "PUT"})

	entries := log.GetAll()
	assert.Len(t, entries, 2)
	// Newest first
	assert.Equal(t, "PUT", entries[0].Method)
	assert.Equal(t, "GET", entries[1].Method)
}

func TestRequestLog_Protocol(t *testing.T) {
	log := NewRequestLog(100, true)

	log.Add(RequestLogEntry{Method: "CONNECT", Protocol: "CONNECT"})
	log.Add(RequestLogEntry{Method: "GET", Protocol: "HTTP"})
	log.Add(RequestLogEntry{Method: "", Protocol: "SOCKS5"})

	entries := log.GetAll()
	assert.Equal(t, "SOCKS5", entries[0].Protocol)
	assert.Equal(t, "HTTP", entries[1].Protocol)
	assert.Equal(t, "CONNECT", entries[2].Protocol)
}
