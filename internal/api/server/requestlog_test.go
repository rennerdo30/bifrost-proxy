package server

import (
	"encoding/json"
	"fmt"
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
	assert.True(t, stats.Enabled)
	assert.Equal(t, 10, stats.Count)
	assert.Equal(t, 100, stats.MaxSize)
}

func TestRequestLog_Stats_Empty(t *testing.T) {
	log := NewRequestLog(50, false)

	stats := log.Stats()
	assert.False(t, stats.Enabled)
	assert.Equal(t, 0, stats.Count)
	assert.Equal(t, 50, stats.MaxSize)
}

// The Web UI renders stats.total_requests, .total_bytes_sent, .total_bytes_recv
// and .top_hosts unconditionally as soon as stats.enabled is true. Before these
// fields existed the Request Log page crashed with
// "Cannot read properties of undefined (reading 'toLocaleString')" the moment
// api.enable_request_log was turned on.
func TestRequestLog_Stats_Aggregates(t *testing.T) {
	log := NewRequestLog(100, true)

	log.Add(RequestLogEntry{Method: "GET", Host: "a.example.com", StatusCode: 200, BytesSent: 10, BytesRecv: 100})
	log.Add(RequestLogEntry{Method: "GET", Host: "a.example.com", StatusCode: 404, BytesSent: 20, BytesRecv: 200})
	log.Add(RequestLogEntry{Method: "POST", Host: "b.example.com", StatusCode: 200, BytesSent: 30, BytesRecv: 300})

	stats := log.Stats()

	assert.Equal(t, int64(3), stats.TotalRequests)
	assert.Equal(t, int64(60), stats.TotalBytesSent)
	assert.Equal(t, int64(600), stats.TotalBytesRecv)
	assert.Equal(t, map[string]int{"GET": 2, "POST": 1}, stats.RequestsByMethod)
	assert.Equal(t, map[string]int{"200": 2, "404": 1}, stats.RequestsByStatus)
	require.Len(t, stats.TopHosts, 2)
	// Most frequent host first.
	assert.Equal(t, HostCount{Host: "a.example.com", Count: 2}, stats.TopHosts[0])
	assert.Equal(t, HostCount{Host: "b.example.com", Count: 1}, stats.TopHosts[1])
}

// The UI calls stats.top_hosts.slice() and Object.keys() on the two maps, so a
// JSON null would crash it just as a missing field did.
func TestRequestLog_Stats_CollectionsNeverNil(t *testing.T) {
	log := NewRequestLog(100, true)

	stats := log.Stats()
	require.NotNil(t, stats.TopHosts)
	require.NotNil(t, stats.RequestsByMethod)
	require.NotNil(t, stats.RequestsByStatus)

	encoded, err := json.Marshal(stats)
	require.NoError(t, err)

	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	for _, field := range []string{
		"enabled", "count", "max_size", "total_requests", "total_bytes_sent",
		"total_bytes_recv", "requests_by_method", "requests_by_status", "top_hosts",
	} {
		assert.Contains(t, decoded, field, "field %q must always be present for the Web UI", field)
	}
	assert.JSONEq(t, `[]`, string(decoded["top_hosts"]))
	assert.JSONEq(t, `{}`, string(decoded["requests_by_method"]))
	assert.JSONEq(t, `{}`, string(decoded["requests_by_status"]))
}

// Running totals must survive ring buffer eviction, otherwise "Total Requests"
// would silently stop counting once the buffer filled up.
func TestRequestLog_Stats_TotalsSurviveEviction(t *testing.T) {
	log := NewRequestLog(2, true)

	for i := 0; i < 5; i++ {
		log.Add(RequestLogEntry{Method: "GET", Host: "example.com", BytesSent: 1, BytesRecv: 2})
	}

	stats := log.Stats()
	assert.Equal(t, 2, stats.Count, "only maxSize entries are retained")
	assert.Equal(t, int64(5), stats.TotalRequests)
	assert.Equal(t, int64(5), stats.TotalBytesSent)
	assert.Equal(t, int64(10), stats.TotalBytesRecv)
}

func TestRequestLog_Stats_ClearResetsTotals(t *testing.T) {
	log := NewRequestLog(100, true)

	log.Add(RequestLogEntry{Method: "GET", Host: "example.com", BytesSent: 5, BytesRecv: 7})
	log.Clear()

	stats := log.Stats()
	assert.Equal(t, 0, stats.Count)
	assert.Zero(t, stats.TotalRequests)
	assert.Zero(t, stats.TotalBytesSent)
	assert.Zero(t, stats.TotalBytesRecv)
	assert.Empty(t, stats.TopHosts)
}

func TestRequestLog_Stats_TopHostsCapped(t *testing.T) {
	log := NewRequestLog(1000, true)

	// topHostsLimit+5 distinct hosts, each with a distinct count so the
	// ordering is unambiguous.
	const extraHosts = 5
	for i := 0; i < topHostsLimit+extraHosts; i++ {
		for j := 0; j <= i; j++ {
			log.Add(RequestLogEntry{Method: "GET", Host: fmt.Sprintf("host-%02d", i)})
		}
	}

	stats := log.Stats()
	require.Len(t, stats.TopHosts, topHostsLimit)
	// The busiest host is the last one added (highest count).
	assert.Equal(t, fmt.Sprintf("host-%02d", topHostsLimit+extraHosts-1), stats.TopHosts[0].Host)
	for i := 1; i < len(stats.TopHosts); i++ {
		assert.GreaterOrEqual(t, stats.TopHosts[i-1].Count, stats.TopHosts[i].Count)
	}
}

func TestRequestLog_Stats_DisabledDoesNotCount(t *testing.T) {
	log := NewRequestLog(100, false)

	log.Add(RequestLogEntry{Method: "GET", Host: "example.com", BytesSent: 1, BytesRecv: 1})

	stats := log.Stats()
	assert.Zero(t, stats.TotalRequests)
	assert.Zero(t, stats.TotalBytesSent)
	assert.Zero(t, stats.TotalBytesRecv)
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
