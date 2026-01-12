package debug

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

// Entry tests

func TestEntrySummary_WithMethod(t *testing.T) {
	entry := Entry{
		Method: "GET",
		Host:   "example.com",
		Path:   "/api/test",
	}

	summary := entry.Summary()
	expected := "GET example.com/api/test"

	if summary != expected {
		t.Errorf("Summary() = %s, want %s", summary, expected)
	}
}

func TestEntrySummary_WithoutMethod(t *testing.T) {
	entry := Entry{
		Type: EntryTypeConnect,
		Host: "example.com",
	}

	summary := entry.Summary()
	expected := "connect example.com"

	if summary != expected {
		t.Errorf("Summary() = %s, want %s", summary, expected)
	}
}

func TestEntryTypes(t *testing.T) {
	types := []EntryType{
		EntryTypeConnect,
		EntryTypeRequest,
		EntryTypeResponse,
		EntryTypeError,
		EntryTypeDisconnect,
	}

	for _, et := range types {
		if string(et) == "" {
			t.Errorf("EntryType %v should not be empty", et)
		}
	}
}

// Storage tests

func TestNewStorage(t *testing.T) {
	tests := []struct {
		name     string
		capacity int
		want     int
	}{
		{"positive capacity", 100, 100},
		{"zero capacity", 0, 1000},
		{"negative capacity", -10, 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewStorage(tt.capacity)
			if s.capacity != tt.want {
				t.Errorf("NewStorage(%d).capacity = %d, want %d", tt.capacity, s.capacity, tt.want)
			}
		})
	}
}

func TestStorageAdd(t *testing.T) {
	s := NewStorage(10)

	entry := Entry{ID: "1", Host: "example.com"}
	s.Add(entry)

	if s.Count() != 1 {
		t.Errorf("Count() = %d, want 1", s.Count())
	}
}

func TestStorageGetAll_Empty(t *testing.T) {
	s := NewStorage(10)
	entries := s.GetAll()

	if len(entries) != 0 {
		t.Errorf("GetAll() on empty storage returned %d entries, want 0", len(entries))
	}
}

func TestStorageGetAll(t *testing.T) {
	s := NewStorage(10)

	// Add 3 entries
	for i := 0; i < 3; i++ {
		s.Add(Entry{ID: string(rune('1' + i)), Host: "example.com"})
	}

	entries := s.GetAll()

	if len(entries) != 3 {
		t.Errorf("GetAll() returned %d entries, want 3", len(entries))
	}
}

func TestStorageRingBuffer(t *testing.T) {
	s := NewStorage(3)

	// Add more entries than capacity
	for i := 0; i < 5; i++ {
		s.Add(Entry{ID: string(rune('0' + i)), Host: "example.com"})
	}

	// Should only have 3 entries (capacity)
	if s.Count() != 3 {
		t.Errorf("Count() after overflow = %d, want 3", s.Count())
	}

	// Get all should return entries in order (oldest first)
	entries := s.GetAll()
	if len(entries) != 3 {
		t.Errorf("GetAll() returned %d entries, want 3", len(entries))
	}

	// The oldest entry should be ID "2" (IDs 0,1 were overwritten)
	if entries[0].ID != "2" {
		t.Errorf("Oldest entry ID = %s, want 2", entries[0].ID)
	}
}

func TestStorageGetLast(t *testing.T) {
	s := NewStorage(10)

	// Add 5 entries
	for i := 0; i < 5; i++ {
		s.Add(Entry{ID: string(rune('0' + i)), Host: "example.com"})
	}

	// Get last 3 (newest first)
	entries := s.GetLast(3)

	if len(entries) != 3 {
		t.Errorf("GetLast(3) returned %d entries, want 3", len(entries))
	}

	// Newest should be ID "4"
	if entries[0].ID != "4" {
		t.Errorf("Newest entry ID = %s, want 4", entries[0].ID)
	}
}

func TestStorageGetLast_MoreThanAvailable(t *testing.T) {
	s := NewStorage(10)

	// Add 3 entries
	for i := 0; i < 3; i++ {
		s.Add(Entry{ID: string(rune('0' + i)), Host: "example.com"})
	}

	// Request more than available
	entries := s.GetLast(10)

	if len(entries) != 3 {
		t.Errorf("GetLast(10) with 3 entries returned %d, want 3", len(entries))
	}
}

func TestStorageClear(t *testing.T) {
	s := NewStorage(10)

	// Add some entries
	for i := 0; i < 5; i++ {
		s.Add(Entry{ID: string(rune('0' + i))})
	}

	s.Clear()

	if s.Count() != 0 {
		t.Errorf("Count() after Clear() = %d, want 0", s.Count())
	}
}

func TestStorageFind(t *testing.T) {
	s := NewStorage(10)

	// Add mixed entries
	s.Add(Entry{ID: "1", Type: EntryTypeError, Host: "example.com"})
	s.Add(Entry{ID: "2", Type: EntryTypeRequest, Host: "example.com"})
	s.Add(Entry{ID: "3", Type: EntryTypeError, Host: "other.com"})
	s.Add(Entry{ID: "4", Type: EntryTypeRequest, Host: "test.com"})

	// Find errors
	errors := s.Find(func(e Entry) bool {
		return e.Type == EntryTypeError
	})

	if len(errors) != 2 {
		t.Errorf("Find(errors) returned %d entries, want 2", len(errors))
	}

	// Find by host
	exampleEntries := s.Find(func(e Entry) bool {
		return e.Host == "example.com"
	})

	if len(exampleEntries) != 2 {
		t.Errorf("Find(host) returned %d entries, want 2", len(exampleEntries))
	}
}

func TestStorageFind_AfterOverflow(t *testing.T) {
	s := NewStorage(3)

	// Add more than capacity
	for i := 0; i < 5; i++ {
		entryType := EntryTypeRequest
		if i%2 == 0 {
			entryType = EntryTypeError
		}
		s.Add(Entry{ID: string(rune('0' + i)), Type: entryType})
	}

	// Should find entries from the current ring buffer content
	errors := s.Find(func(e Entry) bool {
		return e.Type == EntryTypeError
	})

	// Only entries 2, 3, 4 remain; errors are 2 and 4
	if len(errors) != 2 {
		t.Errorf("Find(errors) after overflow returned %d entries, want 2", len(errors))
	}
}

// Logger tests

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		wantEntries int
		wantBody    int
	}{
		{
			name:        "default config",
			cfg:         Config{},
			wantEntries: 1000,
			wantBody:    64 * 1024,
		},
		{
			name:        "custom config",
			cfg:         Config{MaxEntries: 500, MaxBodySize: 1024},
			wantEntries: 500,
			wantBody:    1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.cfg)
			if logger == nil {
				t.Fatal("NewLogger() returned nil")
			}
		})
	}
}

func TestLoggerLogConnect(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10})
	ctx := context.Background()
	ctx = util.WithBackend(ctx, "direct")

	logger.LogConnect(ctx, "example.com", "192.168.1.1")

	if logger.Count() != 1 {
		t.Errorf("Count() = %d, want 1", logger.Count())
	}

	entries := logger.GetEntries()
	if entries[0].Type != EntryTypeConnect {
		t.Errorf("Entry type = %s, want connect", entries[0].Type)
	}
	if entries[0].Host != "example.com" {
		t.Errorf("Entry host = %s, want example.com", entries[0].Host)
	}
}

func TestLoggerLogRequest(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10, CaptureBody: true, MaxBodySize: 100})
	ctx := context.Background()
	ctx = util.WithClientIP(ctx, "192.168.1.1")
	ctx = util.WithBackend(ctx, "server")

	headers := map[string]string{"Content-Type": "application/json"}
	body := []byte(`{"test": "data"}`)

	logger.LogRequest(ctx, "example.com", "POST", "/api", headers, body)

	if logger.Count() != 1 {
		t.Errorf("Count() = %d, want 1", logger.Count())
	}

	entries := logger.GetEntries()
	if entries[0].Type != EntryTypeRequest {
		t.Errorf("Entry type = %s, want request", entries[0].Type)
	}
	if entries[0].Method != "POST" {
		t.Errorf("Entry method = %s, want POST", entries[0].Method)
	}
	if entries[0].RequestBody == nil {
		t.Error("Request body should be captured")
	}
}

func TestLoggerLogRequest_BodyTruncation(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10, CaptureBody: true, MaxBodySize: 10})
	ctx := context.Background()

	body := []byte("this is a very long body that should be truncated")

	logger.LogRequest(ctx, "example.com", "POST", "/api", nil, body)

	entries := logger.GetEntries()
	if len(entries[0].RequestBody) != 10 {
		t.Errorf("Request body length = %d, want 10", len(entries[0].RequestBody))
	}
}

func TestLoggerLogRequest_NoCaptureBody(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10, CaptureBody: false})
	ctx := context.Background()

	body := []byte(`{"test": "data"}`)

	logger.LogRequest(ctx, "example.com", "POST", "/api", nil, body)

	entries := logger.GetEntries()
	if entries[0].RequestBody != nil {
		t.Error("Request body should not be captured when CaptureBody is false")
	}
}

func TestLoggerLogResponse(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10, CaptureBody: true, MaxBodySize: 100})
	ctx := context.Background()
	ctx = util.WithClientIP(ctx, "192.168.1.1")
	ctx = util.WithBackend(ctx, "direct")

	headers := map[string]string{"Content-Type": "text/html"}
	body := []byte("<html>test</html>")

	logger.LogResponse(ctx, "example.com", 200, headers, body, 100*time.Millisecond, 1024, 2048)

	if logger.Count() != 1 {
		t.Errorf("Count() = %d, want 1", logger.Count())
	}

	entries := logger.GetEntries()
	entry := entries[0]

	if entry.Type != EntryTypeResponse {
		t.Errorf("Entry type = %s, want response", entry.Type)
	}
	if entry.StatusCode != 200 {
		t.Errorf("Status code = %d, want 200", entry.StatusCode)
	}
	if entry.BytesSent != 1024 {
		t.Errorf("BytesSent = %d, want 1024", entry.BytesSent)
	}
	if entry.BytesReceived != 2048 {
		t.Errorf("BytesReceived = %d, want 2048", entry.BytesReceived)
	}
}

func TestLoggerLogResponse_BodyTruncation(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10, CaptureBody: true, MaxBodySize: 10})
	ctx := context.Background()

	body := []byte("this is a very long body that should be truncated")

	logger.LogResponse(ctx, "example.com", 200, nil, body, time.Second, 0, 0)

	entries := logger.GetEntries()
	if len(entries[0].ResponseBody) != 10 {
		t.Errorf("Response body length = %d, want 10", len(entries[0].ResponseBody))
	}
}

func TestLoggerLogError(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10})
	ctx := context.Background()
	ctx = util.WithClientIP(ctx, "192.168.1.1")
	ctx = util.WithBackend(ctx, "server")

	logger.LogError(ctx, "example.com", errors.New("connection refused"))

	if logger.Count() != 1 {
		t.Errorf("Count() = %d, want 1", logger.Count())
	}

	entries := logger.GetEntries()
	if entries[0].Type != EntryTypeError {
		t.Errorf("Entry type = %s, want error", entries[0].Type)
	}
	if !strings.Contains(entries[0].Error, "connection refused") {
		t.Errorf("Error message = %s, want to contain 'connection refused'", entries[0].Error)
	}
}

func TestLoggerLogDisconnect(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10})
	ctx := context.Background()
	ctx = util.WithClientIP(ctx, "192.168.1.1")
	ctx = util.WithBackend(ctx, "direct")

	logger.LogDisconnect(ctx, "example.com", 5*time.Second, 4096, 8192)

	if logger.Count() != 1 {
		t.Errorf("Count() = %d, want 1", logger.Count())
	}

	entries := logger.GetEntries()
	entry := entries[0]

	if entry.Type != EntryTypeDisconnect {
		t.Errorf("Entry type = %s, want disconnect", entry.Type)
	}
	if entry.Duration != 5*time.Second {
		t.Errorf("Duration = %v, want 5s", entry.Duration)
	}
}

func TestLoggerGetLastEntries(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10})
	ctx := context.Background()

	// Add 5 entries
	for i := 0; i < 5; i++ {
		logger.LogConnect(ctx, string(rune('a'+i))+".example.com", "192.168.1.1")
	}

	entries := logger.GetLastEntries(3)

	if len(entries) != 3 {
		t.Errorf("GetLastEntries(3) returned %d entries, want 3", len(entries))
	}
}

func TestLoggerFindByHost(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10})
	ctx := context.Background()

	logger.LogConnect(ctx, "example.com", "192.168.1.1")
	logger.LogConnect(ctx, "other.com", "192.168.1.1")
	logger.LogConnect(ctx, "example.com", "192.168.1.2")

	entries := logger.FindByHost("example.com")

	if len(entries) != 2 {
		t.Errorf("FindByHost() returned %d entries, want 2", len(entries))
	}
}

func TestLoggerFindErrors(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10})
	ctx := context.Background()

	logger.LogConnect(ctx, "example.com", "192.168.1.1")
	logger.LogError(ctx, "example.com", errors.New("error 1"))
	logger.LogConnect(ctx, "other.com", "192.168.1.1")
	logger.LogError(ctx, "other.com", errors.New("error 2"))

	errors := logger.FindErrors()

	if len(errors) != 2 {
		t.Errorf("FindErrors() returned %d entries, want 2", len(errors))
	}
}

func TestLoggerClear(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10})
	ctx := context.Background()

	// Add some entries
	for i := 0; i < 5; i++ {
		logger.LogConnect(ctx, "example.com", "192.168.1.1")
	}

	logger.Clear()

	if logger.Count() != 0 {
		t.Errorf("Count() after Clear() = %d, want 0", logger.Count())
	}
}

func TestLoggerNextID(t *testing.T) {
	logger := NewLogger(Config{MaxEntries: 10})
	ctx := context.Background()

	// Add entries and check IDs are unique
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		logger.LogConnect(ctx, "example.com", "192.168.1.1")
	}

	entries := logger.GetEntries()
	for _, e := range entries {
		if ids[e.ID] {
			t.Errorf("Duplicate ID found: %s", e.ID)
		}
		ids[e.ID] = true
	}
}
