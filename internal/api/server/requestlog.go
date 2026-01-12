package server

import (
	"sync"
	"time"
)

// RequestLogEntry represents a single request log entry.
type RequestLogEntry struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Method      string    `json:"method"`
	Host        string    `json:"host"`
	Path        string    `json:"path"`
	URL         string    `json:"url"`
	UserAgent   string    `json:"user_agent"`
	ClientIP    string    `json:"client_ip"`
	Username    string    `json:"username,omitempty"`
	Backend     string    `json:"backend"`
	StatusCode  int       `json:"status_code"`
	BytesSent   int64     `json:"bytes_sent"`
	BytesRecv   int64     `json:"bytes_recv"`
	Duration    int64     `json:"duration_ms"`
	Error       string    `json:"error,omitempty"`
	Protocol    string    `json:"protocol"` // HTTP, SOCKS5, CONNECT
}

// RequestLog maintains a ring buffer of recent requests.
type RequestLog struct {
	mu       sync.RWMutex
	entries  []RequestLogEntry
	maxSize  int
	nextID   int64
	enabled  bool
}

// NewRequestLog creates a new request log with the given max size.
func NewRequestLog(maxSize int, enabled bool) *RequestLog {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &RequestLog{
		entries: make([]RequestLogEntry, 0, maxSize),
		maxSize: maxSize,
		nextID:  1,
		enabled: enabled,
	}
}

// Add adds a new entry to the request log.
func (r *RequestLog) Add(entry RequestLogEntry) {
	if !r.enabled {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry.ID = r.nextID
	r.nextID++

	if len(r.entries) >= r.maxSize {
		// Remove oldest entry (shift left)
		r.entries = r.entries[1:]
	}
	r.entries = append(r.entries, entry)
}

// GetRecent returns the most recent n entries.
func (r *RequestLog) GetRecent(n int) []RequestLogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if n <= 0 || n > len(r.entries) {
		n = len(r.entries)
	}

	// Return entries in reverse order (newest first)
	result := make([]RequestLogEntry, n)
	for i := 0; i < n; i++ {
		result[i] = r.entries[len(r.entries)-1-i]
	}
	return result
}

// GetSince returns entries since the given ID.
func (r *RequestLog) GetSince(sinceID int64) []RequestLogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []RequestLogEntry
	for i := len(r.entries) - 1; i >= 0; i-- {
		if r.entries[i].ID <= sinceID {
			break
		}
		result = append(result, r.entries[i])
	}
	return result
}

// GetAll returns all entries.
func (r *RequestLog) GetAll() []RequestLogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return entries in reverse order (newest first)
	result := make([]RequestLogEntry, len(r.entries))
	for i := 0; i < len(r.entries); i++ {
		result[i] = r.entries[len(r.entries)-1-i]
	}
	return result
}

// Clear removes all entries.
func (r *RequestLog) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = r.entries[:0]
}

// IsEnabled returns whether request logging is enabled.
func (r *RequestLog) IsEnabled() bool {
	return r.enabled
}

// SetEnabled enables or disables request logging.
func (r *RequestLog) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
}

// Stats returns statistics about the request log.
func (r *RequestLog) Stats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return map[string]interface{}{
		"enabled":  r.enabled,
		"count":    len(r.entries),
		"max_size": r.maxSize,
	}
}
