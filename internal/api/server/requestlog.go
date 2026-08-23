package server

import (
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	// defaultRequestLogSize is the ring buffer size used when the configured
	// size is not a positive number.
	defaultRequestLogSize = 1000

	// topHostsLimit caps how many hosts RequestLogStats.TopHosts reports.
	topHostsLimit = 10
)

// RequestLogEntry represents a single request log entry.
type RequestLogEntry struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	URL        string    `json:"url"`
	UserAgent  string    `json:"user_agent"`
	ClientIP   string    `json:"client_ip"`
	Username   string    `json:"username,omitempty"`
	Backend    string    `json:"backend"`
	StatusCode int       `json:"status_code"`
	BytesSent  int64     `json:"bytes_sent"`
	BytesRecv  int64     `json:"bytes_recv"`
	Duration   int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
	Protocol   string    `json:"protocol"` // HTTP, SOCKS5, CONNECT
}

// HostCount is a single entry of RequestLogStats.TopHosts.
type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// RequestLogStats is the payload of GET /api/v1/requests/stats.
//
// Two different scopes are mixed here deliberately, because the ring buffer
// cannot answer both questions from the same data:
//
//   - TotalRequests, TotalBytesSent and TotalBytesRecv are running totals
//     accumulated on every Add since the process started or since the last
//     Clear. They survive ring buffer eviction.
//   - Count, RequestsByMethod, RequestsByStatus and TopHosts describe only the
//     entries still retained in the buffer (at most MaxSize of them), because
//     evicted entries no longer exist.
//
// Every field is always present, and the map/slice fields are never nil, so
// the Web UI can render them without null checks.
type RequestLogStats struct {
	Enabled          bool           `json:"enabled"`
	Count            int            `json:"count"`
	MaxSize          int            `json:"max_size"`
	TotalRequests    int64          `json:"total_requests"`
	TotalBytesSent   int64          `json:"total_bytes_sent"`
	TotalBytesRecv   int64          `json:"total_bytes_recv"`
	RequestsByMethod map[string]int `json:"requests_by_method"`
	RequestsByStatus map[string]int `json:"requests_by_status"`
	TopHosts         []HostCount    `json:"top_hosts"`
}

// RequestLog maintains a ring buffer of recent requests.
type RequestLog struct {
	mu      sync.RWMutex
	entries []RequestLogEntry
	maxSize int
	nextID  int64
	enabled bool

	// Running totals, unaffected by ring buffer eviction and reset by Clear.
	totalRequests  int64
	totalBytesSent int64
	totalBytesRecv int64
}

// NewRequestLog creates a new request log with the given max size.
func NewRequestLog(maxSize int, enabled bool) *RequestLog {
	if maxSize <= 0 {
		maxSize = defaultRequestLogSize
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

	r.totalRequests++
	r.totalBytesSent += entry.BytesSent
	r.totalBytesRecv += entry.BytesRecv

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

// Clear removes all entries and resets the running totals reported by Stats.
// Entry IDs keep increasing so that GetSince cursors held by clients stay
// valid across a clear.
func (r *RequestLog) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = r.entries[:0]
	r.totalRequests = 0
	r.totalBytesSent = 0
	r.totalBytesRecv = 0
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

// Stats returns statistics about the request log. See RequestLogStats for the
// scope of each field.
func (r *RequestLog) Stats() RequestLogStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	byMethod := make(map[string]int, len(r.entries))
	byStatus := make(map[string]int, len(r.entries))
	byHost := make(map[string]int, len(r.entries))

	for i := range r.entries {
		e := &r.entries[i]
		byMethod[e.Method]++
		byStatus[strconv.Itoa(e.StatusCode)]++
		if e.Host != "" {
			byHost[e.Host]++
		}
	}

	return RequestLogStats{
		Enabled:          r.enabled,
		Count:            len(r.entries),
		MaxSize:          r.maxSize,
		TotalRequests:    r.totalRequests,
		TotalBytesSent:   r.totalBytesSent,
		TotalBytesRecv:   r.totalBytesRecv,
		RequestsByMethod: byMethod,
		RequestsByStatus: byStatus,
		TopHosts:         topHosts(byHost),
	}
}

// topHosts turns a host->count map into the highest-count hosts, most frequent
// first. Ties break on host name so the output is stable between calls.
func topHosts(counts map[string]int) []HostCount {
	hosts := make([]HostCount, 0, len(counts))
	for host, count := range counts {
		hosts = append(hosts, HostCount{Host: host, Count: count})
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Count != hosts[j].Count {
			return hosts[i].Count > hosts[j].Count
		}
		return hosts[i].Host < hosts[j].Host
	})
	if len(hosts) > topHostsLimit {
		hosts = hosts[:topHostsLimit]
	}
	return hosts
}
