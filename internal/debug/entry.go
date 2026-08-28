// Package debug provides traffic debugging for Bifrost client.
package debug

import (
	"encoding/json"
	"time"
)

// Entry represents a traffic debug entry.
type Entry struct {
	ID              string            `json:"id"`
	Timestamp       time.Time         `json:"timestamp"`
	Type            EntryType         `json:"type"`
	Host            string            `json:"host"`
	Method          string            `json:"method,omitempty"`
	Path            string            `json:"path,omitempty"`
	Protocol        string            `json:"protocol"`
	StatusCode      int               `json:"status_code,omitempty"`
	Duration        time.Duration     `json:"duration_ms"`
	BytesSent       int64             `json:"bytes_sent"`
	BytesReceived   int64             `json:"bytes_received"`
	Error           string            `json:"error,omitempty"`
	Action          string            `json:"action"` // server, direct
	ClientAddr      string            `json:"client_addr"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	RequestBody     []byte            `json:"request_body,omitempty"`
	ResponseBody    []byte            `json:"response_body,omitempty"`
}

// MarshalJSON emits Duration in the unit its field name promises. The plain
// time.Duration marshaled as NANOseconds under a key called duration_ms, so
// the traffic table read a million times the real value (and disagreed with
// the /logs endpoint, which uses real milliseconds for the same field name).
func (e Entry) MarshalJSON() ([]byte, error) {
	type alias Entry
	return json.Marshal(struct {
		alias
		DurationMS int64 `json:"duration_ms"`
	}{
		alias:      alias(e),
		DurationMS: e.Duration.Milliseconds(),
	})
}

// EntryType represents the type of debug entry.
type EntryType string

const (
	EntryTypeConnect    EntryType = "connect"
	EntryTypeRequest    EntryType = "request"
	EntryTypeResponse   EntryType = "response"
	EntryTypeError      EntryType = "error"
	EntryTypeDisconnect EntryType = "disconnect"
)

// Summary returns a summary of the entry.
func (e *Entry) Summary() string {
	if e.Method != "" {
		return e.Method + " " + e.Host + e.Path
	}
	return string(e.Type) + " " + e.Host
}
