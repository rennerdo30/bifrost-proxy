// Package debug provides traffic debugging for Bifrost client.
package debug

import (
	"time"
)

// Entry represents a traffic debug entry.
type Entry struct {
	ID            string        `json:"id"`
	Timestamp     time.Time     `json:"timestamp"`
	Type          EntryType     `json:"type"`
	Host          string        `json:"host"`
	Method        string        `json:"method,omitempty"`
	Path          string        `json:"path,omitempty"`
	Protocol      string        `json:"protocol"`
	StatusCode    int           `json:"status_code,omitempty"`
	Duration      time.Duration `json:"duration_ms"`
	BytesSent     int64         `json:"bytes_sent"`
	BytesReceived int64         `json:"bytes_received"`
	Error         string        `json:"error,omitempty"`
	Action        string        `json:"action"` // server, direct
	ClientAddr    string        `json:"client_addr"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	RequestBody   []byte        `json:"request_body,omitempty"`
	ResponseBody  []byte        `json:"response_body,omitempty"`
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
