package debug

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

// Config holds debug logger configuration.
type Config struct {
	MaxEntries  int
	CaptureBody bool
	MaxBodySize int
}

// Logger provides traffic debugging.
type Logger struct {
	storage     *Storage
	captureBody bool
	maxBodySize int
	idCounter   atomic.Uint64
}

// NewLogger creates a new debug logger.
func NewLogger(cfg Config) *Logger {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 1000
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = 64 * 1024
	}

	return &Logger{
		storage:     NewStorage(cfg.MaxEntries),
		captureBody: cfg.CaptureBody,
		maxBodySize: cfg.MaxBodySize,
	}
}

// LogConnect logs a connection event.
func (l *Logger) LogConnect(ctx context.Context, host, clientAddr string) {
	entry := Entry{
		ID:         l.nextID(),
		Timestamp:  time.Now(),
		Type:       EntryTypeConnect,
		Host:       host,
		ClientAddr: clientAddr,
		Action:     util.GetBackend(ctx),
	}
	l.storage.Add(entry)
}

// LogRequest logs a request event.
func (l *Logger) LogRequest(ctx context.Context, host, method, path string, headers map[string]string, body []byte) {
	entry := Entry{
		ID:             l.nextID(),
		Timestamp:      time.Now(),
		Type:           EntryTypeRequest,
		Host:           host,
		Method:         method,
		Path:           path,
		ClientAddr:     util.GetClientIP(ctx),
		Action:         util.GetBackend(ctx),
		RequestHeaders: headers,
	}

	if l.captureBody && len(body) > 0 {
		if len(body) > l.maxBodySize {
			body = body[:l.maxBodySize]
		}
		entry.RequestBody = body
	}

	l.storage.Add(entry)
}

// LogResponse logs a response event.
func (l *Logger) LogResponse(ctx context.Context, host string, statusCode int, headers map[string]string, body []byte, duration time.Duration, bytesSent, bytesRecv int64) {
	entry := Entry{
		ID:              l.nextID(),
		Timestamp:       time.Now(),
		Type:            EntryTypeResponse,
		Host:            host,
		StatusCode:      statusCode,
		Duration:        duration,
		BytesSent:       bytesSent,
		BytesReceived:   bytesRecv,
		ClientAddr:      util.GetClientIP(ctx),
		Action:          util.GetBackend(ctx),
		ResponseHeaders: headers,
	}

	if l.captureBody && len(body) > 0 {
		if len(body) > l.maxBodySize {
			body = body[:l.maxBodySize]
		}
		entry.ResponseBody = body
	}

	l.storage.Add(entry)
}

// LogError logs an error event.
func (l *Logger) LogError(ctx context.Context, host string, err error) {
	entry := Entry{
		ID:         l.nextID(),
		Timestamp:  time.Now(),
		Type:       EntryTypeError,
		Host:       host,
		Error:      err.Error(),
		ClientAddr: util.GetClientIP(ctx),
		Action:     util.GetBackend(ctx),
	}
	l.storage.Add(entry)
}

// LogDisconnect logs a disconnect event.
func (l *Logger) LogDisconnect(ctx context.Context, host string, duration time.Duration, bytesSent, bytesRecv int64) {
	entry := Entry{
		ID:            l.nextID(),
		Timestamp:     time.Now(),
		Type:          EntryTypeDisconnect,
		Host:          host,
		Duration:      duration,
		BytesSent:     bytesSent,
		BytesReceived: bytesRecv,
		ClientAddr:    util.GetClientIP(ctx),
		Action:        util.GetBackend(ctx),
	}
	l.storage.Add(entry)
}

// GetEntries returns all debug entries.
func (l *Logger) GetEntries() []Entry {
	return l.storage.GetAll()
}

// GetLastEntries returns the last n entries.
func (l *Logger) GetLastEntries(n int) []Entry {
	return l.storage.GetLast(n)
}

// FindByHost returns entries for a specific host.
func (l *Logger) FindByHost(host string) []Entry {
	return l.storage.Find(func(e Entry) bool {
		return e.Host == host
	})
}

// FindErrors returns all error entries.
func (l *Logger) FindErrors() []Entry {
	return l.storage.Find(func(e Entry) bool {
		return e.Type == EntryTypeError
	})
}

// Clear removes all entries.
func (l *Logger) Clear() {
	l.storage.Clear()
}

// Count returns the number of entries.
func (l *Logger) Count() int {
	return l.storage.Count()
}

func (l *Logger) nextID() string {
	id := l.idCounter.Add(1)
	return fmt.Sprintf("%d-%d", time.Now().Unix(), id)
}
