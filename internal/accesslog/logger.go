// Package accesslog provides access logging for Bifrost.
package accesslog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger is the interface for access loggers.
type Logger interface {
	Log(entry Entry) error
	Close() error
}

// Entry represents a single access log entry.
type Entry struct {
	Timestamp     time.Time     `json:"timestamp"`
	ClientIP      string        `json:"client_ip"`
	Username      string        `json:"username,omitempty"`
	Method        string        `json:"method"`
	Host          string        `json:"host"`
	Path          string        `json:"path,omitempty"`
	Protocol      string        `json:"protocol"`
	StatusCode    int           `json:"status_code"`
	BytesSent     int64         `json:"bytes_sent"`
	BytesReceived int64         `json:"bytes_received"`
	Duration      time.Duration `json:"duration_ms"`
	Backend       string        `json:"backend,omitempty"`
	Error         string        `json:"error,omitempty"`
	RequestID     string        `json:"request_id,omitempty"`
	UserAgent     string        `json:"user_agent,omitempty"`
}

// Config holds access log configuration.
type Config struct {
	Enabled bool   `yaml:"enabled"`
	Format  string `yaml:"format"` // json, apache
	Output  string `yaml:"output"` // stdout, stderr, or file path
}

// New creates a new access logger based on configuration.
func New(cfg Config) (Logger, error) {
	if !cfg.Enabled {
		return &NoopLogger{}, nil
	}

	output, err := getOutput(cfg.Output)
	if err != nil {
		return nil, err
	}

	switch cfg.Format {
	case "json", "":
		return NewJSONLogger(output), nil
	case "apache", "combined":
		return NewApacheLogger(output), nil
	default:
		return NewJSONLogger(output), nil
	}
}

func getOutput(output string) (io.WriteCloser, error) {
	switch output {
	case "stdout", "":
		return &nopCloser{os.Stdout}, nil
	case "stderr":
		return &nopCloser{os.Stderr}, nil
	default:
		// File path
		dir := filepath.Dir(output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create log directory: %w", err)
		}
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		return f, nil
	}
}

type nopCloser struct {
	io.Writer
}

func (n *nopCloser) Close() error {
	return nil
}

// NoopLogger is a no-op logger.
type NoopLogger struct{}

// Log does nothing.
func (l *NoopLogger) Log(entry Entry) error {
	return nil
}

// Close does nothing.
func (l *NoopLogger) Close() error {
	return nil
}

// JSONLogger logs entries in JSON format.
type JSONLogger struct {
	writer io.WriteCloser
	mu     sync.Mutex
	// marshaler is the JSON marshal function used for encoding entries.
	// Defaults to json.Marshal. Can be overridden in tests to simulate errors.
	marshaler func(v any) ([]byte, error)
}

// NewJSONLogger creates a new JSON access logger.
func NewJSONLogger(w io.WriteCloser) *JSONLogger {
	return &JSONLogger{
		writer:    w,
		marshaler: json.Marshal,
	}
}

// Log writes a log entry in JSON format.
func (l *JSONLogger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := l.marshaler(entry)
	if err != nil {
		return err
	}

	_, err = l.writer.Write(append(data, '\n'))
	return err
}

// Close closes the logger.
func (l *JSONLogger) Close() error {
	return l.writer.Close()
}

// ApacheLogger logs entries in Apache combined format.
type ApacheLogger struct {
	writer io.WriteCloser
	mu     sync.Mutex
}

// NewApacheLogger creates a new Apache format access logger.
func NewApacheLogger(w io.WriteCloser) *ApacheLogger {
	return &ApacheLogger{writer: w}
}

// Log writes a log entry in Apache combined format.
func (l *ApacheLogger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Apache combined log format:
	// %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
	username := entry.Username
	if username == "" {
		username = "-"
	}

	line := fmt.Sprintf(
		"%s - %s [%s] \"%s %s %s\" %d %d \"-\" \"%s\"\n",
		entry.ClientIP,
		username,
		entry.Timestamp.Format("02/Jan/2006:15:04:05 -0700"),
		entry.Method,
		entry.Host,
		entry.Protocol,
		entry.StatusCode,
		entry.BytesSent,
		entry.UserAgent,
	)

	_, err := l.writer.Write([]byte(line))
	return err
}

// Close closes the logger.
func (l *ApacheLogger) Close() error {
	return l.writer.Close()
}
