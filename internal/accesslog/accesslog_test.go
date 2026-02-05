package accesslog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Helper to create a WriteCloser from a buffer
type bufferCloser struct {
	*bytes.Buffer
}

func (b *bufferCloser) Close() error {
	return nil
}

func newBufferCloser() *bufferCloser {
	return &bufferCloser{&bytes.Buffer{}}
}

func TestNew_Disabled(t *testing.T) {
	logger, err := New(Config{Enabled: false})

	if err != nil {
		t.Errorf("New() error = %v", err)
	}

	_, ok := logger.(*NoopLogger)
	if !ok {
		t.Error("New() with Enabled=false should return NoopLogger")
	}
}

func TestNew_JSONFormat(t *testing.T) {
	logger, err := New(Config{
		Enabled: true,
		Format:  "json",
		Output:  "stdout",
	})

	if err != nil {
		t.Errorf("New() error = %v", err)
	}

	_, ok := logger.(*JSONLogger)
	if !ok {
		t.Error("New() with format=json should return JSONLogger")
	}
}

func TestNew_ApacheFormat(t *testing.T) {
	logger, err := New(Config{
		Enabled: true,
		Format:  "apache",
		Output:  "stdout",
	})

	if err != nil {
		t.Errorf("New() error = %v", err)
	}

	_, ok := logger.(*ApacheLogger)
	if !ok {
		t.Error("New() with format=apache should return ApacheLogger")
	}
}

func TestNew_CombinedFormat(t *testing.T) {
	logger, err := New(Config{
		Enabled: true,
		Format:  "combined",
		Output:  "stdout",
	})

	if err != nil {
		t.Errorf("New() error = %v", err)
	}

	_, ok := logger.(*ApacheLogger)
	if !ok {
		t.Error("New() with format=combined should return ApacheLogger")
	}
}

func TestNew_UnknownFormat(t *testing.T) {
	logger, err := New(Config{
		Enabled: true,
		Format:  "unknown",
		Output:  "stdout",
	})

	if err != nil {
		t.Errorf("New() error = %v", err)
	}

	// Unknown format defaults to JSON
	_, ok := logger.(*JSONLogger)
	if !ok {
		t.Error("New() with unknown format should default to JSONLogger")
	}
}

func TestNew_EmptyFormat(t *testing.T) {
	logger, err := New(Config{
		Enabled: true,
		Format:  "",
		Output:  "stdout",
	})

	if err != nil {
		t.Errorf("New() error = %v", err)
	}

	_, ok := logger.(*JSONLogger)
	if !ok {
		t.Error("New() with empty format should return JSONLogger")
	}
}

func TestNew_StderrOutput(t *testing.T) {
	logger, err := New(Config{
		Enabled: true,
		Format:  "json",
		Output:  "stderr",
	})

	if err != nil {
		t.Errorf("New() error = %v", err)
	}

	if logger == nil {
		t.Error("New() returned nil")
	}
}

func TestNew_FileOutput(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "access.log")

	logger, err := New(Config{
		Enabled: true,
		Format:  "json",
		Output:  logFile,
	})

	if err != nil {
		t.Errorf("New() error = %v", err)
	}

	if logger == nil {
		t.Error("New() returned nil")
	}

	logger.Close()

	// Verify file was created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file was not created")
	}
}

func TestNew_NestedFileOutput(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "nested", "dir", "access.log")

	logger, err := New(Config{
		Enabled: true,
		Format:  "json",
		Output:  logFile,
	})

	if err != nil {
		t.Errorf("New() with nested path error = %v", err)
	}

	logger.Close()
}

func TestNew_InvalidFileOutput(t *testing.T) {
	_, err := New(Config{
		Enabled: true,
		Format:  "json",
		Output:  "/dev/null/impossible/path/log.txt",
	})

	if err == nil {
		t.Error("New() with invalid file path should return error")
	}
}

func TestNoopLogger(t *testing.T) {
	logger := &NoopLogger{}

	entry := Entry{
		Timestamp: time.Now(),
		ClientIP:  "192.168.1.1",
		Method:    "GET",
		Host:      "example.com",
	}

	// Log should do nothing and return nil
	err := logger.Log(entry)
	if err != nil {
		t.Errorf("NoopLogger.Log() error = %v", err)
	}

	// Close should return nil
	err = logger.Close()
	if err != nil {
		t.Errorf("NoopLogger.Close() error = %v", err)
	}
}

func TestJSONLogger_Log(t *testing.T) {
	buf := newBufferCloser()
	logger := NewJSONLogger(buf)

	entry := Entry{
		Timestamp:     time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		ClientIP:      "192.168.1.1",
		Username:      "testuser",
		Method:        "GET",
		Host:          "example.com",
		Path:          "/api/test",
		Protocol:      "HTTP/1.1",
		StatusCode:    200,
		BytesSent:     1024,
		BytesReceived: 256,
		Duration:      100 * time.Millisecond,
		Backend:       "direct",
		RequestID:     "req-123",
		UserAgent:     "TestAgent/1.0",
	}

	err := logger.Log(entry)
	if err != nil {
		t.Errorf("JSONLogger.Log() error = %v", err)
	}

	output := buf.String()

	// Should be valid JSON
	var parsed Entry
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}

	// Verify fields
	if parsed.ClientIP != "192.168.1.1" {
		t.Errorf("ClientIP = %s, want 192.168.1.1", parsed.ClientIP)
	}
	if parsed.Method != "GET" {
		t.Errorf("Method = %s, want GET", parsed.Method)
	}
	if parsed.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", parsed.StatusCode)
	}
}

func TestJSONLogger_Close(t *testing.T) {
	buf := newBufferCloser()
	logger := NewJSONLogger(buf)

	err := logger.Close()
	if err != nil {
		t.Errorf("JSONLogger.Close() error = %v", err)
	}
}

func TestApacheLogger_Log(t *testing.T) {
	buf := newBufferCloser()
	logger := NewApacheLogger(buf)

	entry := Entry{
		Timestamp:  time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		ClientIP:   "192.168.1.1",
		Username:   "testuser",
		Method:     "GET",
		Host:       "example.com",
		Protocol:   "HTTP/1.1",
		StatusCode: 200,
		BytesSent:  1024,
		UserAgent:  "TestAgent/1.0",
	}

	err := logger.Log(entry)
	if err != nil {
		t.Errorf("ApacheLogger.Log() error = %v", err)
	}

	output := buf.String()

	// Should contain key elements
	if !strings.Contains(output, "192.168.1.1") {
		t.Error("Output should contain client IP")
	}
	if !strings.Contains(output, "testuser") {
		t.Error("Output should contain username")
	}
	if !strings.Contains(output, "GET") {
		t.Error("Output should contain method")
	}
	if !strings.Contains(output, "200") {
		t.Error("Output should contain status code")
	}
}

func TestApacheLogger_LogWithoutUsername(t *testing.T) {
	buf := newBufferCloser()
	logger := NewApacheLogger(buf)

	entry := Entry{
		Timestamp:  time.Now(),
		ClientIP:   "192.168.1.1",
		Method:     "GET",
		Host:       "example.com",
		Protocol:   "HTTP/1.1",
		StatusCode: 200,
		BytesSent:  1024,
	}

	err := logger.Log(entry)
	if err != nil {
		t.Errorf("ApacheLogger.Log() error = %v", err)
	}

	output := buf.String()

	// Should contain "-" for missing username
	if !strings.Contains(output, " - - [") {
		t.Errorf("Output should contain '- -' for missing username, got: %s", output)
	}
}

func TestApacheLogger_Close(t *testing.T) {
	buf := newBufferCloser()
	logger := NewApacheLogger(buf)

	err := logger.Close()
	if err != nil {
		t.Errorf("ApacheLogger.Close() error = %v", err)
	}
}

func TestNopCloser(t *testing.T) {
	nc := &nopCloser{os.Stdout}

	err := nc.Close()
	if err != nil {
		t.Errorf("nopCloser.Close() error = %v", err)
	}
}

func TestGetOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"stdout", "stdout"},
		{"empty", ""},
		{"stderr", "stderr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := getOutput(tt.output)
			if err != nil {
				t.Errorf("getOutput(%s) error = %v", tt.output, err)
			}
			if w == nil {
				t.Error("getOutput() returned nil")
			}
		})
	}
}

func TestGetOutput_File(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	w, err := getOutput(logFile)
	if err != nil {
		t.Errorf("getOutput() error = %v", err)
	}

	if w == nil {
		t.Fatal("getOutput() returned nil")
	}

	// Write something to verify it works
	_, err = w.Write([]byte("test\n"))
	if err != nil {
		t.Errorf("Write error = %v", err)
	}

	w.Close()
}

func TestEntryStruct(t *testing.T) {
	entry := Entry{
		Timestamp:     time.Now(),
		ClientIP:      "192.168.1.1",
		Username:      "user",
		Method:        "POST",
		Host:          "api.example.com",
		Path:          "/v1/data",
		Protocol:      "HTTP/2",
		StatusCode:    201,
		BytesSent:     2048,
		BytesReceived: 512,
		Duration:      50 * time.Millisecond,
		Backend:       "server",
		Error:         "",
		RequestID:     "abc123",
		UserAgent:     "CustomClient/2.0",
	}

	// Marshal and unmarshal to verify JSON tags work
	data, err := json.Marshal(entry)
	if err != nil {
		t.Errorf("Marshal error = %v", err)
	}

	var parsed Entry
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("Unmarshal error = %v", err)
	}

	if parsed.ClientIP != entry.ClientIP {
		t.Error("ClientIP not preserved")
	}
}

// Test concurrent logging
func TestJSONLogger_Concurrent(t *testing.T) {
	buf := newBufferCloser()
	logger := NewJSONLogger(buf)

	done := make(chan bool)

	// Start multiple goroutines logging concurrently
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				logger.Log(Entry{
					Timestamp: time.Now(),
					ClientIP:  "192.168.1.1",
					Method:    "GET",
				})
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify we have 1000 lines
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1000 {
		t.Errorf("Expected 1000 log lines, got %d", len(lines))
	}
}

// Test that file logger actually writes to file
func TestJSONLogger_FileWrite(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "access.log")

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}

	logger := NewJSONLogger(f)

	entry := Entry{
		Timestamp:  time.Now(),
		ClientIP:   "10.0.0.1",
		Method:     "POST",
		Host:       "test.com",
		StatusCode: 201,
	}

	logger.Log(entry)
	logger.Close()

	// Read file and verify content
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(data), "10.0.0.1") {
		t.Error("File should contain logged client IP")
	}
}

// errorWriter is a writer that always returns an error
type errorWriter struct{}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	return 0, io.ErrShortWrite
}

func (e *errorWriter) Close() error {
	return nil
}

func TestJSONLogger_WriteError(t *testing.T) {
	logger := NewJSONLogger(&errorWriter{})

	entry := Entry{
		Timestamp: time.Now(),
		ClientIP:  "192.168.1.1",
	}

	err := logger.Log(entry)
	if err == nil {
		t.Error("Expected error from failing writer")
	}
}

func TestApacheLogger_WriteError(t *testing.T) {
	logger := NewApacheLogger(&errorWriter{})

	entry := Entry{
		Timestamp: time.Now(),
		ClientIP:  "192.168.1.1",
	}

	err := logger.Log(entry)
	if err == nil {
		t.Error("Expected error from failing writer")
	}
}

func TestGetOutput_FileOpenError(t *testing.T) {
	// Create a file that blocks creating a file with the same name as a directory component
	tmpDir := t.TempDir()

	// Create a regular file
	blockingFile := filepath.Join(tmpDir, "blocking")
	if err := os.WriteFile(blockingFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Now try to create a log file that would require "blocking" to be a directory
	impossiblePath := filepath.Join(blockingFile, "access.log")

	_, err := getOutput(impossiblePath)
	if err == nil {
		t.Error("getOutput() should fail when path component is a file, not a directory")
	}

	// Verify error message contains expected text
	if !strings.Contains(err.Error(), "create log directory") && !strings.Contains(err.Error(), "open log file") {
		t.Errorf("Error should mention file/directory issue, got: %v", err)
	}
}

func TestGetOutput_FileCannotBeOpened(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a directory with the log file name to prevent opening it as a file
	logPath := filepath.Join(tmpDir, "access.log")
	if err := os.Mkdir(logPath, 0755); err != nil {
		t.Fatal(err)
	}

	_, err := getOutput(logPath)
	if err == nil {
		t.Error("getOutput() should fail when log path is a directory")
	}

	if !strings.Contains(err.Error(), "open log file") {
		t.Errorf("Error should mention 'open log file', got: %v", err)
	}
}

// TestJSONLogger_MarshalError tests the json.Marshal error path.
func TestJSONLogger_MarshalError(t *testing.T) {
	buf := newBufferCloser()
	logger := NewJSONLogger(buf)

	// Override the marshaler to simulate a marshal error
	marshalErr := fmt.Errorf("simulated marshal error")
	logger.marshaler = func(v any) ([]byte, error) {
		return nil, marshalErr
	}

	entry := Entry{
		Timestamp: time.Now(),
		ClientIP:  "192.168.1.1",
	}

	err := logger.Log(entry)
	if err == nil {
		t.Error("Expected error from failing marshaler")
	}
	if err != marshalErr {
		t.Errorf("Expected marshalErr, got: %v", err)
	}

	// Verify nothing was written
	if buf.Len() != 0 {
		t.Error("Buffer should be empty when marshal fails")
	}
}
