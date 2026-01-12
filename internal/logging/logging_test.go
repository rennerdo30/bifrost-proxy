package logging

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Level != "info" {
		t.Errorf("DefaultConfig().Level = %s, want info", cfg.Level)
	}
	if cfg.Format != "text" {
		t.Errorf("DefaultConfig().Format = %s, want text", cfg.Format)
	}
	if cfg.Output != "stdout" {
		t.Errorf("DefaultConfig().Output = %s, want stdout", cfg.Output)
	}
	if cfg.TimeFormat == "" {
		t.Error("DefaultConfig().TimeFormat should not be empty")
	}
}

func TestSetup_TextFormat(t *testing.T) {
	err := Setup(Config{
		Level:  "debug",
		Format: "text",
		Output: "stdout",
	})

	if err != nil {
		t.Errorf("Setup() error = %v", err)
	}
}

func TestSetup_JSONFormat(t *testing.T) {
	err := Setup(Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})

	if err != nil {
		t.Errorf("Setup() error = %v", err)
	}
}

func TestSetup_StderrOutput(t *testing.T) {
	err := Setup(Config{
		Level:  "warn",
		Format: "text",
		Output: "stderr",
	})

	if err != nil {
		t.Errorf("Setup() error = %v", err)
	}
}

func TestSetup_FileOutput(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	err := Setup(Config{
		Level:  "info",
		Format: "text",
		Output: logFile,
	})

	if err != nil {
		t.Errorf("Setup() with file output error = %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file was not created")
	}
}

func TestSetup_FileOutputWithNestedDir(t *testing.T) {
	// Create temp directory with nested path
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "nested", "dir", "test.log")

	err := Setup(Config{
		Level:  "info",
		Format: "text",
		Output: logFile,
	})

	if err != nil {
		t.Errorf("Setup() with nested file output error = %v", err)
	}
}

func TestSetup_InvalidLevel(t *testing.T) {
	err := Setup(Config{
		Level:  "invalid",
		Format: "text",
		Output: "stdout",
	})

	if err == nil {
		t.Error("Setup() with invalid level should return error")
	}
	if !strings.Contains(err.Error(), "unknown log level") {
		t.Errorf("Error should mention unknown log level, got: %v", err)
	}
}

func TestSetup_InvalidFormat(t *testing.T) {
	err := Setup(Config{
		Level:  "info",
		Format: "invalid",
		Output: "stdout",
	})

	if err == nil {
		t.Error("Setup() with invalid format should return error")
	}
	if !strings.Contains(err.Error(), "unknown log format") {
		t.Errorf("Error should mention unknown log format, got: %v", err)
	}
}

func TestSetup_EmptyDefaults(t *testing.T) {
	// Empty config should use defaults
	err := Setup(Config{})

	if err != nil {
		t.Errorf("Setup() with empty config error = %v", err)
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    slog.Level
		wantErr bool
	}{
		{"debug", slog.LevelDebug, false},
		{"DEBUG", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"INFO", slog.LevelInfo, false},
		{"", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"warning", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"invalid", slog.LevelInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level, err := parseLevel(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("parseLevel() should return error")
				}
				return
			}

			if err != nil {
				t.Errorf("parseLevel() error = %v", err)
				return
			}

			if level != tt.want {
				t.Errorf("parseLevel() = %v, want %v", level, tt.want)
			}
		})
	}
}

func TestDefault(t *testing.T) {
	logger := Default()

	if logger == nil {
		t.Error("Default() returned nil")
	}
}

func TestWith(t *testing.T) {
	logger := With("key", "value")

	if logger == nil {
		t.Error("With() returned nil")
	}
}

func TestWithComponent(t *testing.T) {
	logger := WithComponent("test-component")

	if logger == nil {
		t.Error("WithComponent() returned nil")
	}
}

func TestLoggingFunctions(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	loggerMu.Lock()
	oldLogger := defaultLogger
	defaultLogger = slog.New(handler)
	loggerMu.Unlock()

	defer func() {
		loggerMu.Lock()
		defaultLogger = oldLogger
		loggerMu.Unlock()
	}()

	// Test each logging function
	Debug("debug message", "key", "value")
	Info("info message", "key", "value")
	Warn("warn message", "key", "value")
	Error("error message", "key", "value")

	output := buf.String()

	if !strings.Contains(output, "debug message") {
		t.Error("Debug() output not found")
	}
	if !strings.Contains(output, "info message") {
		t.Error("Info() output not found")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("Warn() output not found")
	}
	if !strings.Contains(output, "error message") {
		t.Error("Error() output not found")
	}
}

func TestGetOutput(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantErr bool
	}{
		{"stdout", "stdout", false},
		{"STDOUT", "STDOUT", false},
		{"stderr", "stderr", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := getOutput(tt.output)

			if tt.wantErr {
				if err == nil {
					t.Error("getOutput() should return error")
				}
				return
			}

			if err != nil {
				t.Errorf("getOutput() error = %v", err)
				return
			}

			if w == nil {
				t.Error("getOutput() returned nil writer")
			}
		})
	}
}

func TestGetOutput_FileCreation(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "output.log")

	w, err := getOutput(logFile)

	if err != nil {
		t.Errorf("getOutput() error = %v", err)
		return
	}

	if w == nil {
		t.Error("getOutput() returned nil writer")
	}

	// Close the file
	if f, ok := w.(*os.File); ok {
		f.Close()
	}
}

func TestSetup_InvalidFilePath(t *testing.T) {
	// Try to write to a path that will fail (directory as file)
	err := Setup(Config{
		Level:  "info",
		Format: "text",
		Output: "/dev/null/impossible/path/log.txt",
	})

	if err == nil {
		t.Error("Setup() with invalid file path should return error")
	}
}
