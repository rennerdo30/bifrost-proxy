// Package logging provides structured logging for Bifrost.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Config holds logging configuration.
type Config struct {
	Level      string `yaml:"level" json:"level"`             // debug, info, warn, error
	Format     string `yaml:"format" json:"format"`           // json, text
	Output     string `yaml:"output" json:"output"`           // stdout, stderr, or file path
	TimeFormat string `yaml:"time_format" json:"time_format"` // time format string
}

// DefaultConfig returns the default logging configuration.
func DefaultConfig() Config {
	return Config{
		Level:      "info",
		Format:     "text",
		Output:     "stdout",
		TimeFormat: "2006-01-02T15:04:05.000Z07:00",
	}
}

var (
	defaultLogger  *slog.Logger
	loggerMu       sync.RWMutex
	currentLogFile *os.File // Track current log file for cleanup
)

func init() {
	// Initialize with default logger
	defaultLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// Close closes the current log file if one is open.
// This should be called during application shutdown.
func Close() error {
	loggerMu.Lock()
	defer loggerMu.Unlock()

	if currentLogFile != nil {
		err := currentLogFile.Close()
		currentLogFile = nil
		return err
	}
	return nil
}

// Setup initializes the logging system with the given configuration.
func Setup(cfg Config) error {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return err
	}

	output, logFile, err := getOutput(cfg.Output)
	if err != nil {
		return err
	}

	// Close previous log file if one exists
	loggerMu.Lock()
	if currentLogFile != nil {
		currentLogFile.Close()
	}
	currentLogFile = logFile
	loggerMu.Unlock()

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "json":
		handler = slog.NewJSONHandler(output, opts)
	case "text", "":
		handler = slog.NewTextHandler(output, opts)
	default:
		return fmt.Errorf("unknown log format: %s", cfg.Format)
	}

	loggerMu.Lock()
	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
	loggerMu.Unlock()

	return nil
}

// parseLevel converts a string log level to slog.Level.
func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %s", level)
	}
}

// getOutput returns an io.Writer for the given output specification.
// Returns the writer, the file handle (if a file was opened, nil otherwise), and any error.
func getOutput(output string) (io.Writer, *os.File, error) {
	switch strings.ToLower(output) {
	case "stdout", "":
		return os.Stdout, nil, nil
	case "stderr":
		return os.Stderr, nil, nil
	default:
		// Treat as file path
		dir := filepath.Dir(output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, nil, fmt.Errorf("failed to create log directory: %w", err)
		}
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open log file: %w", err)
		}
		return f, f, nil
	}
}

// Default returns the default logger.
func Default() *slog.Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return defaultLogger
}

// With returns a new logger with the given attributes.
func With(args ...any) *slog.Logger {
	return Default().With(args...)
}

// WithComponent returns a logger with a component attribute.
func WithComponent(component string) *slog.Logger {
	return With("component", component)
}

// Debug logs at debug level.
func Debug(msg string, args ...any) {
	Default().Debug(msg, args...)
}

// Info logs at info level.
func Info(msg string, args ...any) {
	Default().Info(msg, args...)
}

// Warn logs at warn level.
func Warn(msg string, args ...any) {
	Default().Warn(msg, args...)
}

// Error logs at error level.
func Error(msg string, args ...any) {
	Default().Error(msg, args...)
}
