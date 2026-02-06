// Package health provides health checking functionality.
package health

import (
	"context"
	"time"
)

// Checker is the interface for health checkers.
type Checker interface {
	// Check performs a health check and returns the result.
	Check(ctx context.Context) Result

	// Type returns the health check type.
	Type() string
}

// Result represents the result of a health check.
type Result struct {
	Healthy   bool          `json:"healthy"`
	Message   string        `json:"message,omitempty"`
	Latency   time.Duration `json:"latency"`
	Timestamp time.Time     `json:"timestamp"`
	Error     string        `json:"error,omitempty"`
}

// Config holds health check configuration.
type Config struct {
	Type               string        `yaml:"type"`                 // tcp, http, ping
	Target             string        `yaml:"target"`               // Target address
	Interval           time.Duration `yaml:"interval"`             // Check interval
	Timeout            time.Duration `yaml:"timeout"`              // Check timeout
	Path               string        `yaml:"path"`                 // For HTTP checks
	Scheme             string        `yaml:"scheme"`               // For HTTP checks: "http" or "https" (default: "http")
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"` // For HTTP checks: skip TLS verification (default: false)
}

// DefaultConfig returns default health check configuration.
func DefaultConfig() Config {
	return Config{
		Type:     "tcp",
		Interval: 30 * time.Second,
		Timeout:  5 * time.Second,
	}
}

// New creates a health checker based on configuration.
func New(cfg Config) Checker {
	switch cfg.Type {
	case "http":
		return NewHTTPChecker(cfg)
	case "ping":
		return NewPingChecker(cfg)
	case "tcp", "":
		return NewTCPChecker(cfg)
	default:
		return NewTCPChecker(cfg)
	}
}
