package health

import (
	"context"
	"net"
	"time"
)

// TCPChecker performs TCP health checks.
type TCPChecker struct {
	target  string
	timeout time.Duration
}

// NewTCPChecker creates a new TCP health checker.
func NewTCPChecker(cfg Config) *TCPChecker {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &TCPChecker{
		target:  cfg.Target,
		timeout: timeout,
	}
}

// Check performs a TCP health check.
func (c *TCPChecker) Check(ctx context.Context) Result {
	start := time.Now()

	// Create dialer with context
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", c.target)
	latency := time.Since(start)

	result := Result{
		Latency:   latency,
		Timestamp: time.Now(),
	}

	if err != nil {
		result.Healthy = false
		result.Error = err.Error()
		result.Message = "TCP connection failed"
		return result
	}

	conn.Close()

	result.Healthy = true
	result.Message = "TCP connection successful"
	return result
}

// Type returns the checker type.
func (c *TCPChecker) Type() string {
	return "tcp"
}
