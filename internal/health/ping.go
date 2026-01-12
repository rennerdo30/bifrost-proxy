package health

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// PingChecker performs ICMP ping health checks.
type PingChecker struct {
	target  string
	timeout time.Duration
}

// NewPingChecker creates a new ping health checker.
func NewPingChecker(cfg Config) *PingChecker {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Extract host from target (remove port if present)
	host := cfg.Target
	if h, _, err := net.SplitHostPort(cfg.Target); err == nil {
		host = h
	}

	return &PingChecker{
		target:  host,
		timeout: timeout,
	}
}

// Check performs a ping health check.
func (c *PingChecker) Check(ctx context.Context) Result {
	start := time.Now()

	var cmd *exec.Cmd

	// Platform-specific ping command
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "5000", c.target)
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5000", c.target)
	default: // Linux and others
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5", c.target)
	}

	output, err := cmd.CombinedOutput()
	latency := time.Since(start)

	result := Result{
		Latency:   latency,
		Timestamp: time.Now(),
	}

	if err != nil {
		result.Healthy = false
		result.Error = err.Error()
		result.Message = "Ping failed"
		return result
	}

	// Check for success in output
	outputStr := string(output)
	if strings.Contains(outputStr, "1 packets transmitted, 1") ||
		strings.Contains(outputStr, "1 received") ||
		strings.Contains(outputStr, "Reply from") {
		result.Healthy = true
		result.Message = "Ping successful"
	} else {
		result.Healthy = false
		result.Message = "Ping failed"
		result.Error = "No response"
	}

	return result
}

// Type returns the checker type.
func (c *PingChecker) Type() string {
	return "ping"
}
