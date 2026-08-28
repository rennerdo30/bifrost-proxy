package health

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"strconv"
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

	// The configured timeout drives both the subprocess flag and a context
	// bound. The flags used to be hardcoded to 5s while the setting was
	// accepted and stored, so failure detection ran 5-10x slower than the
	// operator configured.
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Platform-specific ping command and per-platform timeout unit:
	// milliseconds on Windows (-w) and macOS (-W), whole seconds on Linux (-W,
	// rounded up so a sub-second timeout still waits at least one second).
	// G204: target is validated hostname/IP from health check config, not user input
	timeoutMS := c.timeout.Milliseconds()
	if timeoutMS < 1 {
		timeoutMS = 1
	}
	timeoutSec := int64((c.timeout + time.Second - 1) / time.Second)
	if timeoutSec < 1 {
		timeoutSec = 1
	}
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.FormatInt(timeoutMS, 10), c.target) //nolint:gosec // G204: target is validated hostname from config
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.FormatInt(timeoutMS, 10), c.target) //nolint:gosec // G204: target is validated hostname from config
	default: // Linux and others
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.FormatInt(timeoutSec, 10), c.target) //nolint:gosec // G204: target is validated hostname from config
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
