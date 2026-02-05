package health

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// HTTPChecker performs HTTP health checks.
type HTTPChecker struct {
	target  string
	path    string
	timeout time.Duration
	client  *http.Client
}

// NewHTTPChecker creates a new HTTP health checker.
func NewHTTPChecker(cfg Config) *HTTPChecker {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	path := cfg.Path
	if path == "" {
		path = "/health"
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // G402: Health checks need to accept self-signed certs for internal services
		},
	}

	return &HTTPChecker{
		target:  cfg.Target,
		path:    path,
		timeout: timeout,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}
}

// Check performs an HTTP health check.
func (c *HTTPChecker) Check(ctx context.Context) Result {
	start := time.Now()

	url := fmt.Sprintf("http://%s%s", c.target, c.path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{
			Healthy:   false,
			Error:     err.Error(),
			Message:   "Failed to create request",
			Latency:   time.Since(start),
			Timestamp: time.Now(),
		}
	}

	resp, err := c.client.Do(req)
	latency := time.Since(start)

	result := Result{
		Latency:   latency,
		Timestamp: time.Now(),
	}

	if err != nil {
		result.Healthy = false
		result.Error = err.Error()
		result.Message = "HTTP request failed"
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		result.Healthy = true
		result.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
	} else {
		result.Healthy = false
		result.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
		result.Error = fmt.Sprintf("unhealthy status code: %d", resp.StatusCode)
	}

	return result
}

// Type returns the checker type.
func (c *HTTPChecker) Type() string {
	return "http"
}
