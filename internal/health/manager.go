package health

import (
	"context"
	"sync"
	"time"
)

// Manager manages health checks for multiple targets.
type Manager struct {
	checks   map[string]*managedCheck
	mu       sync.RWMutex
	done     chan struct{}
	running  bool
}

type managedCheck struct {
	name     string
	checker  Checker
	interval time.Duration
	result   Result
	callback func(name string, result Result)
	mu       sync.RWMutex
}

// NewManager creates a new health check manager.
func NewManager() *Manager {
	return &Manager{
		checks: make(map[string]*managedCheck),
		done:   make(chan struct{}),
	}
}

// Register registers a health check.
func (m *Manager) Register(name string, checker Checker, interval time.Duration, callback func(string, Result)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if interval == 0 {
		interval = 30 * time.Second
	}

	m.checks[name] = &managedCheck{
		name:     name,
		checker:  checker,
		interval: interval,
		callback: callback,
	}
}

// Unregister removes a health check.
func (m *Manager) Unregister(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.checks, name)
}

// Start starts the health check manager.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.done = make(chan struct{})
	m.mu.Unlock()

	// Start health check goroutines
	m.mu.RLock()
	for _, check := range m.checks {
		go m.runCheck(ctx, check)
	}
	m.mu.RUnlock()

	return nil
}

// Stop stops the health check manager.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	close(m.done)
	m.running = false
}

// runCheck runs a single health check periodically.
func (m *Manager) runCheck(ctx context.Context, check *managedCheck) {
	// Initial check
	m.performCheck(ctx, check)

	ticker := time.NewTicker(check.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
			m.performCheck(ctx, check)
		}
	}
}

// performCheck performs a single health check.
func (m *Manager) performCheck(ctx context.Context, check *managedCheck) {
	// Create timeout context
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result := check.checker.Check(checkCtx)

	check.mu.Lock()
	check.result = result
	check.mu.Unlock()

	if check.callback != nil {
		check.callback(check.name, result)
	}
}

// GetResult returns the latest health check result for a target.
func (m *Manager) GetResult(name string) (Result, bool) {
	m.mu.RLock()
	check, exists := m.checks[name]
	m.mu.RUnlock()

	if !exists {
		return Result{}, false
	}

	check.mu.RLock()
	result := check.result
	check.mu.RUnlock()

	return result, true
}

// GetAllResults returns all health check results.
func (m *Manager) GetAllResults() map[string]Result {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make(map[string]Result)
	for name, check := range m.checks {
		check.mu.RLock()
		results[name] = check.result
		check.mu.RUnlock()
	}

	return results
}

// IsHealthy returns true if all health checks are passing.
func (m *Manager) IsHealthy() bool {
	results := m.GetAllResults()
	for _, result := range results {
		if !result.Healthy {
			return false
		}
	}
	return true
}

// CheckNow performs an immediate health check.
func (m *Manager) CheckNow(ctx context.Context, name string) (Result, error) {
	m.mu.RLock()
	check, exists := m.checks[name]
	m.mu.RUnlock()

	if !exists {
		return Result{}, ErrCheckNotFound
	}

	result := check.checker.Check(ctx)

	check.mu.Lock()
	check.result = result
	check.mu.Unlock()

	return result, nil
}

// Error types
var (
	ErrCheckNotFound = &HealthError{Message: "health check not found"}
)

// HealthError represents a health check error.
type HealthError struct {
	Message string
}

func (e *HealthError) Error() string {
	return e.Message
}
