package backend

import (
	"context"
	"fmt"
	"sync"
)

// Manager manages multiple backends.
type Manager struct {
	backends map[string]Backend
	mu       sync.RWMutex
}

// NewManager creates a new backend manager.
func NewManager() *Manager {
	return &Manager{
		backends: make(map[string]Backend),
	}
}

// Add adds a backend to the manager.
func (m *Manager) Add(backend Backend) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.backends[backend.Name()]; exists {
		return fmt.Errorf("%w: %s", ErrBackendExists, backend.Name())
	}

	m.backends[backend.Name()] = backend
	return nil
}

// Get retrieves a backend by name.
func (m *Manager) Get(name string) (Backend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	backend, exists := m.backends[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, name)
	}
	return backend, nil
}

// Remove removes a backend from the manager.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.backends[name]; !exists {
		return fmt.Errorf("%w: %s", ErrBackendNotFound, name)
	}

	delete(m.backends, name)
	return nil
}

// List returns all backend names.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.backends))
	for name := range m.backends {
		names = append(names, name)
	}
	return names
}

// All returns all backends.
func (m *Manager) All() []Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()

	backends := make([]Backend, 0, len(m.backends))
	for _, b := range m.backends {
		backends = append(backends, b)
	}
	return backends
}

// Healthy returns all healthy backends.
func (m *Manager) Healthy() []Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var healthy []Backend
	for _, b := range m.backends {
		if b.IsHealthy() {
			healthy = append(healthy, b)
		}
	}
	return healthy
}

// StartAll starts all backends.
func (m *Manager) StartAll(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, backend := range m.backends {
		if err := backend.Start(ctx); err != nil {
			return fmt.Errorf("failed to start backend %s: %w", backend.Name(), err)
		}
	}
	return nil
}

// StopAll stops all backends.
func (m *Manager) StopAll(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	for _, backend := range m.backends {
		if err := backend.Stop(ctx); err != nil {
			lastErr = fmt.Errorf("failed to stop backend %s: %w", backend.Name(), err)
		}
	}
	return lastErr
}

// Stats returns statistics for all backends.
func (m *Manager) Stats() []Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make([]Stats, 0, len(m.backends))
	for _, b := range m.backends {
		stats = append(stats, b.Stats())
	}
	return stats
}
