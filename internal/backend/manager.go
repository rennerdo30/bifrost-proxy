package backend

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
)

// backendNamePattern matches valid backend names: alphanumeric, hyphens, underscores.
var backendNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// reservedNames contains backend names that are reserved for internal use.
var reservedNames = map[string]bool{
	"all":  true,
	"none": true,
	"any":  true,
}

// ValidateName validates a backend name.
// Valid names contain only alphanumeric characters, hyphens, and underscores,
// and must start with an alphanumeric character. Reserved names are not allowed.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: backend name cannot be empty", ErrBackendInvalid)
	}
	if reservedNames[name] {
		return fmt.Errorf("%w: backend name %q is reserved", ErrBackendInvalid, name)
	}
	if !backendNamePattern.MatchString(name) {
		return fmt.Errorf("%w: backend name %q must contain only alphanumeric characters, hyphens, and underscores, and must start with alphanumeric", ErrBackendInvalid, name)
	}
	return nil
}

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

	name := backend.Name()

	// Validate backend name
	if err := ValidateName(name); err != nil {
		return err
	}

	if _, exists := m.backends[name]; exists {
		return fmt.Errorf("%w: %s", ErrBackendExists, name)
	}

	m.backends[name] = backend
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
	// Copy backend list under lock, then operate without holding lock
	// to avoid blocking registration during slow start operations
	m.mu.RLock()
	backends := make([]Backend, 0, len(m.backends))
	for _, b := range m.backends {
		backends = append(backends, b)
	}
	m.mu.RUnlock()

	for _, b := range backends {
		if err := b.Start(ctx); err != nil {
			return fmt.Errorf("failed to start backend %s: %w", b.Name(), err)
		}
	}
	return nil
}

// StopAll stops all backends.
func (m *Manager) StopAll(ctx context.Context) error {
	// Copy backend list under lock, then operate without holding lock
	// to avoid blocking registration during slow stop operations
	m.mu.RLock()
	backends := make([]Backend, 0, len(m.backends))
	for _, b := range m.backends {
		backends = append(backends, b)
	}
	m.mu.RUnlock()

	var errs []error
	for _, b := range backends {
		if err := b.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop backend %s: %w", b.Name(), err))
		}
	}
	return errors.Join(errs...)
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
