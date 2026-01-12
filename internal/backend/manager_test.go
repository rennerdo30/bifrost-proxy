package backend

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	assert.NotNil(t, m)
	assert.NotNil(t, m.backends)
	assert.Empty(t, m.backends)
}

func TestManager_Add(t *testing.T) {
	m := NewManager()

	backend := NewDirectBackend(DirectConfig{Name: "test"})
	err := m.Add(backend)
	require.NoError(t, err)

	// Verify it was added
	got, err := m.Get("test")
	require.NoError(t, err)
	assert.Equal(t, backend, got)
}

func TestManager_Add_Duplicate(t *testing.T) {
	m := NewManager()

	backend1 := NewDirectBackend(DirectConfig{Name: "test"})
	backend2 := NewDirectBackend(DirectConfig{Name: "test"})

	err := m.Add(backend1)
	require.NoError(t, err)

	err = m.Add(backend2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestManager_Get_NotFound(t *testing.T) {
	m := NewManager()

	_, err := m.Get("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_Remove(t *testing.T) {
	m := NewManager()

	backend := NewDirectBackend(DirectConfig{Name: "test"})
	m.Add(backend)

	err := m.Remove("test")
	require.NoError(t, err)

	// Verify it was removed
	_, err = m.Get("test")
	assert.Error(t, err)
}

func TestManager_Remove_NotFound(t *testing.T) {
	m := NewManager()

	err := m.Remove("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_List(t *testing.T) {
	m := NewManager()

	m.Add(NewDirectBackend(DirectConfig{Name: "backend1"}))
	m.Add(NewDirectBackend(DirectConfig{Name: "backend2"}))
	m.Add(NewDirectBackend(DirectConfig{Name: "backend3"}))

	names := m.List()
	assert.Len(t, names, 3)
	assert.Contains(t, names, "backend1")
	assert.Contains(t, names, "backend2")
	assert.Contains(t, names, "backend3")
}

func TestManager_List_Empty(t *testing.T) {
	m := NewManager()
	names := m.List()
	assert.Empty(t, names)
}

func TestManager_All(t *testing.T) {
	m := NewManager()

	b1 := NewDirectBackend(DirectConfig{Name: "backend1"})
	b2 := NewDirectBackend(DirectConfig{Name: "backend2"})
	m.Add(b1)
	m.Add(b2)

	all := m.All()
	assert.Len(t, all, 2)
}

func TestManager_Healthy(t *testing.T) {
	m := NewManager()

	// Add a backend and start it (makes it healthy)
	b1 := NewDirectBackend(DirectConfig{Name: "healthy"})
	b2 := NewDirectBackend(DirectConfig{Name: "unhealthy"})
	m.Add(b1)
	m.Add(b2)

	ctx := context.Background()
	b1.Start(ctx)
	// b2 not started, so unhealthy

	healthy := m.Healthy()
	assert.Len(t, healthy, 1)
	assert.Equal(t, "healthy", healthy[0].Name())
}

func TestManager_Healthy_NoneHealthy(t *testing.T) {
	m := NewManager()

	m.Add(NewDirectBackend(DirectConfig{Name: "test"}))

	healthy := m.Healthy()
	assert.Empty(t, healthy)
}

func TestManager_StartAll(t *testing.T) {
	m := NewManager()

	b1 := NewDirectBackend(DirectConfig{Name: "backend1"})
	b2 := NewDirectBackend(DirectConfig{Name: "backend2"})
	m.Add(b1)
	m.Add(b2)

	ctx := context.Background()
	err := m.StartAll(ctx)
	require.NoError(t, err)

	assert.True(t, b1.IsHealthy())
	assert.True(t, b2.IsHealthy())
}

func TestManager_StopAll(t *testing.T) {
	m := NewManager()

	b1 := NewDirectBackend(DirectConfig{Name: "backend1"})
	b2 := NewDirectBackend(DirectConfig{Name: "backend2"})
	m.Add(b1)
	m.Add(b2)

	ctx := context.Background()
	m.StartAll(ctx)

	err := m.StopAll(ctx)
	require.NoError(t, err)

	assert.False(t, b1.IsHealthy())
	assert.False(t, b2.IsHealthy())
}

func TestManager_Stats(t *testing.T) {
	m := NewManager()

	b1 := NewDirectBackend(DirectConfig{Name: "backend1"})
	b2 := NewDirectBackend(DirectConfig{Name: "backend2"})
	m.Add(b1)
	m.Add(b2)

	ctx := context.Background()
	b1.Start(ctx)

	stats := m.Stats()
	assert.Len(t, stats, 2)

	// Find the healthy one
	var foundHealthy bool
	for _, s := range stats {
		if s.Name == "backend1" {
			assert.True(t, s.Healthy)
			foundHealthy = true
		}
	}
	assert.True(t, foundHealthy)
}

func TestManager_Concurrency(t *testing.T) {
	m := NewManager()

	// Add backends concurrently
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			name := string(rune('A' + id))
			b := NewDirectBackend(DirectConfig{Name: name})
			m.Add(b)
			done <- struct{}{}
		}(i)
	}

	// Wait for all
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for concurrent adds")
		}
	}

	// Should have some backends (exact number depends on race)
	backends := m.All()
	assert.NotEmpty(t, backends)
}
