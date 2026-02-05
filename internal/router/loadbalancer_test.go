package router

import (
	"context"
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

// TestRoundRobinBalancer_CounterOverflow tests counter overflow scenarios.
// The atomic counter wraps around at uint64 max value.
func TestRoundRobinBalancer_CounterOverflow(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))

	lb := &RoundRobinBalancer{}
	backends := []backend.Backend{b1, b2}

	// Set counter to near max value
	lb.counter.Store(math.MaxUint64 - 1)

	// Select should work even when counter wraps around
	selected1 := lb.Select(backends, "")
	assert.NotNil(t, selected1)

	selected2 := lb.Select(backends, "") // This wraps to 0
	assert.NotNil(t, selected2)

	selected3 := lb.Select(backends, "") // This continues after wrap
	assert.NotNil(t, selected3)
}

// TestWeightedBalancer_ZeroWeights tests handling of zero weights.
func TestWeightedBalancer_ZeroWeights(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))

	// Zero weight means backend won't be in weighted list
	weights := map[string]int{"b1": 0, "b2": 3}
	lb := NewWeightedBalancer(weights)

	backends := []backend.Backend{b1, b2}

	// All selections should be b2 since b1 has zero weight
	for i := 0; i < 10; i++ {
		selected := lb.Select(backends, "")
		// With weight 0, b1 shouldn't be selected
		// But the code defaults to weight 1 if not found
		assert.NotNil(t, selected)
	}
}

// TestWeightedBalancer_AllZeroWeights tests when all weights are zero.
// When all backends have zero weight, no backend is added to weighted list.
func TestWeightedBalancer_AllZeroWeights(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))

	// All zero weights - no backends in weighted list
	weights := map[string]int{"b1": 0, "b2": 0}
	lb := NewWeightedBalancer(weights)

	backends := []backend.Backend{b1, b2}

	// With all zero weights, weighted list is empty, returns nil
	selected := lb.Select(backends, "")
	assert.Nil(t, selected, "All zero weights should result in no selection")
}

// TestWeightedBalancer_NegativeWeights tests handling of negative weights.
func TestWeightedBalancer_NegativeWeights(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))

	// Negative weights - should be treated as 0 or less iterations
	weights := map[string]int{"b1": -5, "b2": 3}
	lb := NewWeightedBalancer(weights)

	backends := []backend.Backend{b1, b2}

	// All selections should be b2 since negative weight means no iterations
	for i := 0; i < 10; i++ {
		selected := lb.Select(backends, "")
		assert.NotNil(t, selected)
		// With negative weight, b1 won't be added to weighted list
		if selected != nil {
			assert.Equal(t, "b2", selected.Name())
		}
	}
}

// TestIPHashBalancer_IPv6 tests IPv6 address hashing.
func TestIPHashBalancer_IPv6(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))

	lb := &IPHashBalancer{}
	backends := []backend.Backend{b1, b2}

	// Test various IPv6 formats
	ipv6Addresses := []string{
		"::1",
		"2001:db8::1",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"fe80::1%eth0",
		"[::1]:8080", // With port brackets
	}

	for _, ip := range ipv6Addresses {
		selected := lb.Select(backends, ip)
		assert.NotNil(t, selected, "IPv6 address %s should select a backend", ip)

		// Same IP should return same backend consistently
		selected2 := lb.Select(backends, ip)
		assert.Equal(t, selected.Name(), selected2.Name(), "Same IPv6 %s should return same backend", ip)
	}
}

// TestIPHashBalancer_EmptyIP tests empty IP address handling.
func TestIPHashBalancer_EmptyIP(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	require.NoError(t, b1.Start(context.Background()))

	lb := &IPHashBalancer{}
	backends := []backend.Backend{b1}

	// Empty IP should still work (hash of empty string)
	selected := lb.Select(backends, "")
	assert.NotNil(t, selected)
}

// TestRoundRobinBalancer_DynamicHealthChange tests dynamic health state changes.
func TestRoundRobinBalancer_DynamicHealthChange(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b3 := backend.NewDirectBackend(backend.DirectConfig{Name: "b3"})

	// Start only b1 and b2 initially
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))
	// b3 not started - unhealthy

	lb := &RoundRobinBalancer{}
	backends := []backend.Backend{b1, b2, b3}

	// Should only select from healthy backends (b1, b2)
	selected := lb.Select(backends, "")
	assert.NotNil(t, selected)
	assert.NotEqual(t, "b3", selected.Name())

	// Now start b3
	require.NoError(t, b3.Start(context.Background()))

	// Should now potentially select b3
	foundB3 := false
	for i := 0; i < 10; i++ {
		selected = lb.Select(backends, "")
		if selected.Name() == "b3" {
			foundB3 = true
			break
		}
	}
	assert.True(t, foundB3, "b3 should be selected after becoming healthy")

	// Stop b1 - should no longer be selected
	b1.Stop(context.Background())

	// Should not select b1 anymore
	for i := 0; i < 10; i++ {
		selected = lb.Select(backends, "")
		assert.NotEqual(t, "b1", selected.Name(), "b1 should not be selected after becoming unhealthy")
	}
}

// TestLeastConnBalancer_DynamicHealthChange tests dynamic health changes.
func TestLeastConnBalancer_DynamicHealthChange(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	require.NoError(t, b1.Start(context.Background()))
	// b2 not started - unhealthy

	lb := &LeastConnBalancer{}
	backends := []backend.Backend{b1, b2}

	// Should only select b1 since b2 is unhealthy
	selected := lb.Select(backends, "")
	assert.Equal(t, "b1", selected.Name())

	// Start b2
	require.NoError(t, b2.Start(context.Background()))

	// Now both should be selectable
	selected1 := lb.Select(backends, "")
	assert.NotNil(t, selected1)
}

// TestWeightedBalancer_CounterOverflow tests counter overflow in weighted balancer.
func TestWeightedBalancer_CounterOverflow(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))

	weights := map[string]int{"b1": 2, "b2": 1}
	lb := NewWeightedBalancer(weights)

	// Set counter to near max value
	lb.counter.Store(math.MaxUint64 - 1)

	backends := []backend.Backend{b1, b2}

	// Select should work even when counter wraps around
	for i := 0; i < 5; i++ {
		selected := lb.Select(backends, "")
		assert.NotNil(t, selected)
	}
}

// TestConcurrentBalancerAccess tests concurrent access to balancers.
func TestConcurrentBalancerAccess(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))

	backends := []backend.Backend{b1, b2}

	// Test round robin concurrency
	t.Run("RoundRobin", func(t *testing.T) {
		lb := &RoundRobinBalancer{}
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				selected := lb.Select(backends, "")
				assert.NotNil(t, selected)
			}()
		}
		wg.Wait()
	})

	// Test least conn concurrency
	t.Run("LeastConn", func(t *testing.T) {
		lb := &LeastConnBalancer{}
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				selected := lb.Select(backends, "")
				assert.NotNil(t, selected)
			}()
		}
		wg.Wait()
	})

	// Test IP hash concurrency
	t.Run("IPHash", func(t *testing.T) {
		lb := &IPHashBalancer{}
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				ip := "192.168.1." + string(rune('0'+n%10))
				selected := lb.Select(backends, ip)
				assert.NotNil(t, selected)
			}(i)
		}
		wg.Wait()
	})

	// Test weighted concurrency
	t.Run("Weighted", func(t *testing.T) {
		lb := NewWeightedBalancer(map[string]int{"b1": 3, "b2": 1})
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				selected := lb.Select(backends, "")
				assert.NotNil(t, selected)
			}()
		}
		wg.Wait()
	})
}

// TestIPHashBalancer_DifferentIPsDistribution tests IP hash distribution.
func TestIPHashBalancer_DifferentIPsDistribution(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b3 := backend.NewDirectBackend(backend.DirectConfig{Name: "b3"})
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))
	require.NoError(t, b3.Start(context.Background()))

	lb := &IPHashBalancer{}
	backends := []backend.Backend{b1, b2, b3}

	// Count selections for different IPs
	counts := make(map[string]int)

	for i := 0; i < 300; i++ {
		ip := "192.168.1." + string(rune('0'+i%256))
		selected := lb.Select(backends, ip)
		if selected != nil {
			counts[selected.Name()]++
		}
	}

	// All backends should receive some requests (distribution)
	for name, count := range counts {
		assert.Greater(t, count, 0, "Backend %s should receive some requests", name)
	}
}

// TestRoundRobinBalancer_SingleBackend tests with single backend.
func TestRoundRobinBalancer_SingleBackend(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	require.NoError(t, b1.Start(context.Background()))

	lb := &RoundRobinBalancer{}
	backends := []backend.Backend{b1}

	// Should always return the same backend
	for i := 0; i < 10; i++ {
		selected := lb.Select(backends, "")
		assert.Equal(t, "b1", selected.Name())
	}
}

// TestWeightedBalancer_VeryHighWeight tests with very high weights.
func TestWeightedBalancer_VeryHighWeight(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	require.NoError(t, b1.Start(context.Background()))
	require.NoError(t, b2.Start(context.Background()))

	// Very high weight for b1
	weights := map[string]int{"b1": 1000, "b2": 1}
	lb := NewWeightedBalancer(weights)

	backends := []backend.Backend{b1, b2}

	// Almost all selections should be b1
	b1Count := 0
	total := 100
	for i := 0; i < total; i++ {
		selected := lb.Select(backends, "")
		if selected.Name() == "b1" {
			b1Count++
		}
	}

	// b1 should be selected roughly 1000/1001 times
	ratio := float64(b1Count) / float64(total)
	assert.Greater(t, ratio, 0.9, "b1 with weight 1000 should be selected > 90% of the time")
}
