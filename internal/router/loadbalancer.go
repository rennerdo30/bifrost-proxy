package router

import (
	"hash/fnv"
	"sync/atomic"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

// RoundRobinBalancer implements round-robin load balancing.
type RoundRobinBalancer struct {
	counter atomic.Uint64
}

// Select selects a backend using round-robin.
func (b *RoundRobinBalancer) Select(backends []backend.Backend, clientIP string) backend.Backend {
	if len(backends) == 0 {
		return nil
	}

	// Filter healthy backends
	var healthy []backend.Backend
	for _, be := range backends {
		if be.IsHealthy() {
			healthy = append(healthy, be)
		}
	}

	if len(healthy) == 0 {
		return nil
	}

	idx := b.counter.Add(1) % uint64(len(healthy))
	return healthy[idx]
}

// LeastConnBalancer implements least-connections load balancing.
type LeastConnBalancer struct{}

// Select selects the backend with the fewest active connections.
func (b *LeastConnBalancer) Select(backends []backend.Backend, clientIP string) backend.Backend {
	if len(backends) == 0 {
		return nil
	}

	var selected backend.Backend
	minConns := int64(-1)

	for _, be := range backends {
		if !be.IsHealthy() {
			continue
		}

		stats := be.Stats()
		if minConns == -1 || stats.ActiveConnections < minConns {
			minConns = stats.ActiveConnections
			selected = be
		}
	}

	return selected
}

// IPHashBalancer implements IP-hash load balancing for session persistence.
type IPHashBalancer struct{}

// Select selects a backend based on client IP hash.
func (b *IPHashBalancer) Select(backends []backend.Backend, clientIP string) backend.Backend {
	// Filter healthy backends
	var healthy []backend.Backend
	for _, be := range backends {
		if be.IsHealthy() {
			healthy = append(healthy, be)
		}
	}

	if len(healthy) == 0 {
		return nil
	}

	// Hash the client IP
	h := fnv.New32a()
	h.Write([]byte(clientIP))
	hash := h.Sum32()

	idx := hash % uint32(len(healthy)) //nolint:gosec // G115: len(healthy) is always positive and small
	return healthy[idx]
}

// WeightedBalancer implements weighted load balancing.
type WeightedBalancer struct {
	weights map[string]int
	counter atomic.Uint64
}

// NewWeightedBalancer creates a new weighted balancer.
func NewWeightedBalancer(weights map[string]int) *WeightedBalancer {
	return &WeightedBalancer{
		weights: weights,
	}
}

// Select selects a backend using weighted round-robin.
func (b *WeightedBalancer) Select(backends []backend.Backend, clientIP string) backend.Backend {
	if len(backends) == 0 {
		return nil
	}

	// Build weighted list
	var weighted []backend.Backend
	for _, be := range backends {
		if !be.IsHealthy() {
			continue
		}

		weight := 1
		if w, ok := b.weights[be.Name()]; ok {
			weight = w
		}

		for i := 0; i < weight; i++ {
			weighted = append(weighted, be)
		}
	}

	if len(weighted) == 0 {
		return nil
	}

	idx := b.counter.Add(1) % uint64(len(weighted))
	return weighted[idx]
}
