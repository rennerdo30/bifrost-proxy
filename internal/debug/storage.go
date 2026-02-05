package debug

import (
	"sync"
)

// Storage provides ring buffer storage for debug entries.
type Storage struct {
	entries  []Entry
	capacity int
	head     int
	count    int
	mu       sync.RWMutex
}

// NewStorage creates a new storage with the given capacity.
func NewStorage(capacity int) *Storage {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Storage{
		entries:  make([]Entry, capacity),
		capacity: capacity,
	}
}

// Add adds an entry to the storage.
func (s *Storage) Add(entry Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[s.head] = entry
	s.head = (s.head + 1) % s.capacity
	if s.count < s.capacity {
		s.count++
	}
}

// GetAll returns all entries, oldest first.
func (s *Storage) GetAll() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Entry, s.count)
	if s.count == 0 {
		return result
	}

	// Start from the oldest entry
	start := 0
	if s.count == s.capacity {
		start = s.head
	}

	for i := 0; i < s.count; i++ {
		idx := (start + i) % s.capacity
		result[i] = s.entries[idx]
	}

	return result
}

// GetLast returns the last n entries, newest first.
func (s *Storage) GetLast(n int) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if n > s.count {
		n = s.count
	}

	result := make([]Entry, n)
	for i := 0; i < n; i++ {
		idx := (s.head - 1 - i + s.capacity) % s.capacity
		result[i] = s.entries[idx]
	}

	return result
}

// Count returns the number of entries.
func (s *Storage) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// Clear removes all entries.
func (s *Storage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.head = 0
	s.count = 0
}

// Find searches for entries matching a filter.
func (s *Storage) Find(filter func(Entry) bool) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Entry
	start := 0
	if s.count == s.capacity {
		start = s.head
	}

	for i := 0; i < s.count; i++ {
		idx := (start + i) % s.capacity
		if filter(s.entries[idx]) {
			result = append(result, s.entries[idx])
		}
	}

	return result
}
