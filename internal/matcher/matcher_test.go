package matcher

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatcher(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		domain   string
		want     bool
	}{
		// Exact match
		{"exact match", []string{"example.com"}, "example.com", true},
		{"exact match case insensitive", []string{"Example.COM"}, "example.com", true},
		{"exact match domain case insensitive", []string{"example.com"}, "Example.COM", true},
		{"exact no match", []string{"example.com"}, "other.com", false},
		{"exact no match subdomain", []string{"example.com"}, "sub.example.com", false},
		{"exact no match different parts", []string{"example.com"}, "example.org", false},
		{"exact match single part", []string{"localhost"}, "localhost", true},
		{"exact no match single part", []string{"localhost"}, "other", false},

		// Glob pattern match (prefix/suffix wildcards within parts)
		{"glob prefix match", []string{"sf-*.example.com"}, "sf-abc.example.com", true},
		{"glob prefix match multi char", []string{"sf-*.example.com"}, "sf-abcdef.example.com", true},
		{"glob prefix no match", []string{"sf-*.example.com"}, "other.example.com", false},
		{"glob prefix no match wrong prefix", []string{"sf-*.example.com"}, "xy-abc.example.com", false},
		{"glob suffix match", []string{"*-api.example.com"}, "backend-api.example.com", true},
		{"glob suffix match multi word", []string{"*-api.example.com"}, "my-backend-api.example.com", true},
		{"glob suffix no match", []string{"*-api.example.com"}, "backend-web.example.com", false},
		{"glob middle match", []string{"pre-*-suf.example.com"}, "pre-middle-suf.example.com", true},
		{"glob middle no match", []string{"pre-*-suf.example.com"}, "pre-middle-other.example.com", false},
		{"glob multiple wildcards", []string{"*-*-*.example.com"}, "a-b-c.example.com", true},
		{"glob single label pattern", []string{"sf-*"}, "sf-test", true},
		{"glob single label no match", []string{"sf-*"}, "other", false},
		{"glob with wildcard subdomain", []string{"*.sf-*.example.com"}, "sub.sf-abc.example.com", true},
		{"glob with suffix pattern", []string{".sf-*.example.com"}, "sf-abc.example.com", true},
		{"glob with suffix pattern sub", []string{".sf-*.example.com"}, "sub.sf-abc.example.com", true},

		// Wildcard match (*.domain.com)
		{"wildcard match", []string{"*.example.com"}, "sub.example.com", true},
		{"wildcard match deep", []string{"*.example.com"}, "a.b.example.com", true},
		{"wildcard no match exact", []string{"*.example.com"}, "example.com", false},
		{"wildcard no match other", []string{"*.example.com"}, "other.com", false},
		{"wildcard no match different suffix", []string{"*.example.com"}, "sub.example.org", false},
		{"wildcard no match same length wrong suffix", []string{"*.example.com"}, "sub.other.com", false},

		// Suffix match (.domain.com)
		{"suffix match exact", []string{".example.com"}, "example.com", true},
		{"suffix match sub", []string{".example.com"}, "sub.example.com", true},
		{"suffix match deep", []string{".example.com"}, "a.b.example.com", true},
		{"suffix no match", []string{".example.com"}, "notexample.com", false},
		{"suffix no match different domain", []string{".example.com"}, "example.org", false},
		{"suffix no match too short", []string{".sub.example.com"}, "example.com", false},
		{"suffix no match single part shorter", []string{".example.com"}, "com", false},

		// Universal wildcard
		{"universal wildcard", []string{"*"}, "any.domain.com", true},
		{"universal wildcard simple", []string{"*"}, "localhost", true},

		// Multiple patterns
		{"multi first match", []string{"a.com", "b.com"}, "a.com", true},
		{"multi second match", []string{"a.com", "b.com"}, "b.com", true},
		{"multi no match", []string{"a.com", "b.com"}, "c.com", false},
		{"multi mixed patterns", []string{"exact.com", "*.wild.com", ".suffix.com"}, "sub.wild.com", true},
		{"multi mixed patterns suffix", []string{"exact.com", "*.wild.com", ".suffix.com"}, "suffix.com", true},

		// Edge cases
		{"with port", []string{"example.com"}, "example.com:443", true},
		{"with port wildcard", []string{"*.example.com"}, "sub.example.com:7080", true},
		{"empty domain", []string{"example.com"}, "", false},
		{"whitespace domain", []string{"example.com"}, "   ", false},
		{"whitespace handling", []string{" example.com "}, "example.com", true},
		{"empty pattern ignored", []string{""}, "example.com", false},
		{"whitespace pattern ignored", []string{"   "}, "example.com", false},
		{"mixed empty and valid patterns", []string{"", "example.com", "   "}, "example.com", true},
		{"no patterns", []string{}, "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.patterns)
			got := m.Match(tt.domain)
			assert.Equal(t, tt.want, got, "Match(%q) should return %v", tt.domain, tt.want)
		})
	}
}

func TestNew(t *testing.T) {
	t.Run("creates matcher with patterns", func(t *testing.T) {
		patterns := []string{"a.com", "b.com", "*.c.com"}
		m := New(patterns)
		require.NotNil(t, m)
		assert.Len(t, m.Patterns(), 3)
	})

	t.Run("creates empty matcher", func(t *testing.T) {
		m := New(nil)
		require.NotNil(t, m)
		assert.Empty(t, m.Patterns())
	})

	t.Run("creates matcher with empty slice", func(t *testing.T) {
		m := New([]string{})
		require.NotNil(t, m)
		assert.Empty(t, m.Patterns())
	})
}

func TestAddPattern(t *testing.T) {
	t.Run("adds exact pattern", func(t *testing.T) {
		m := New(nil)
		m.AddPattern("example.com")
		assert.True(t, m.Match("example.com"))
		assert.False(t, m.Match("sub.example.com"))
	})

	t.Run("adds wildcard pattern", func(t *testing.T) {
		m := New(nil)
		m.AddPattern("*.example.com")
		assert.True(t, m.Match("sub.example.com"))
		assert.False(t, m.Match("example.com"))
	})

	t.Run("adds suffix pattern", func(t *testing.T) {
		m := New(nil)
		m.AddPattern(".example.com")
		assert.True(t, m.Match("example.com"))
		assert.True(t, m.Match("sub.example.com"))
	})

	t.Run("adds universal wildcard", func(t *testing.T) {
		m := New(nil)
		m.AddPattern("*")
		assert.True(t, m.Match("anything.com"))
		assert.True(t, m.Match("localhost"))
	})

	t.Run("ignores empty pattern", func(t *testing.T) {
		m := New(nil)
		m.AddPattern("")
		assert.Empty(t, m.Patterns())
	})

	t.Run("ignores whitespace-only pattern", func(t *testing.T) {
		m := New(nil)
		m.AddPattern("   ")
		assert.Empty(t, m.Patterns())
	})

	t.Run("trims whitespace from pattern", func(t *testing.T) {
		m := New(nil)
		m.AddPattern("  example.com  ")
		patterns := m.Patterns()
		require.Len(t, patterns, 1)
		assert.Equal(t, "example.com", patterns[0])
	})

	t.Run("lowercases pattern", func(t *testing.T) {
		m := New(nil)
		m.AddPattern("Example.COM")
		patterns := m.Patterns()
		require.Len(t, patterns, 1)
		assert.Equal(t, "example.com", patterns[0])
	})
}

func TestMatcherPatterns(t *testing.T) {
	t.Run("returns all patterns", func(t *testing.T) {
		patterns := []string{"a.com", "*.b.com", ".c.com"}
		m := New(patterns)

		got := m.Patterns()
		require.Len(t, got, len(patterns))
		assert.Equal(t, "a.com", got[0])
		assert.Equal(t, "*.b.com", got[1])
		assert.Equal(t, ".c.com", got[2])
	})

	t.Run("returns empty slice for no patterns", func(t *testing.T) {
		m := New(nil)
		got := m.Patterns()
		assert.Empty(t, got)
	})

	t.Run("returns copy not reference", func(t *testing.T) {
		m := New([]string{"example.com"})
		got := m.Patterns()
		got[0] = "modified.com"
		assert.Equal(t, "example.com", m.Patterns()[0])
	})
}

func TestMatcherClear(t *testing.T) {
	t.Run("clears all patterns", func(t *testing.T) {
		m := New([]string{"example.com", "*.test.com"})
		require.True(t, m.Match("example.com"))
		require.Len(t, m.Patterns(), 2)

		m.Clear()

		assert.False(t, m.Match("example.com"))
		assert.Empty(t, m.Patterns())
	})

	t.Run("clear on empty matcher", func(t *testing.T) {
		m := New(nil)
		m.Clear()
		assert.Empty(t, m.Patterns())
	})
}

func TestMatcherConcurrency(t *testing.T) {
	m := New([]string{"example.com", "*.test.com", ".suffix.org"})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)

		go func() {
			defer wg.Done()
			m.Match("example.com")
		}()

		go func() {
			defer wg.Done()
			m.Match("sub.test.com")
		}()

		go func() {
			defer wg.Done()
			m.Patterns()
		}()
	}

	wg.Wait()
}

func TestMatcherConcurrencyWithModification(t *testing.T) {
	m := New(nil)

	var wg sync.WaitGroup

	// Writers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m.AddPattern("domain" + string(rune('a'+i%26)) + ".com")
		}(i)
	}

	// Readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Match("example.com")
			m.Patterns()
		}()
	}

	wg.Wait()
}

func TestMatchEdgeCases(t *testing.T) {
	t.Run("domain with multiple colons (IPv6)", func(t *testing.T) {
		m := New([]string{"example.com"})
		// LastIndex of : will find the port separator correctly
		assert.True(t, m.Match("example.com:7080"))
	})

	t.Run("domain is just a colon", func(t *testing.T) {
		m := New([]string{""})
		assert.False(t, m.Match(":"))
	})

	t.Run("pattern with multiple dots", func(t *testing.T) {
		m := New([]string{"sub.domain.example.com"})
		assert.True(t, m.Match("sub.domain.example.com"))
		assert.False(t, m.Match("other.domain.example.com"))
	})

	t.Run("wildcard pattern matching exact domain length", func(t *testing.T) {
		m := New([]string{"*.example.com"})
		// Domain parts: [example, com] = 2
		// Pattern parts: [example, com] = 2
		// Should not match because wildcard requires at least one subdomain
		assert.False(t, m.Match("example.com"))
	})

	t.Run("suffix pattern matching shorter domain", func(t *testing.T) {
		m := New([]string{".a.b.c.com"})
		// Pattern has 4 parts: a, b, c, com
		// Domain has 2 parts: c, com
		// Should not match
		assert.False(t, m.Match("c.com"))
		assert.False(t, m.Match("b.c.com"))
		assert.True(t, m.Match("a.b.c.com"))
		assert.True(t, m.Match("x.a.b.c.com"))
	})
}

func BenchmarkMatcherExact(b *testing.B) {
	m := New([]string{"example.com"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match("example.com")
	}
}

func BenchmarkMatcherWildcard(b *testing.B) {
	m := New([]string{"*.example.com"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match("sub.example.com")
	}
}

func BenchmarkMatcherManyPatterns(b *testing.B) {
	patterns := make([]string, 100)
	for i := 0; i < 100; i++ {
		patterns[i] = "domain" + string(rune(i)) + ".com"
	}
	m := New(patterns)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match("domain50.com")
	}
}
