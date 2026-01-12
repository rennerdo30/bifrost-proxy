package matcher

import "testing"

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
		{"exact no match", []string{"example.com"}, "other.com", false},
		{"exact no match subdomain", []string{"example.com"}, "sub.example.com", false},

		// Wildcard match (*.domain.com)
		{"wildcard match", []string{"*.example.com"}, "sub.example.com", true},
		{"wildcard match deep", []string{"*.example.com"}, "a.b.example.com", true},
		{"wildcard no match exact", []string{"*.example.com"}, "example.com", false},
		{"wildcard no match other", []string{"*.example.com"}, "other.com", false},

		// Suffix match (.domain.com)
		{"suffix match exact", []string{".example.com"}, "example.com", true},
		{"suffix match sub", []string{".example.com"}, "sub.example.com", true},
		{"suffix match deep", []string{".example.com"}, "a.b.example.com", true},
		{"suffix no match", []string{".example.com"}, "notexample.com", false},

		// Universal wildcard
		{"universal wildcard", []string{"*"}, "any.domain.com", true},
		{"universal wildcard simple", []string{"*"}, "localhost", true},

		// Multiple patterns
		{"multi first match", []string{"a.com", "b.com"}, "a.com", true},
		{"multi second match", []string{"a.com", "b.com"}, "b.com", true},
		{"multi no match", []string{"a.com", "b.com"}, "c.com", false},

		// Edge cases
		{"with port", []string{"example.com"}, "example.com:443", true},
		{"empty domain", []string{"example.com"}, "", false},
		{"whitespace handling", []string{" example.com "}, "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.patterns)
			if got := m.Match(tt.domain); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestMatcherPatterns(t *testing.T) {
	patterns := []string{"a.com", "*.b.com", ".c.com"}
	m := New(patterns)

	got := m.Patterns()
	if len(got) != len(patterns) {
		t.Errorf("Patterns() returned %d patterns, want %d", len(got), len(patterns))
	}
}

func TestMatcherClear(t *testing.T) {
	m := New([]string{"example.com"})
	if !m.Match("example.com") {
		t.Error("Match should return true before clear")
	}

	m.Clear()

	if m.Match("example.com") {
		t.Error("Match should return false after clear")
	}
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
