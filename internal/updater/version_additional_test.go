package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion_String(t *testing.T) {
	tests := []struct {
		name    string
		version Version
		want    string
	}{
		{
			name:    "simple version",
			version: Version{Major: 1, Minor: 2, Patch: 3},
			want:    "1.2.3",
		},
		{
			name:    "version with prerelease",
			version: Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc1"},
			want:    "1.2.3-rc1",
		},
		{
			name:    "zero version",
			version: Version{Major: 0, Minor: 0, Patch: 0},
			want:    "0.0.0",
		},
		{
			name:    "prerelease with dots",
			version: Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "beta.1"},
			want:    "1.0.0-beta.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.version.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVersion_IsPrerelease(t *testing.T) {
	tests := []struct {
		name    string
		version Version
		want    bool
	}{
		{
			name:    "stable version",
			version: Version{Major: 1, Minor: 2, Patch: 3},
			want:    false,
		},
		{
			name:    "prerelease version",
			version: Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc1"},
			want:    true,
		},
		{
			name:    "empty prerelease",
			version: Version{Major: 1, Minor: 0, Patch: 0, Prerelease: ""},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.version.IsPrerelease()
			assert.Equal(t, tt.want, got)
		})
	}
}
