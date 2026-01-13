package updater

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Version
		wantErr bool
	}{
		{
			name:  "simple version",
			input: "1.2.3",
			want:  Version{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:  "version with v prefix",
			input: "v1.2.3",
			want:  Version{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:  "prerelease version",
			input: "1.2.3-rc1",
			want:  Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc1"},
		},
		{
			name:  "prerelease with v prefix",
			input: "v1.0.0-beta.1",
			want:  Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "beta.1"},
		},
		{
			name:  "major only",
			input: "2",
			want:  Version{Major: 2, Minor: 0, Patch: 0},
		},
		{
			name:  "major.minor",
			input: "2.1",
			want:  Version{Major: 2, Minor: 1, Patch: 0},
		},
		{
			name:    "invalid",
			input:   "not-a-version",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want int
	}{
		{"equal", "1.0.0", "1.0.0", 0},
		{"major greater", "2.0.0", "1.0.0", 1},
		{"major less", "1.0.0", "2.0.0", -1},
		{"minor greater", "1.2.0", "1.1.0", 1},
		{"minor less", "1.1.0", "1.2.0", -1},
		{"patch greater", "1.0.2", "1.0.1", 1},
		{"patch less", "1.0.1", "1.0.2", -1},
		{"stable greater than prerelease", "1.0.0", "1.0.0-rc1", 1},
		{"prerelease less than stable", "1.0.0-rc1", "1.0.0", -1},
		{"prerelease comparison", "1.0.0-rc1", "1.0.0-beta", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, _ := ParseVersion(tt.v1)
			v2, _ := ParseVersion(tt.v2)
			if got := v1.Compare(v2); got != tt.want {
				t.Errorf("Version.Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionIsNewerThan(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want bool
	}{
		{"newer major", "2.0.0", "1.0.0", true},
		{"same version", "1.0.0", "1.0.0", false},
		{"older version", "1.0.0", "2.0.0", false},
		{"newer minor", "1.1.0", "1.0.0", true},
		{"newer patch", "1.0.1", "1.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, _ := ParseVersion(tt.v1)
			v2, _ := ParseVersion(tt.v2)
			if got := v1.IsNewerThan(v2); got != tt.want {
				t.Errorf("Version.IsNewerThan() = %v, want %v", got, tt.want)
			}
		})
	}
}
