package updater

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a semantic version.
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
}

// ParseVersion parses a version string (e.g., "v1.2.3", "1.2.3-rc1", "1.2.3-beta.1").
func ParseVersion(s string) (Version, error) {
	// Remove leading 'v' if present
	s = strings.TrimPrefix(s, "v")

	var v Version
	var mainPart string

	// Split prerelease suffix
	if idx := strings.IndexAny(s, "-+"); idx != -1 {
		mainPart = s[:idx]
		v.Prerelease = s[idx+1:]
	} else {
		mainPart = s
	}

	// Split major.minor.patch
	parts := strings.Split(mainPart, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return Version{}, fmt.Errorf("%w: %s", ErrInvalidVersion, s)
	}

	var err error
	v.Major, err = strconv.Atoi(parts[0])
	if err != nil {
		return Version{}, fmt.Errorf("%w: invalid major version", ErrInvalidVersion)
	}

	if len(parts) >= 2 {
		v.Minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return Version{}, fmt.Errorf("%w: invalid minor version", ErrInvalidVersion)
		}
	}

	if len(parts) >= 3 {
		v.Patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return Version{}, fmt.Errorf("%w: invalid patch version", ErrInvalidVersion)
		}
	}

	return v, nil
}

// String returns the version as a string (without leading 'v').
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	return s
}

// Compare compares two versions.
// Returns: -1 if v < other, 0 if equal, 1 if v > other.
func (v Version) Compare(other Version) int {
	// Compare major
	if v.Major < other.Major {
		return -1
	}
	if v.Major > other.Major {
		return 1
	}

	// Compare minor
	if v.Minor < other.Minor {
		return -1
	}
	if v.Minor > other.Minor {
		return 1
	}

	// Compare patch
	if v.Patch < other.Patch {
		return -1
	}
	if v.Patch > other.Patch {
		return 1
	}

	// Compare prerelease
	// No prerelease > prerelease (1.0.0 > 1.0.0-rc1)
	if v.Prerelease == "" && other.Prerelease != "" {
		return 1
	}
	if v.Prerelease != "" && other.Prerelease == "" {
		return -1
	}

	// Both have prerelease, compare lexicographically
	if v.Prerelease < other.Prerelease {
		return -1
	}
	if v.Prerelease > other.Prerelease {
		return 1
	}

	return 0
}

// IsNewerThan returns true if v is newer than other.
func (v Version) IsNewerThan(other Version) bool {
	return v.Compare(other) > 0
}

// IsPrerelease returns true if this is a prerelease version.
func (v Version) IsPrerelease() bool {
	return v.Prerelease != ""
}
