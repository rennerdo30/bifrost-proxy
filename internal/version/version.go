// Package version provides build version information for Bifrost.
package version

import (
	"fmt"
	"runtime"
)

// Build-time variables injected via ldflags
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// String returns a full version string including commit and build time.
func String() string {
	return fmt.Sprintf("Bifrost %s (%s) built %s", Version, GitCommit, BuildTime)
}

// Short returns just the version number.
func Short() string {
	return Version
}

// Full returns version info with Go version.
func Full() string {
	return fmt.Sprintf("%s - Go %s %s/%s", String(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// Info contains structured version information.
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// GetInfo returns structured version information.
func GetInfo() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
