package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	result := String()

	// Should contain version, commit, and build time
	if !strings.Contains(result, "Bifrost") {
		t.Errorf("String() should contain 'Bifrost', got: %s", result)
	}
	if !strings.Contains(result, Version) {
		t.Errorf("String() should contain version %s, got: %s", Version, result)
	}
	if !strings.Contains(result, GitCommit) {
		t.Errorf("String() should contain commit %s, got: %s", GitCommit, result)
	}
	if !strings.Contains(result, BuildTime) {
		t.Errorf("String() should contain build time %s, got: %s", BuildTime, result)
	}
}

func TestShort(t *testing.T) {
	result := Short()

	if result != Version {
		t.Errorf("Short() = %s, want %s", result, Version)
	}
}

func TestFull(t *testing.T) {
	result := Full()

	// Should contain version string
	if !strings.Contains(result, String()) {
		t.Errorf("Full() should contain String() output, got: %s", result)
	}

	// Should contain Go version
	if !strings.Contains(result, runtime.Version()) {
		t.Errorf("Full() should contain Go version %s, got: %s", runtime.Version(), result)
	}

	// Should contain OS/arch
	if !strings.Contains(result, runtime.GOOS) {
		t.Errorf("Full() should contain GOOS %s, got: %s", runtime.GOOS, result)
	}
	if !strings.Contains(result, runtime.GOARCH) {
		t.Errorf("Full() should contain GOARCH %s, got: %s", runtime.GOARCH, result)
	}
}

func TestGetInfo(t *testing.T) {
	info := GetInfo()

	if info.Version != Version {
		t.Errorf("GetInfo().Version = %s, want %s", info.Version, Version)
	}
	if info.GitCommit != GitCommit {
		t.Errorf("GetInfo().GitCommit = %s, want %s", info.GitCommit, GitCommit)
	}
	if info.BuildTime != BuildTime {
		t.Errorf("GetInfo().BuildTime = %s, want %s", info.BuildTime, BuildTime)
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("GetInfo().GoVersion = %s, want %s", info.GoVersion, runtime.Version())
	}

	expectedPlatform := runtime.GOOS + "/" + runtime.GOARCH
	if info.Platform != expectedPlatform {
		t.Errorf("GetInfo().Platform = %s, want %s", info.Platform, expectedPlatform)
	}
}

func TestInfoStruct(t *testing.T) {
	// Test that Info struct can be created and all fields are accessible
	info := Info{
		Version:   "1.0.0",
		GitCommit: "abc123",
		BuildTime: "2024-01-01T00:00:00Z",
		GoVersion: "go1.21.0",
		Platform:  "linux/amd64",
	}

	if info.Version != "1.0.0" {
		t.Errorf("Info.Version = %s, want 1.0.0", info.Version)
	}
	if info.GitCommit != "abc123" {
		t.Errorf("Info.GitCommit = %s, want abc123", info.GitCommit)
	}
	if info.BuildTime != "2024-01-01T00:00:00Z" {
		t.Errorf("Info.BuildTime = %s, want 2024-01-01T00:00:00Z", info.BuildTime)
	}
	if info.GoVersion != "go1.21.0" {
		t.Errorf("Info.GoVersion = %s, want go1.21.0", info.GoVersion)
	}
	if info.Platform != "linux/amd64" {
		t.Errorf("Info.Platform = %s, want linux/amd64", info.Platform)
	}
}
