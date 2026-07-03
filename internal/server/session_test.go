package server

import (
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

func TestBuildSessionManager_Memory(t *testing.T) {
	mgr, err := buildSessionManager(config.SessionConfig{
		Store:              "memory",
		Duration:           config.Duration(2 * time.Hour),
		MaxSessionsPerUser: 3,
	})
	if err != nil {
		t.Fatalf("buildSessionManager returned error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected a non-nil session manager")
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestBuildSessionManager_DefaultsToMemory(t *testing.T) {
	// An empty store type must default to the in-memory backend rather than
	// erroring, so the API session flow works out of the box.
	mgr, err := buildSessionManager(config.SessionConfig{})
	if err != nil {
		t.Fatalf("buildSessionManager returned error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected a non-nil session manager")
	}
	_ = mgr.Close() //nolint:errcheck // best effort in test
}

func TestBuildSessionManager_RedisUnreachableFailsClosed(t *testing.T) {
	// A Redis store pointed at an unreachable address must fail closed at build
	// time (mirrors the startup behavior) instead of returning a usable manager.
	_, err := buildSessionManager(config.SessionConfig{
		Store: "redis",
		Redis: config.RedisSessionConfig{
			Addr:      "127.0.0.1:1", // nothing listens here
			OpTimeout: config.Duration(500 * time.Millisecond),
		},
	})
	if err == nil {
		t.Fatal("expected an error for an unreachable redis session store")
	}
}
