package session_test

import (
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/session"
)

func TestNewStore_MemoryDefault(t *testing.T) {
	for _, typ := range []string{"", "memory"} {
		store, err := session.NewStore(session.StoreOptions{Type: typ})
		if err != nil {
			t.Fatalf("type %q: unexpected error: %v", typ, err)
		}
		if store == nil {
			t.Fatalf("type %q: expected non-nil store", typ)
		}
		if err := store.Close(); err != nil {
			t.Errorf("type %q: close: %v", typ, err)
		}
	}
}

func TestNewStore_Unknown(t *testing.T) {
	_, err := session.NewStore(session.StoreOptions{Type: "bogus"})
	if err == nil {
		t.Fatal("expected error for unknown store type")
	}
}

func TestBuildManager_Memory(t *testing.T) {
	mgr, err := session.BuildManager(
		session.StoreOptions{Type: "memory", CleanupInterval: time.Minute},
		session.DefaultManagerConfig(),
	)
	if err != nil {
		t.Fatalf("BuildManager: %v", err)
	}
	defer func() {
		if cerr := mgr.Close(); cerr != nil {
			t.Errorf("close: %v", cerr)
		}
	}()

	// Exercise the manager end-to-end to prove the store is wired in.
	sess, err := mgr.CreateSession(&auth.UserInfo{Username: "dave"}, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := mgr.ValidateSession(sess.ID)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if got.Username != "dave" {
		t.Errorf("expected dave, got %s", got.Username)
	}
}

func TestBuildManager_UnknownStoreFailsClosed(t *testing.T) {
	_, err := session.BuildManager(
		session.StoreOptions{Type: "bogus"},
		session.DefaultManagerConfig(),
	)
	if err == nil {
		t.Fatal("expected BuildManager to fail for unknown store type")
	}
}
