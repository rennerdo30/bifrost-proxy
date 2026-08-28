package client

import (
	"sync/atomic"
	"testing"
)

func TestClient_OpenQuickAccessUsesDesktopOverride(t *testing.T) {
	client := &Client{}
	var calls atomic.Int32
	client.SetOpenQuickHandler(func() { calls.Add(1) })

	client.openQuickAccess()

	if got := calls.Load(); got != 1 {
		t.Fatalf("quick-access handler called %d times, want 1", got)
	}
}
