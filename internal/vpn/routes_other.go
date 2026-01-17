//go:build !linux && !darwin && !windows

package vpn

import (
	"context"
	"errors"
)

// noopRouteManager is a no-op implementation for unsupported platforms.
type noopRouteManager struct{}

func newPlatformRouteManager() RouteManager {
	return &noopRouteManager{}
}

func (n *noopRouteManager) Setup(ctx context.Context, tunName string, cfg Config) error {
	return errors.New("route management not supported on this platform")
}

func (n *noopRouteManager) Cleanup(ctx context.Context) error {
	return nil
}

func (n *noopRouteManager) AddBypassRoute(destination string) error {
	return errors.New("route management not supported on this platform")
}

func (n *noopRouteManager) RemoveBypassRoute(destination string) error {
	return errors.New("route management not supported on this platform")
}
