package service

import "context"

// Runner defines the interface for a runnable service.
type Runner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// Reloader defines the interface for a service that supports config reload.
type Reloader interface {
	ReloadConfig() error
}

// Run executes the service.
// On Windows, it detects if running as a service and uses SCM.
// On other platforms (or interactive mode), it handles signals.
func Run(name string, runner Runner) error {
	return run(name, runner)
}
