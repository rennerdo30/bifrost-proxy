//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/rennerdo30/bifrost-proxy/internal/logging"
)

// ShutdownTimeout is the maximum time allowed for graceful shutdown.
const ShutdownTimeout = 30 * time.Second

func run(name string, runner Runner) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		logging.Warn("Failed to detect if running as Windows Service, assuming interactive", "error", err)
		return runInteractive(name, runner)
	}

	if isService {
		return runService(name, runner)
	}

	return runInteractive(name, runner)
}

func runInteractive(name string, runner Runner) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if err := runner.Start(ctx); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	sig := <-sigChan
	logging.Info("Received shutdown signal", "signal", sig)
	cancel()
	// Use timeout context for graceful shutdown
	stopCtx, stopCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer stopCancel()
	return runner.Stop(stopCtx)
}

type serviceHandler struct {
	runner Runner
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := h.runner.Start(ctx); err != nil {
		logging.Error("Failed to start service", "error", err)
		return true, 1 // specificExitCode
	}

	s <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			s <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			logging.Info("Service stopping...")
			s <- svc.Status{State: svc.StopPending}
			cancel()
			// Use timeout context for graceful shutdown
			stopCtx, stopCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
			if err := h.runner.Stop(stopCtx); err != nil {
				logging.Error("Error stopping service", "error", err)
			}
			stopCancel()
			break loop
		default:
			logging.Warn("Unexpected service control request", "cmd", c)
		}
	}

	return false, 0
}

func runService(name string, runner Runner) error {
	return svc.Run(name, &serviceHandler{runner: runner})
}
