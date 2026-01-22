//go:build !windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rennerdo30/bifrost-proxy/internal/logging"
)

func run(name string, runner Runner) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	if err := runner.Start(ctx); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			logging.Info("Received SIGHUP, reloading configuration...")
			if reloader, ok := runner.(Reloader); ok {
				if err := reloader.ReloadConfig(); err != nil {
					logging.Error("Config reload failed: %v", err)
				}
			} else {
				logging.Info("SIGHUP received but service does not support reload")
			}
		case syscall.SIGINT, syscall.SIGTERM:
			logging.Info("Received shutdown signal")
			cancel()
			return runner.Stop(context.Background())
		}
	}
}
