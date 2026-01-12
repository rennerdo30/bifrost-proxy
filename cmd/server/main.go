// Package main provides the Bifrost server entry point.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	clicmd "github.com/rennerdo30/bifrost-proxy/internal/cli/server"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/server"
	"github.com/rennerdo30/bifrost-proxy/internal/version"
)

var (
	configFile string
	rootCmd    = &cobra.Command{
		Use:   "bifrost-server",
		Short: "Bifrost Proxy Server",
		Long:  `Bifrost is a production-ready proxy server with support for WireGuard, OpenVPN, and upstream proxies.`,
		RunE:  run,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "server-config.yaml", "config file path")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.Full())
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultServerConfig()
			if err := config.LoadAndValidate(configFile, &cfg); err != nil {
				return fmt.Errorf("configuration invalid: %w", err)
			}
			fmt.Println("Configuration is valid")
			return nil
		},
	})

	// Add CLI control commands
	rootCmd.AddCommand(clicmd.NewCommands())
}

func run(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg := config.DefaultServerConfig()
	if err := config.LoadAndValidate(configFile, &cfg); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Create server
	srv, err := server.New(&cfg)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	// Set config path for hot reload support
	srv.SetConfigPath(configFile)

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Start server
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	// Wait for shutdown signal
	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			logging.Info("Received SIGHUP, reloading configuration...")
			if err := srv.ReloadConfig(); err != nil {
				logging.Error("Config reload failed: %v", err)
			}
		case syscall.SIGINT, syscall.SIGTERM:
			logging.Info("Received shutdown signal")
			cancel()
			return srv.Stop(context.Background())
		}
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
