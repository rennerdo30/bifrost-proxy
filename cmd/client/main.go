// Package main provides the Bifrost client entry point.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/rennerdo30/bifrost-proxy/internal/client"
	clicmd "github.com/rennerdo30/bifrost-proxy/internal/cli/client"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/version"
)

var (
	configFile string
	rootCmd    = &cobra.Command{
		Use:   "bifrost-client",
		Short: "Bifrost Proxy Client",
		Long:  `Bifrost client provides a local proxy that routes traffic through the Bifrost server or directly.`,
		RunE:  run,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "client-config.yaml", "config file path")

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
			cfg := config.DefaultClientConfig()
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
	cfg := config.DefaultClientConfig()
	if err := config.LoadAndValidate(configFile, &cfg); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Create client
	c, err := client.New(&cfg)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start client
	if err := c.Start(ctx); err != nil {
		return fmt.Errorf("start client: %w", err)
	}

	// Wait for shutdown signal
	sig := <-sigChan
	logging.Info("Received signal", "signal", sig)

	cancel()
	return c.Stop(context.Background())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
