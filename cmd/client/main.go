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

	// Config init flags
	initOutput       string
	initServer       string
	initProtocol     string
	initHTTPListen   string
	initSOCKS5Listen string
	initForce        bool

	rootCmd = &cobra.Command{
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

	// Add config commands
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management commands",
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a sample client configuration file",
		Long: `Generate a sample client configuration file with sensible defaults.

The generated configuration includes:
  - Local HTTP and SOCKS5 proxy listeners
  - Connection to the specified Bifrost server
  - Default routing rules (localhost direct, everything else through server)
  - Debug, logging, and Web UI settings`,
		RunE: runConfigInit,
	}

	initCmd.Flags().StringVarP(&initOutput, "output", "o", "client-config.yaml", "output file path")
	initCmd.Flags().StringVarP(&initServer, "server", "s", "", "server address (host:port) - required")
	initCmd.Flags().StringVarP(&initProtocol, "protocol", "p", "http", "server protocol (http or socks5)")
	initCmd.Flags().StringVar(&initHTTPListen, "http-listen", "127.0.0.1:3128", "HTTP proxy listen address")
	initCmd.Flags().StringVar(&initSOCKS5Listen, "socks5-listen", "127.0.0.1:1081", "SOCKS5 proxy listen address")
	initCmd.Flags().BoolVarP(&initForce, "force", "f", false, "overwrite existing file")

	configCmd.AddCommand(initCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	// Validate required flags
	if initServer == "" {
		return fmt.Errorf("server address is required (use --server or -s)")
	}

	// Validate protocol
	if initProtocol != "http" && initProtocol != "socks5" {
		return fmt.Errorf("protocol must be 'http' or 'socks5'")
	}

	// Check if output file exists
	if !initForce {
		if _, err := os.Stat(initOutput); err == nil {
			return fmt.Errorf("file %s already exists (use --force to overwrite)", initOutput)
		}
	}

	// Create config with defaults
	cfg := config.DefaultClientConfig()

	// Apply flag values
	cfg.Proxy.HTTP.Listen = initHTTPListen
	cfg.Proxy.SOCKS5.Listen = initSOCKS5Listen
	cfg.Server.Address = initServer
	cfg.Server.Protocol = initProtocol

	// Set up default routes
	cfg.Routes = []config.ClientRouteConfig{
		{
			Name:     "local",
			Domains:  []string{"localhost", "127.0.0.1", "*.local"},
			Action:   "direct",
			Priority: 100,
		},
		{
			Name:     "default",
			Domains:  []string{"*"},
			Action:   "server",
			Priority: 1,
		},
	}

	// Save configuration
	if err := config.Save(initOutput, &cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Generated client configuration: %s\n\n", initOutput)
	fmt.Println("Next steps:")
	fmt.Printf("  1. Review and customize the configuration\n")
	fmt.Printf("  2. Start the client: bifrost-client -c %s\n", initOutput)

	return nil
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
