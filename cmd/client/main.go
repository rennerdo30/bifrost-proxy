// Package main provides the Bifrost client entry point.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/rennerdo30/bifrost-proxy/internal/client"
	clicmd "github.com/rennerdo30/bifrost-proxy/internal/cli/client"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/updater"
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

	// Add update commands
	rootCmd.AddCommand(newUpdateCommand())
}

// Update command flags
var (
	updateForce   bool
	updateChannel string
)

func newUpdateCommand() *cobra.Command {
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Check for and install updates",
		Long:  `Check for new versions of bifrost-client and optionally install updates.`,
		RunE:  runUpdate,
	}

	updateCheckCmd := &cobra.Command{
		Use:   "check",
		Short: "Check if updates are available",
		RunE:  runUpdateCheck,
	}

	updateInstallCmd := &cobra.Command{
		Use:   "install",
		Short: "Download and install the latest update",
		RunE:  runUpdateInstall,
	}

	updateCmd.PersistentFlags().BoolVarP(&updateForce, "force", "f", false, "Force update even if same version")
	updateCmd.PersistentFlags().StringVar(&updateChannel, "channel", "stable", "Release channel (stable, prerelease)")

	updateCmd.AddCommand(updateCheckCmd, updateInstallCmd)

	return updateCmd
}

func runUpdateCheck(cmd *cobra.Command, args []string) error {
	cfg := updater.Config{
		Enabled:     true,
		Channel:     updater.Channel(updateChannel),
		GitHubOwner: "rennerdo30",
		GitHubRepo:  "bifrost-proxy",
	}

	u, err := updater.New(cfg, updater.BinaryTypeClient, nil)
	if err != nil {
		return fmt.Errorf("create updater: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := u.CheckForUpdate(ctx)
	if err != nil {
		if errors.Is(err, updater.ErrNoUpdateAvailable) {
			fmt.Printf("Current version %s is up to date.\n", version.Short())
			return nil
		}
		return fmt.Errorf("check for update: %w", err)
	}

	fmt.Printf("Update available!\n")
	fmt.Printf("  Current version: %s\n", info.CurrentVersion)
	fmt.Printf("  New version:     %s\n", info.NewVersion)
	fmt.Printf("  Published:       %s\n", info.PublishedAt.Format(time.RFC1123))
	fmt.Printf("  Release URL:     %s\n", info.ReleaseURL)
	fmt.Printf("\nRun 'bifrost-client update install' to install.\n")

	return nil
}

func runUpdateInstall(cmd *cobra.Command, args []string) error {
	cfg := updater.Config{
		Enabled:     true,
		Channel:     updater.Channel(updateChannel),
		GitHubOwner: "rennerdo30",
		GitHubRepo:  "bifrost-proxy",
	}

	u, err := updater.New(cfg, updater.BinaryTypeClient, nil)
	if err != nil {
		return fmt.Errorf("create updater: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Check for update first
	info, err := u.CheckForUpdate(ctx)
	if err != nil {
		if errors.Is(err, updater.ErrNoUpdateAvailable) && !updateForce {
			fmt.Printf("Already running latest version %s.\n", version.Short())
			return nil
		}
		if !updateForce {
			return fmt.Errorf("check for update: %w", err)
		}
	}

	fmt.Printf("Downloading %s (%d MB)...\n", info.NewVersion, info.AssetSize/(1024*1024))

	// Progress callback
	lastPct := -1
	progress := func(downloaded, total int64) {
		if total <= 0 {
			return
		}
		pct := int(float64(downloaded) / float64(total) * 100)
		if pct != lastPct {
			fmt.Printf("\rDownloading: %d%% (%d/%d MB)", pct, downloaded/(1024*1024), total/(1024*1024))
			lastPct = pct
		}
	}

	if err := u.Install(ctx, info, progress); err != nil {
		return fmt.Errorf("install failed: %w", err)
	}

	fmt.Printf("\n\nUpdate installed successfully!\n")
	fmt.Printf("Please restart bifrost-client to use version %s.\n", info.NewVersion)

	return nil
}

func runUpdate(cmd *cobra.Command, args []string) error {
	cfg := updater.Config{
		Enabled:     true,
		Channel:     updater.Channel(updateChannel),
		GitHubOwner: "rennerdo30",
		GitHubRepo:  "bifrost-proxy",
	}

	u, err := updater.New(cfg, updater.BinaryTypeClient, nil)
	if err != nil {
		return fmt.Errorf("create updater: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := u.CheckForUpdate(ctx)
	if err != nil {
		if errors.Is(err, updater.ErrNoUpdateAvailable) {
			fmt.Printf("Current version %s is up to date.\n", version.Short())
			return nil
		}
		return fmt.Errorf("check for update: %w", err)
	}

	fmt.Printf("Update available!\n")
	fmt.Printf("  Current version: %s\n", info.CurrentVersion)
	fmt.Printf("  New version:     %s\n", info.NewVersion)
	fmt.Printf("  Published:       %s\n", info.PublishedAt.Format(time.RFC1123))
	fmt.Printf("\nWould you like to install this update? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response == "y" || response == "yes" {
		return runUpdateInstall(cmd, args)
	}

	fmt.Println("Update skipped.")
	return nil
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

	// Set config path so changes can be saved
	c.SetConfigPath(configFile)

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
