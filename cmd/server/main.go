// Package main provides the Bifrost server entry point.
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

	clicmd "github.com/rennerdo30/bifrost-proxy/internal/cli/server"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/server"
	"github.com/rennerdo30/bifrost-proxy/internal/updater"
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
		Long:  `Check for new versions of bifrost-server and optionally install updates.`,
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

	u, err := updater.New(cfg, updater.BinaryTypeServer, nil)
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
	fmt.Printf("\nRun 'bifrost-server update install' to install.\n")

	return nil
}

func runUpdateInstall(cmd *cobra.Command, args []string) error {
	cfg := updater.Config{
		Enabled:     true,
		Channel:     updater.Channel(updateChannel),
		GitHubOwner: "rennerdo30",
		GitHubRepo:  "bifrost-proxy",
	}

	u, err := updater.New(cfg, updater.BinaryTypeServer, nil)
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
	fmt.Printf("Please restart bifrost-server to use version %s.\n", info.NewVersion)

	return nil
}

func runUpdate(cmd *cobra.Command, args []string) error {
	cfg := updater.Config{
		Enabled:     true,
		Channel:     updater.Channel(updateChannel),
		GitHubOwner: "rennerdo30",
		GitHubRepo:  "bifrost-proxy",
	}

	u, err := updater.New(cfg, updater.BinaryTypeServer, nil)
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
