// Package main provides the Bifrost server entry point.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	clicmd "github.com/rennerdo30/bifrost-proxy/internal/cli/server"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/server"
	"github.com/rennerdo30/bifrost-proxy/internal/service"
	"github.com/rennerdo30/bifrost-proxy/internal/updater"
	"github.com/rennerdo30/bifrost-proxy/internal/version"

	// Auth plugins - blank imports to register via init()
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/mfa"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/apikey"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/hotp"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/jwt"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/kerberos"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ldap"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/mtls"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/native"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/none"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ntlm"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/oauth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/system"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/totp"
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

	// Add service commands
	rootCmd.AddCommand(newServiceCommand())
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

func getUpdaterConfig(cmd *cobra.Command) updater.Config {
	// Start with defaults
	serverCfg := config.DefaultServerConfig()

	// Try to load config file
	if err := config.Load(configFile, &serverCfg); err != nil {
		// If config load fails, we proceed with defaults
		// This ensures update commands work even without a valid config file
		logging.Debug("Failed to load config for update check", "error", err)
	}

	// Determine channel
	channel := serverCfg.AutoUpdate.Channel
	if channel == "" {
		channel = "stable"
	}

	// If CLI flag was explicitly defined, it takes precedence
	if cmd.Flags().Changed("channel") {
		channel = updateChannel
	}

	return updater.Config{
		Enabled:     true,
		Channel:     updater.Channel(channel),
		GitHubOwner: "rennerdo30",
		GitHubRepo:  "bifrost-proxy",
	}
}

func runUpdateCheck(cmd *cobra.Command, args []string) error {
	cfg := getUpdaterConfig(cmd)

	u, err := updater.New(cfg, updater.BinaryTypeServer, nil)
	if err != nil {
		return fmt.Errorf("create updater: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := u.CheckForUpdate(ctx)
	if err != nil {
		if errors.Is(err, updater.ErrNoUpdateAvailable) {
			fmt.Printf("Current version %s is up to date (Channel: %s).\n", version.Short(), cfg.Channel)
			return nil
		}
		return fmt.Errorf("check for update: %w", err)
	}

	fmt.Printf("Update available!\n")
	fmt.Printf("  Channel:         %s\n", cfg.Channel)
	fmt.Printf("  Current version: %s\n", info.CurrentVersion)
	fmt.Printf("  New version:     %s\n", info.NewVersion)
	fmt.Printf("  Published:       %s\n", info.PublishedAt.Format(time.RFC1123))
	fmt.Printf("  Release URL:     %s\n", info.ReleaseURL)
	fmt.Printf("\nRun 'bifrost-server update install' to install.\n")

	return nil
}

func runUpdateInstall(cmd *cobra.Command, args []string) error {
	cfg := getUpdaterConfig(cmd)

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
			fmt.Printf("Already running latest version %s (Channel: %s).\n", version.Short(), cfg.Channel)
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
	cfg := getUpdaterConfig(cmd)

	u, err := updater.New(cfg, updater.BinaryTypeServer, nil)
	if err != nil {
		return fmt.Errorf("create updater: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := u.CheckForUpdate(ctx)
	if err != nil {
		if errors.Is(err, updater.ErrNoUpdateAvailable) {
			fmt.Printf("Current version %s is up to date (Channel: %s).\n", version.Short(), cfg.Channel)
			return nil
		}
		return fmt.Errorf("check for update: %w", err)
	}

	fmt.Printf("Update available!\n")
	fmt.Printf("  Channel:         %s\n", cfg.Channel)
	fmt.Printf("  Current version: %s\n", info.CurrentVersion)
	fmt.Printf("  New version:     %s\n", info.NewVersion)
	fmt.Printf("  Published:       %s\n", info.PublishedAt.Format(time.RFC1123))
	fmt.Printf("\nWould you like to install this update? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n') //nolint:errcheck // Interactive prompt - EOF is acceptable
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

	// Run service (handles signals and Windows Service events)
	return service.Run("bifrost-server", srv)
}

// Service command flags
var (
	serviceConfigPath string
	serviceName       string
)

func newServiceCommand() *cobra.Command {
	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Manage system service installation",
		Long:  `Install, uninstall, or check status of bifrost-server as a system service.`,
	}

	// Install command
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install as a system service",
		Long: `Install bifrost-server as a system service.

On Linux: Creates a systemd unit file
On macOS: Creates a launchd plist
On Windows: Registers a Windows Service`,
		RunE: runServiceInstall,
	}
	installCmd.Flags().StringVarP(&serviceConfigPath, "config", "c", "", "Path to config file (required)")
	installCmd.Flags().StringVar(&serviceName, "name", "", "Service name (default: bifrost-server)")
	_ = installCmd.MarkFlagRequired("config") //nolint:errcheck // Flag registration only fails on invalid flag name

	// Uninstall command
	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the system service",
		RunE:  runServiceUninstall,
	}
	uninstallCmd.Flags().StringVar(&serviceName, "name", "", "Service name (default: bifrost-server)")

	// Status command
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show service installation status",
		RunE:  runServiceStatus,
	}
	statusCmd.Flags().StringVar(&serviceName, "name", "", "Service name (default: bifrost-server)")

	serviceCmd.AddCommand(installCmd, uninstallCmd, statusCmd)
	return serviceCmd
}

func runServiceInstall(cmd *cobra.Command, args []string) error {
	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	cfg := service.Config{
		Type:       service.TypeServer,
		Name:       serviceName,
		BinaryPath: exePath,
		ConfigPath: serviceConfigPath,
	}

	mgr, err := service.New(cfg)
	if err != nil {
		return fmt.Errorf("create service manager: %w", err)
	}

	return mgr.Install()
}

func runServiceUninstall(cmd *cobra.Command, args []string) error {
	cfg := service.Config{
		Type: service.TypeServer,
		Name: serviceName,
	}

	mgr, err := service.New(cfg)
	if err != nil {
		return fmt.Errorf("create service manager: %w", err)
	}

	return mgr.Uninstall()
}

func runServiceStatus(cmd *cobra.Command, args []string) error {
	cfg := service.Config{
		Type: service.TypeServer,
		Name: serviceName,
	}

	mgr, err := service.New(cfg)
	if err != nil {
		return fmt.Errorf("create service manager: %w", err)
	}

	status, err := mgr.Status()
	if err != nil {
		return err
	}

	fmt.Printf("Service: %s\n", cfg.Name)
	fmt.Printf("Platform: %s\n", service.Platform())
	fmt.Printf("Status: %s\n", status)
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
