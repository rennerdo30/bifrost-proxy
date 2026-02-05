// Package main provides the Bifrost client entry point.
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

	clicmd "github.com/rennerdo30/bifrost-proxy/internal/cli/client"
	"github.com/rennerdo30/bifrost-proxy/internal/client"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/service"
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
	initCmd.Flags().StringVar(&initHTTPListen, "http-listen", "127.0.0.1:7380", "HTTP proxy listen address")
	initCmd.Flags().StringVar(&initSOCKS5Listen, "socks5-listen", "127.0.0.1:7381", "SOCKS5 proxy listen address")
	initCmd.Flags().BoolVarP(&initForce, "force", "f", false, "overwrite existing file")

	configCmd.AddCommand(initCmd)
	rootCmd.AddCommand(configCmd)

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

func getUpdaterConfig(cmd *cobra.Command) updater.Config {
	// Start with defaults
	clientCfg := config.DefaultClientConfig()

	// Try to load config file
	if err := config.Load(configFile, &clientCfg); err != nil {
		// If config load fails, we proceed with defaults
		// This ensures update commands work even without a valid config file
		logging.Debug("Failed to load config for update check", "error", err)
	}

	// Determine channel
	channel := clientCfg.AutoUpdate.Channel
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

	u, err := updater.New(cfg, updater.BinaryTypeClient, nil)
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
	fmt.Printf("\nRun 'bifrost-client update install' to install.\n")

	return nil
}

func runUpdateInstall(cmd *cobra.Command, args []string) error {
	cfg := getUpdaterConfig(cmd)

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
	fmt.Printf("Please restart bifrost-client to use version %s.\n", info.NewVersion)

	return nil
}

func runUpdate(cmd *cobra.Command, args []string) error {
	cfg := getUpdaterConfig(cmd)

	u, err := updater.New(cfg, updater.BinaryTypeClient, nil)
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

	// Create updates map from flags
	updates := map[string]interface{}{
		"proxy": map[string]interface{}{
			"http": map[string]interface{}{
				"listen": initHTTPListen,
			},
			"socks5": map[string]interface{}{
				"listen": initSOCKS5Listen,
			},
		},
		"server": map[string]interface{}{
			"address":  initServer,
			"protocol": initProtocol,
		},
	}

	// Parse template and apply updates
	node, err := config.ParseNode([]byte(config.DefaultClientConfigTemplate))
	if err != nil {
		return fmt.Errorf("failed to parse config template: %w", err)
	}

	if err := config.UpdateNode(node, updates); err != nil {
		return fmt.Errorf("failed to update config template: %w", err)
	}

	// Save configuration
	if err := config.SaveNode(initOutput, node); err != nil {
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

	// Run service (handles signals and Windows Service events)
	return service.Run("bifrost-client", c)
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
		Long:  `Install, uninstall, or check status of bifrost-client as a system service.`,
	}

	// Install command
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install as a system service",
		Long: `Install bifrost-client as a system service.

On Linux: Creates a systemd unit file
On macOS: Creates a launchd plist
On Windows: Registers a Windows Service`,
		RunE: runServiceInstall,
	}
	installCmd.Flags().StringVarP(&serviceConfigPath, "config", "c", "", "Path to config file (required)")
	installCmd.Flags().StringVar(&serviceName, "name", "", "Service name (default: bifrost-client)")
	_ = installCmd.MarkFlagRequired("config") //nolint:errcheck // Flag registration only fails on invalid flag name

	// Uninstall command
	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the system service",
		RunE:  runServiceUninstall,
	}
	uninstallCmd.Flags().StringVar(&serviceName, "name", "", "Service name (default: bifrost-client)")

	// Status command
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show service installation status",
		RunE:  runServiceStatus,
	}
	statusCmd.Flags().StringVar(&serviceName, "name", "", "Service name (default: bifrost-client)")

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
		Type:       service.TypeClient,
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
		Type: service.TypeClient,
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
		Type: service.TypeClient,
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
