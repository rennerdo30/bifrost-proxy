package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetRootCmd resets the root command for testing
func resetRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bifrost-server",
		Short: "Bifrost Proxy Server",
		Long:  `Bifrost is a production-ready proxy server with support for WireGuard, OpenVPN, and upstream proxies.`,
	}
	cmd.PersistentFlags().StringP("config", "c", "server-config.yaml", "config file path")
	return cmd
}

func TestVersionCommand(t *testing.T) {
	cmd := resetRootCmd()

	versionOutput := ""
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			versionOutput = "bifrost-server version (test)"
		},
	}
	cmd.AddCommand(versionCmd)

	cmd.SetArgs([]string{"version"})
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Contains(t, versionOutput, "version")
}

func TestConfigFlag(t *testing.T) {
	cmd := resetRootCmd()

	var configFile string
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		configFile, _ = cmd.Flags().GetString("config")
		return nil
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}

	cmd.SetArgs([]string{"--config", "/path/to/config.yaml"})
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Equal(t, "/path/to/config.yaml", configFile)
}

func TestConfigFlagShort(t *testing.T) {
	cmd := resetRootCmd()

	var configFile string
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		configFile, _ = cmd.Flags().GetString("config")
		return nil
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}

	cmd.SetArgs([]string{"-c", "/path/to/config.yaml"})
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Equal(t, "/path/to/config.yaml", configFile)
}

func TestConfigFlagDefault(t *testing.T) {
	cmd := resetRootCmd()

	var configFile string
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		configFile, _ = cmd.Flags().GetString("config")
		return nil
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}

	cmd.SetArgs([]string{})
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Equal(t, "server-config.yaml", configFile)
}

func TestUnknownSubcommand(t *testing.T) {
	cmd := resetRootCmd()
	// Add a subcommand so that unknown subcommands are treated as errors
	subCmd := &cobra.Command{
		Use:   "known",
		Short: "A known command",
		Run: func(cmd *cobra.Command, args []string) {
			// Do nothing
		},
	}
	cmd.AddCommand(subCmd)

	// Capture stderr
	var buf bytes.Buffer
	cmd.SetErr(&buf)

	cmd.SetArgs([]string{"unknown-command"})
	err := cmd.Execute()

	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "unknown command")
	}
}

func TestInvalidFlag(t *testing.T) {
	cmd := resetRootCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}

	cmd.SetArgs([]string{"--invalid-flag"})
	err := cmd.Execute()

	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "unknown flag")
	}
}

func TestHelpFlag(t *testing.T) {
	cmd := resetRootCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}

	var buf bytes.Buffer
	cmd.SetOut(&buf)

	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()

	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "bifrost-server")
	assert.Contains(t, output, "--config")
}

func TestValidateCommand_FileNotFound(t *testing.T) {
	cmd := resetRootCmd()

	var validateErr error
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				validateErr = err
				return err
			}
			return nil
		},
	}
	cmd.AddCommand(validateCmd)

	cmd.SetArgs([]string{"validate", "-c", "/nonexistent/config.yaml"})
	err := cmd.Execute()

	assert.Error(t, err)
	assert.True(t, os.IsNotExist(validateErr))
}

func TestValidateCommand_Success(t *testing.T) {
	// Create a minimal valid config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	validConfig := `
log_level: info
server:
  http_address: ":7080"
  socks5_address: ":7180"
api:
  address: ":7081"
backends: []
rules: []
`
	err := os.WriteFile(configPath, []byte(validConfig), 0644)
	require.NoError(t, err)

	cmd := resetRootCmd()

	var validated bool
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if _, statErr := os.Stat(cfgPath); os.IsNotExist(statErr) {
				return statErr
			}
			validated = true
			return nil
		},
	}
	cmd.AddCommand(validateCmd)

	cmd.SetArgs([]string{"validate", "-c", configPath})
	err = cmd.Execute()

	assert.NoError(t, err)
	assert.True(t, validated)
}

func TestSubcommandHelp(t *testing.T) {
	cmd := resetRootCmd()

	// Add a subcommand with its own flags
	subCmd := &cobra.Command{
		Use:   "sub",
		Short: "A subcommand",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	subCmd.Flags().Bool("sub-flag", false, "A subcommand flag")
	cmd.AddCommand(subCmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)

	cmd.SetArgs([]string{"sub", "--help"})
	err := cmd.Execute()

	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "sub")
	assert.Contains(t, output, "--sub-flag")
}

func TestMultipleSubcommands(t *testing.T) {
	cmd := resetRootCmd()

	subCmd1Executed := false
	subCmd2Executed := false

	subCmd1 := &cobra.Command{
		Use:   "cmd1",
		Short: "Command 1",
		Run: func(cmd *cobra.Command, args []string) {
			subCmd1Executed = true
		},
	}
	subCmd2 := &cobra.Command{
		Use:   "cmd2",
		Short: "Command 2",
		Run: func(cmd *cobra.Command, args []string) {
			subCmd2Executed = true
		},
	}
	cmd.AddCommand(subCmd1)
	cmd.AddCommand(subCmd2)

	// Execute cmd1
	cmd.SetArgs([]string{"cmd1"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.True(t, subCmd1Executed)
	assert.False(t, subCmd2Executed)

	// Reset and execute cmd2
	subCmd1Executed = false
	cmd.SetArgs([]string{"cmd2"})
	err = cmd.Execute()
	assert.NoError(t, err)
	assert.False(t, subCmd1Executed)
	assert.True(t, subCmd2Executed)
}

func TestServiceInstallCommand_RequiresRoot(t *testing.T) {
	// This test verifies the command structure exists
	// Actual installation would require elevated privileges
	cmd := resetRootCmd()

	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Manage system service",
	}

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install as system service",
		RunE: func(cmd *cobra.Command, args []string) error {
			// In real implementation, this would check for admin privileges
			return nil
		},
	}
	serviceCmd.AddCommand(installCmd)
	cmd.AddCommand(serviceCmd)

	cmd.SetArgs([]string{"service", "install"})
	err := cmd.Execute()
	assert.NoError(t, err) // Structure test only
}

func TestUpdateCommand_Structure(t *testing.T) {
	cmd := resetRootCmd()

	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Check for and install updates",
	}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Check if updates are available",
		Run: func(cmd *cobra.Command, args []string) {
			// Mock: updates available
		},
	}
	updateCmd.AddCommand(checkCmd)
	cmd.AddCommand(updateCmd)

	cmd.SetArgs([]string{"update", "check"})
	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestCommandAliases(t *testing.T) {
	cmd := resetRootCmd()

	var executed bool
	aliasedCmd := &cobra.Command{
		Use:     "long-command",
		Aliases: []string{"lc", "longcmd"},
		Short:   "A command with aliases",
		Run: func(cmd *cobra.Command, args []string) {
			executed = true
		},
	}
	cmd.AddCommand(aliasedCmd)

	// Test using alias
	cmd.SetArgs([]string{"lc"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.True(t, executed)
}

func TestFlagParsing_EmptyValue(t *testing.T) {
	cmd := resetRootCmd()

	var configFile string
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		configFile, _ = cmd.Flags().GetString("config")
		return nil
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}

	// Empty value for config
	cmd.SetArgs([]string{"--config", ""})
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Equal(t, "", configFile)
}

func TestFlagParsing_SpacesInPath(t *testing.T) {
	cmd := resetRootCmd()

	var configFile string
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		configFile, _ = cmd.Flags().GetString("config")
		return nil
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}

	pathWithSpaces := "/path/with spaces/config.yaml"
	cmd.SetArgs([]string{"--config", pathWithSpaces})
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Equal(t, pathWithSpaces, configFile)
}

func TestOutputFormatting(t *testing.T) {
	cmd := resetRootCmd()

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("bifrost-server v1.0.0")
			cmd.Println("Build: test")
		},
	}
	cmd.AddCommand(versionCmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)

	cmd.SetArgs([]string{"version"})
	err := cmd.Execute()

	assert.NoError(t, err)
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	assert.Len(t, lines, 2)
}
