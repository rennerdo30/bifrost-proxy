// Package server provides CLI commands for the Bifrost server.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// APIClient is a client for the server REST API.
type APIClient struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// NewAPIClient creates a new API client.
func NewAPIClient(baseURL, token string) *APIClient {
	return &APIClient{
		BaseURL: baseURL,
		Token:   token,
		Client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// NewCommands creates the server CLI commands.
func NewCommands() *cobra.Command {
	var apiURL string
	var apiToken string

	root := &cobra.Command{
		Use:   "ctl",
		Short: "Control a running Bifrost server",
	}

	root.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:8082", "API server URL")
	root.PersistentFlags().StringVar(&apiToken, "token", "", "API authentication token")

	// Status command
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show server status",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ShowStatus()
		},
	}

	// Backend commands
	backendCmd := &cobra.Command{
		Use:   "backend",
		Short: "Manage backends",
	}

	backendListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all backends",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ListBackends()
		},
	}

	backendShowCmd := &cobra.Command{
		Use:   "show [name]",
		Short: "Show backend details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ShowBackend(args[0])
		},
	}

	backendCmd.AddCommand(backendListCmd, backendShowCmd)

	// Config commands
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
	}

	configReloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ReloadConfig()
		},
	}

	configCmd.AddCommand(configReloadCmd)

	// Stats command
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show server statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ShowStats()
		},
	}

	// Health command
	healthCmd := &cobra.Command{
		Use:   "health",
		Short: "Check server health",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.CheckHealth()
		},
	}

	root.AddCommand(statusCmd, backendCmd, configCmd, statsCmd, healthCmd)
	return root
}

func (c *APIClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Content-Type", "application/json")

	return c.Client.Do(req)
}

func (c *APIClient) getJSON(path string, v interface{}) error {
	resp, err := c.doRequest("GET", path, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: %s - %s", resp.Status, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(v)
}

// ShowStatus displays the server status.
func (c *APIClient) ShowStatus() error {
	var status map[string]interface{}
	if err := c.getJSON("/api/v1/status", &status); err != nil {
		return err
	}

	fmt.Printf("Status: %v\n", status["status"])
	fmt.Printf("Version: %v\n", status["version"])
	fmt.Printf("Time: %v\n", status["time"])
	if backends, ok := status["backends"].(float64); ok {
		fmt.Printf("Backends: %.0f\n", backends)
	}

	return nil
}

// ListBackends lists all backends.
func (c *APIClient) ListBackends() error {
	var backends []map[string]interface{}
	if err := c.getJSON("/api/v1/backends", &backends); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tHEALTHY\tACTIVE CONN\tTOTAL CONN")

	for _, b := range backends {
		name := b["name"]
		bType := b["type"]
		healthy := b["healthy"]
		stats, _ := b["stats"].(map[string]interface{})
		active := int64(0)
		total := int64(0)
		if stats != nil {
			if v, ok := stats["active_connections"].(float64); ok {
				active = int64(v)
			}
			if v, ok := stats["total_connections"].(float64); ok {
				total = int64(v)
			}
		}
		fmt.Fprintf(w, "%v\t%v\t%v\t%d\t%d\n", name, bType, healthy, active, total)
	}

	return w.Flush()
}

// ShowBackend shows details for a specific backend.
func (c *APIClient) ShowBackend(name string) error {
	var backend map[string]interface{}
	if err := c.getJSON("/api/v1/backends/"+name, &backend); err != nil {
		return err
	}

	data, _ := json.MarshalIndent(backend, "", "  ")
	fmt.Println(string(data))
	return nil
}

// ReloadConfig triggers a configuration reload.
func (c *APIClient) ReloadConfig() error {
	resp, err := c.doRequest("POST", "/api/v1/config/reload", nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reload failed: %s - %s", resp.Status, string(body))
	}

	fmt.Println("Configuration reloaded successfully")
	return nil
}

// ShowStats displays server statistics.
func (c *APIClient) ShowStats() error {
	var stats map[string]interface{}
	if err := c.getJSON("/api/v1/stats", &stats); err != nil {
		return err
	}

	data, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Println(string(data))
	return nil
}

// CheckHealth checks server health.
func (c *APIClient) CheckHealth() error {
	var health map[string]interface{}
	if err := c.getJSON("/api/v1/health", &health); err != nil {
		return err
	}

	status := health["status"]
	if status == "healthy" {
		fmt.Println("Server is healthy")
		return nil
	}

	fmt.Printf("Server health: %v\n", status)
	return nil
}
