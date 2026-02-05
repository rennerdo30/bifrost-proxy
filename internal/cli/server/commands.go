// Package server provides CLI commands for the Bifrost server.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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

	// Backend add command
	var backendType string
	var backendConfig string
	var backendEnabled bool
	backendAddCmd := &cobra.Command{
		Use:   "add [name]",
		Short: "Add a new backend",
		Long: `Add a new backend to the server.

Example:
  bifrost-server ctl backend add my-proxy --type http_proxy --config '{"address":"proxy.example.com:8080"}'
  bifrost-server ctl backend add direct-out --type direct
  bifrost-server ctl backend add socks --type socks5_proxy --config '{"address":"socks.example.com:1080","username":"user","password":"pass"}'`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.AddBackend(args[0], backendType, backendConfig, backendEnabled)
		},
	}
	backendAddCmd.Flags().StringVarP(&backendType, "type", "t", "", "Backend type (required): direct, http_proxy, socks5_proxy, wireguard, openvpn, nordvpn, mullvad, pia, protonvpn")
	backendAddCmd.Flags().StringVarP(&backendConfig, "config", "c", "{}", "Backend configuration as JSON")
	backendAddCmd.Flags().BoolVarP(&backendEnabled, "enabled", "e", true, "Enable the backend after creation")
	_ = backendAddCmd.MarkFlagRequired("type") //nolint:errcheck // Flag registration only fails on invalid flag name

	// Backend remove command
	backendRemoveCmd := &cobra.Command{
		Use:   "remove [name]",
		Short: "Remove a backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.RemoveBackend(args[0])
		},
	}

	// Backend test command
	var testTarget string
	var testTimeout string
	backendTestCmd := &cobra.Command{
		Use:   "test [name]",
		Short: "Test backend connectivity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.TestBackend(args[0], testTarget, testTimeout)
		},
	}
	backendTestCmd.Flags().StringVar(&testTarget, "target", "google.com:443", "Target host:port to test connectivity")
	backendTestCmd.Flags().StringVar(&testTimeout, "timeout", "10s", "Test timeout")

	backendCmd.AddCommand(backendListCmd, backendShowCmd, backendAddCmd, backendRemoveCmd, backendTestCmd)

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

	// Rule commands
	ruleCmd := &cobra.Command{
		Use:   "rule",
		Short: "Manage routing rules",
	}

	ruleListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all routing rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ListRules()
		},
	}

	var ruleDomain string
	var ruleBackend string
	var rulePriority int
	ruleAddCmd := &cobra.Command{
		Use:   "add [name]",
		Short: "Add a new routing rule",
		Long: `Add a new routing rule to route traffic for specific domains to a backend.

Example:
  bifrost-server ctl rule add anime --domain "*.crunchyroll.com" --backend germany
  bifrost-server ctl rule add work --domain "*.company.com" --backend office --priority 100
  bifrost-server ctl rule add streaming --domain "*.netflix.com,*.hulu.com" --backend us-west`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.AddRule(args[0], ruleDomain, ruleBackend, rulePriority)
		},
	}
	ruleAddCmd.Flags().StringVarP(&ruleDomain, "domain", "d", "", "Domain pattern(s), comma-separated for multiple (required)")
	ruleAddCmd.Flags().StringVarP(&ruleBackend, "backend", "b", "", "Backend name to route traffic to (required)")
	ruleAddCmd.Flags().IntVarP(&rulePriority, "priority", "p", 0, "Rule priority (higher = matched first)")
	_ = ruleAddCmd.MarkFlagRequired("domain")  //nolint:errcheck // Flag registration only fails on invalid flag name
	_ = ruleAddCmd.MarkFlagRequired("backend") //nolint:errcheck // Flag registration only fails on invalid flag name

	ruleRemoveCmd := &cobra.Command{
		Use:   "remove [name]",
		Short: "Remove a routing rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.RemoveRule(args[0])
		},
	}

	ruleCmd.AddCommand(ruleListCmd, ruleAddCmd, ruleRemoveCmd)

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

	root.AddCommand(statusCmd, backendCmd, configCmd, ruleCmd, statsCmd, healthCmd)
	return root
}

func (c *APIClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
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
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error message
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
		stats, _ := b["stats"].(map[string]interface{}) //nolint:errcheck
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

	data, _ := json.MarshalIndent(backend, "", "  ") //nolint:errcheck // Error only on cycle which won't happen
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
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error message
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

	data, _ := json.MarshalIndent(stats, "", "  ") //nolint:errcheck // Error only on cycle which won't happen
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

// AddBackend adds a new backend to the server.
func (c *APIClient) AddBackend(name, backendType, configJSON string, enabled bool) error {
	// Parse the config JSON
	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &configMap); err != nil {
		return fmt.Errorf("invalid config JSON: %w", err)
	}

	// Build the request body
	reqBody := map[string]interface{}{
		"name":    name,
		"type":    backendType,
		"enabled": enabled,
		"config":  configMap,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest("POST", "/api/v1/backends", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error message

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to add backend: %s - %s", resp.Status, string(respBody))
	}

	fmt.Printf("Backend '%s' added successfully (type: %s, enabled: %v)\n", name, backendType, enabled)
	return nil
}

// RemoveBackend removes a backend from the server.
func (c *APIClient) RemoveBackend(name string) error {
	resp, err := c.doRequest("DELETE", "/api/v1/backends/"+name, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error message
		return fmt.Errorf("failed to remove backend: %s - %s", resp.Status, string(body))
	}

	fmt.Printf("Backend '%s' removed successfully\n", name)
	return nil
}

// TestBackend tests connectivity through a backend.
func (c *APIClient) TestBackend(name, target, timeout string) error {
	reqBody := map[string]string{
		"target":  target,
		"timeout": timeout,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest("POST", "/api/v1/backends/"+name+"/test", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	status := result["status"]
	if status == "success" {
		fmt.Printf("Backend '%s' test PASSED\n", name)
		fmt.Printf("  Target: %v\n", result["target"])
		fmt.Printf("  Duration: %v\n", result["duration"])
		fmt.Printf("  Healthy: %v\n", result["healthy"])
	} else {
		fmt.Printf("Backend '%s' test FAILED\n", name)
		fmt.Printf("  Target: %v\n", result["target"])
		fmt.Printf("  Error: %v\n", result["error"])
		fmt.Printf("  Duration: %v\n", result["duration"])
	}

	return nil
}

// ListRules lists all routing rules.
func (c *APIClient) ListRules() error {
	var routes []map[string]interface{}
	if err := c.getJSON("/api/v1/routes", &routes); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDOMAINS\tBACKEND\tPRIORITY")

	for _, r := range routes {
		name := r["name"]
		domains := ""
		if d, ok := r["domains"].([]interface{}); ok && len(d) > 0 {
			parts := make([]string, len(d))
			for i, v := range d {
				parts[i] = fmt.Sprintf("%v", v)
			}
			domains = strings.Join(parts, ", ")
		}
		backend := r["backend"]
		if backend == nil || backend == "" {
			if backends, ok := r["backends"].([]interface{}); ok && len(backends) > 0 {
				parts := make([]string, len(backends))
				for i, v := range backends {
					parts[i] = fmt.Sprintf("%v", v)
				}
				backend = strings.Join(parts, ", ")
			}
		}
		priority := r["priority"]
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\n", name, domains, backend, priority)
	}

	return w.Flush()
}

// AddRule adds a new routing rule.
func (c *APIClient) AddRule(name, domain, backend string, priority int) error {
	// Parse comma-separated domains
	domains := strings.Split(domain, ",")
	for i := range domains {
		domains[i] = strings.TrimSpace(domains[i])
	}

	reqBody := map[string]interface{}{
		"name":     name,
		"domains":  domains,
		"backend":  backend,
		"priority": priority,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest("POST", "/api/v1/routes", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error message

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to add rule: %s - %s", resp.Status, string(respBody))
	}

	fmt.Printf("Rule '%s' added successfully\n", name)
	fmt.Printf("  Domains: %s\n", strings.Join(domains, ", "))
	fmt.Printf("  Backend: %s\n", backend)
	if priority > 0 {
		fmt.Printf("  Priority: %d\n", priority)
	}
	return nil
}

// RemoveRule removes a routing rule.
func (c *APIClient) RemoveRule(name string) error {
	resp, err := c.doRequest("DELETE", "/api/v1/routes/"+name, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error message
		return fmt.Errorf("failed to remove rule: %s - %s", resp.Status, string(body))
	}

	fmt.Printf("Rule '%s' removed successfully\n", name)
	return nil
}
