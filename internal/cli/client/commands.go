// Package client provides CLI commands for the Bifrost client.
package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// APIClient is a client for the client REST API.
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

// NewCommands creates the client CLI commands.
func NewCommands() *cobra.Command {
	var apiURL string
	var apiToken string

	root := &cobra.Command{
		Use:   "ctl",
		Short: "Control a running Bifrost client",
	}

	root.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:3130", "API server URL")
	root.PersistentFlags().StringVar(&apiToken, "token", "", "API authentication token")

	// Status command
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show client status",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ShowStatus()
		},
	}

	// Debug commands
	debugCmd := &cobra.Command{
		Use:   "debug",
		Short: "Debug traffic commands",
	}

	var debugCount int
	debugTailCmd := &cobra.Command{
		Use:   "tail",
		Short: "Show recent traffic entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.TailDebug(debugCount)
		},
	}
	debugTailCmd.Flags().IntVarP(&debugCount, "count", "n", 20, "Number of entries to show")

	debugClearCmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear debug entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ClearDebug()
		},
	}

	debugErrorsCmd := &cobra.Command{
		Use:   "errors",
		Short: "Show error entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ShowErrors()
		},
	}

	debugCmd.AddCommand(debugTailCmd, debugClearCmd, debugErrorsCmd)

	// Routes commands
	routesCmd := &cobra.Command{
		Use:   "routes",
		Short: "Manage routes",
	}

	routesListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ListRoutes()
		},
	}

	routesTestCmd := &cobra.Command{
		Use:   "test [domain]",
		Short: "Test which route matches a domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.TestRoute(args[0])
		},
	}

	routesCmd.AddCommand(routesListCmd, routesTestCmd)

	// Health command
	healthCmd := &cobra.Command{
		Use:   "health",
		Short: "Check client health",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.CheckHealth()
		},
	}

	root.AddCommand(statusCmd, debugCmd, routesCmd, healthCmd)
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

// ShowStatus displays the client status.
func (c *APIClient) ShowStatus() error {
	var status map[string]interface{}
	if err := c.getJSON("/api/v1/status", &status); err != nil {
		return err
	}

	fmt.Printf("Status: %v\n", status["status"])
	fmt.Printf("Server: %v\n", status["server_status"])
	fmt.Printf("Version: %v\n", status["version"])
	fmt.Printf("Time: %v\n", status["time"])
	if entries, ok := status["debug_entries"].(float64); ok {
		fmt.Printf("Debug Entries: %.0f\n", entries)
	}

	return nil
}

// TailDebug shows recent debug entries.
func (c *APIClient) TailDebug(count int) error {
	var entries []map[string]interface{}
	if err := c.getJSON("/api/v1/debug/entries/last/"+strconv.Itoa(count), &entries); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tMETHOD\tHOST\tSTATUS\tDURATION\tROUTE")

	for _, e := range entries {
		timestamp := ""
		if t, ok := e["timestamp"].(string); ok {
			if parsed, err := time.Parse(time.RFC3339, t); err == nil {
				timestamp = parsed.Format("15:04:05")
			}
		}
		method := e["method"]
		host := e["host"]
		status := e["status_code"]
		duration := e["duration_ms"]
		route := e["route"]
		fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%vms\t%v\n", timestamp, method, host, status, duration, route)
	}

	return w.Flush()
}

// ClearDebug clears all debug entries.
func (c *APIClient) ClearDebug() error {
	resp, err := c.doRequest("DELETE", "/api/v1/debug/entries", nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clear failed: %s - %s", resp.Status, string(body))
	}

	fmt.Println("Debug entries cleared")
	return nil
}

// ShowErrors shows error entries.
func (c *APIClient) ShowErrors() error {
	var entries []map[string]interface{}
	if err := c.getJSON("/api/v1/debug/errors", &entries); err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No errors recorded")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tHOST\tERROR")

	for _, e := range entries {
		timestamp := ""
		if t, ok := e["timestamp"].(string); ok {
			if parsed, err := time.Parse(time.RFC3339, t); err == nil {
				timestamp = parsed.Format("15:04:05")
			}
		}
		host := e["host"]
		errMsg := e["error"]
		fmt.Fprintf(w, "%s\t%v\t%v\n", timestamp, host, errMsg)
	}

	return w.Flush()
}

// ListRoutes lists all configured routes.
func (c *APIClient) ListRoutes() error {
	var routes []map[string]interface{}
	if err := c.getJSON("/api/v1/routes", &routes); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tPATTERNS\tACTION\tPRIORITY")

	for _, r := range routes {
		name := r["name"]
		patterns := r["patterns"]
		action := r["action"]
		priority := r["priority"]
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\n", name, patterns, action, priority)
	}

	return w.Flush()
}

// TestRoute tests which route matches a domain.
func (c *APIClient) TestRoute(domain string) error {
	var result map[string]interface{}
	if err := c.getJSON("/api/v1/routes/test?domain="+domain, &result); err != nil {
		return err
	}

	fmt.Printf("Domain: %v\n", result["domain"])
	fmt.Printf("Action: %v\n", result["action"])
	return nil
}

// CheckHealth checks client health.
func (c *APIClient) CheckHealth() error {
	var health map[string]interface{}
	if err := c.getJSON("/api/v1/health", &health); err != nil {
		return err
	}

	status := health["status"]
	fmt.Printf("Health: %v\n", status)
	return nil
}
