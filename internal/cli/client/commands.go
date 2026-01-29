// Package client provides CLI commands for the Bifrost client.
package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
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

	root.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:7383", "API server URL")
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

	var exportOutput string
	var exportFormat string
	debugExportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export debug entries to file",
		Long: `Export debug entries to HAR (HTTP Archive) format.

Example:
  bifrost-client ctl debug export --output traffic.har
  bifrost-client ctl debug export -o traffic.json --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ExportDebug(exportOutput, exportFormat)
		},
	}
	debugExportCmd.Flags().StringVarP(&exportOutput, "output", "o", "traffic.har", "Output file path")
	debugExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "har", "Export format: har or json")

	debugCmd.AddCommand(debugTailCmd, debugClearCmd, debugErrorsCmd, debugExportCmd)

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

	var routeDomain string
	var routeAction string
	var routePriority int
	routesAddCmd := &cobra.Command{
		Use:   "add [name]",
		Short: "Add a new route",
		Long: `Add a new routing rule for the client.

Example:
  bifrost-client ctl routes add work --domain "*.company.com" --action server
  bifrost-client ctl routes add bypass --domain "*.local" --action direct
  bifrost-client ctl routes add streaming --domain "*.netflix.com,*.hulu.com" --action server --priority 100`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.AddRoute(args[0], routeDomain, routeAction, routePriority)
		},
	}
	routesAddCmd.Flags().StringVarP(&routeDomain, "domain", "d", "", "Domain pattern(s), comma-separated for multiple (required)")
	routesAddCmd.Flags().StringVarP(&routeAction, "action", "a", "server", "Action: 'server' (use proxy) or 'direct' (bypass proxy)")
	routesAddCmd.Flags().IntVarP(&routePriority, "priority", "p", 0, "Rule priority (higher = matched first)")
	routesAddCmd.MarkFlagRequired("domain")

	routesRemoveCmd := &cobra.Command{
		Use:   "remove [name]",
		Short: "Remove a route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.RemoveRoute(args[0])
		},
	}

	routesCmd.AddCommand(routesListCmd, routesTestCmd, routesAddCmd, routesRemoveCmd)

	// Health command
	healthCmd := &cobra.Command{
		Use:   "health",
		Short: "Check client health",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.CheckHealth()
		},
	}

	// VPN commands
	vpnCmd := &cobra.Command{
		Use:   "vpn",
		Short: "VPN mode commands",
	}

	vpnStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show VPN status",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ShowVPNStatus()
		},
	}

	vpnEnableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable VPN mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.EnableVPN()
		},
	}

	vpnDisableCmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable VPN mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.DisableVPN()
		},
	}

	// VPN split tunnel commands
	vpnSplitCmd := &cobra.Command{
		Use:   "split",
		Short: "Split tunnel configuration",
	}

	vpnSplitListCmd := &cobra.Command{
		Use:   "list",
		Short: "List split tunnel rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ListSplitTunnelRules()
		},
	}

	vpnSplitAddAppCmd := &cobra.Command{
		Use:   "add-app [name]",
		Short: "Add app to split tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.AddSplitTunnelApp(args[0])
		},
	}

	vpnSplitRemoveAppCmd := &cobra.Command{
		Use:   "remove-app [name]",
		Short: "Remove app from split tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.RemoveSplitTunnelApp(args[0])
		},
	}

	vpnSplitAddDomainCmd := &cobra.Command{
		Use:   "add-domain [pattern]",
		Short: "Add domain pattern to split tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.AddSplitTunnelDomain(args[0])
		},
	}

	vpnSplitAddIPCmd := &cobra.Command{
		Use:   "add-ip [cidr]",
		Short: "Add IP/CIDR to split tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.AddSplitTunnelIP(args[0])
		},
	}

	vpnSplitCmd.AddCommand(vpnSplitListCmd, vpnSplitAddAppCmd, vpnSplitRemoveAppCmd, vpnSplitAddDomainCmd, vpnSplitAddIPCmd)
	vpnCmd.AddCommand(vpnStatusCmd, vpnEnableCmd, vpnDisableCmd, vpnSplitCmd)

	// VPN connections command
	vpnConnectionsCmd := &cobra.Command{
		Use:   "connections",
		Short: "Show active VPN connections",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ShowVPNConnections()
		},
	}
	vpnCmd.AddCommand(vpnConnectionsCmd)

	// VPN DNS cache command
	vpnDNSCacheCmd := &cobra.Command{
		Use:   "dns-cache",
		Short: "Show VPN DNS cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(apiURL, apiToken)
			return client.ShowVPNDNSCache()
		},
	}
	vpnCmd.AddCommand(vpnDNSCacheCmd)

	root.AddCommand(statusCmd, debugCmd, routesCmd, healthCmd, vpnCmd)
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

// ExportDebug exports debug entries to a file.
func (c *APIClient) ExportDebug(outputPath, format string) error {
	var entries []map[string]interface{}
	if err := c.getJSON("/api/v1/debug/entries", &entries); err != nil {
		return fmt.Errorf("failed to fetch debug entries: %w", err)
	}

	if len(entries) == 0 {
		return fmt.Errorf("no debug entries to export")
	}

	var output []byte
	var err error

	if format == "json" {
		// Export as raw JSON
		output, err = json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal entries: %w", err)
		}
	} else {
		// Export as HAR format
		har := convertToHAR(entries)
		output, err = json.MarshalIndent(har, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal HAR: %w", err)
		}
	}

	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Exported %d entries to %s\n", len(entries), outputPath)
	return nil
}

// convertToHAR converts debug entries to HAR format.
func convertToHAR(entries []map[string]interface{}) map[string]interface{} {
	harEntries := make([]map[string]interface{}, 0, len(entries))

	for _, e := range entries {
		method, _ := e["method"].(string)
		host, _ := e["host"].(string)
		status, _ := e["status"].(float64)
		duration, _ := e["duration"].(float64)
		timestamp, _ := e["timestamp"].(string)
		requestSize, _ := e["request_size"].(float64)
		responseSize, _ := e["response_size"].(float64)

		// Build URL
		scheme := "https"
		if proto, ok := e["protocol"].(string); ok && strings.HasPrefix(proto, "HTTP/") {
			scheme = "http"
		}
		url := fmt.Sprintf("%s://%s", scheme, host)

		harEntry := map[string]interface{}{
			"startedDateTime": timestamp,
			"time":            duration,
			"request": map[string]interface{}{
				"method":      method,
				"url":         url,
				"httpVersion": "HTTP/1.1",
				"cookies":     []interface{}{},
				"headers":     []interface{}{},
				"queryString": []interface{}{},
				"headersSize": -1,
				"bodySize":    int(requestSize),
			},
			"response": map[string]interface{}{
				"status":      int(status),
				"statusText":  getStatusText(int(status)),
				"httpVersion": "HTTP/1.1",
				"cookies":     []interface{}{},
				"headers":     []interface{}{},
				"content": map[string]interface{}{
					"size":     int(responseSize),
					"mimeType": "",
				},
				"redirectURL":  "",
				"headersSize":  -1,
				"bodySize":     int(responseSize),
			},
			"cache": map[string]interface{}{},
			"timings": map[string]interface{}{
				"blocked": -1,
				"dns":     -1,
				"connect": -1,
				"send":    0,
				"wait":    duration,
				"receive": 0,
				"ssl":     -1,
			},
			"serverIPAddress": "",
			"connection":      "",
		}

		// Add route info as custom field
		if route, ok := e["route"].(string); ok {
			harEntry["_route"] = route
		}
		if errorMsg, ok := e["error"].(string); ok && errorMsg != "" {
			harEntry["_error"] = errorMsg
		}

		harEntries = append(harEntries, harEntry)
	}

	return map[string]interface{}{
		"log": map[string]interface{}{
			"version": "1.2",
			"creator": map[string]interface{}{
				"name":    "Bifrost Proxy",
				"version": "1.0.0",
			},
			"entries": harEntries,
		},
	}
}

// getStatusText returns the HTTP status text for a status code.
func getStatusText(code int) string {
	statusTexts := map[int]string{
		200: "OK",
		201: "Created",
		204: "No Content",
		301: "Moved Permanently",
		302: "Found",
		304: "Not Modified",
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		500: "Internal Server Error",
		502: "Bad Gateway",
		503: "Service Unavailable",
	}
	if text, ok := statusTexts[code]; ok {
		return text
	}
	return "Unknown"
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

// AddRoute adds a new routing rule.
func (c *APIClient) AddRoute(name, domain, action string, priority int) error {
	// Parse comma-separated domains
	domains := strings.Split(domain, ",")
	for i := range domains {
		domains[i] = strings.TrimSpace(domains[i])
	}

	reqBody := map[string]interface{}{
		"name":     name,
		"domains":  domains,
		"action":   action,
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

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to add route: %s - %s", resp.Status, string(respBody))
	}

	fmt.Printf("Route '%s' added successfully\n", name)
	fmt.Printf("  Domains: %s\n", strings.Join(domains, ", "))
	fmt.Printf("  Action: %s\n", action)
	if priority > 0 {
		fmt.Printf("  Priority: %d\n", priority)
	}
	return nil
}

// RemoveRoute removes a routing rule.
func (c *APIClient) RemoveRoute(name string) error {
	resp, err := c.doRequest("DELETE", "/api/v1/routes/"+name, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to remove route: %s - %s", resp.Status, string(body))
	}

	fmt.Printf("Route '%s' removed successfully\n", name)
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

// ShowVPNStatus shows VPN status.
func (c *APIClient) ShowVPNStatus() error {
	var status map[string]interface{}
	if err := c.getJSON("/api/v1/vpn/status", &status); err != nil {
		return err
	}

	fmt.Printf("Status: %v\n", status["status"])
	if uptime, ok := status["uptime"].(float64); ok && uptime > 0 {
		fmt.Printf("Uptime: %v\n", time.Duration(uptime))
	}
	fmt.Printf("Bytes Sent: %v\n", status["bytes_sent"])
	fmt.Printf("Bytes Received: %v\n", status["bytes_received"])
	fmt.Printf("Active Connections: %v\n", status["active_connections"])
	fmt.Printf("Tunneled Connections: %v\n", status["tunneled_connections"])
	fmt.Printf("Bypassed Connections: %v\n", status["bypassed_connections"])
	if dnsQueries, ok := status["dns_queries"].(float64); ok && dnsQueries > 0 {
		fmt.Printf("DNS Queries: %.0f\n", dnsQueries)
		fmt.Printf("DNS Cache Hits: %v\n", status["dns_cache_hits"])
	}
	if lastErr, ok := status["last_error"].(string); ok && lastErr != "" {
		fmt.Printf("Last Error: %v\n", lastErr)
	}

	return nil
}

// EnableVPN enables VPN mode.
func (c *APIClient) EnableVPN() error {
	resp, err := c.doRequest("POST", "/api/v1/vpn/enable", nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enable failed: %s - %s", resp.Status, string(body))
	}

	fmt.Println("VPN enabled")
	return nil
}

// DisableVPN disables VPN mode.
func (c *APIClient) DisableVPN() error {
	resp, err := c.doRequest("POST", "/api/v1/vpn/disable", nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("disable failed: %s - %s", resp.Status, string(body))
	}

	fmt.Println("VPN disabled")
	return nil
}

// ListSplitTunnelRules lists split tunnel rules.
func (c *APIClient) ListSplitTunnelRules() error {
	var rules map[string]interface{}
	if err := c.getJSON("/api/v1/vpn/split/rules", &rules); err != nil {
		return err
	}

	fmt.Printf("Mode: %v\n\n", rules["mode"])

	if apps, ok := rules["apps"].([]interface{}); ok && len(apps) > 0 {
		fmt.Println("Apps:")
		for _, app := range apps {
			if a, ok := app.(map[string]interface{}); ok {
				fmt.Printf("  - %v\n", a["name"])
			}
		}
		fmt.Println()
	}

	if domains, ok := rules["domains"].([]interface{}); ok && len(domains) > 0 {
		fmt.Println("Domains:")
		for _, d := range domains {
			fmt.Printf("  - %v\n", d)
		}
		fmt.Println()
	}

	if ips, ok := rules["ips"].([]interface{}); ok && len(ips) > 0 {
		fmt.Println("IPs:")
		for _, ip := range ips {
			fmt.Printf("  - %v\n", ip)
		}
		fmt.Println()
	}

	if bypass, ok := rules["always_bypass"].([]interface{}); ok && len(bypass) > 0 {
		fmt.Println("Always Bypass:")
		for _, b := range bypass {
			fmt.Printf("  - %v\n", b)
		}
	}

	return nil
}

// AddSplitTunnelApp adds an app to split tunnel.
func (c *APIClient) AddSplitTunnelApp(name string) error {
	body := fmt.Sprintf(`{"name": %q}`, name)
	resp, err := c.doRequest("POST", "/api/v1/vpn/split/apps", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add failed: %s - %s", resp.Status, string(respBody))
	}

	fmt.Printf("Added app: %s\n", name)
	return nil
}

// RemoveSplitTunnelApp removes an app from split tunnel.
func (c *APIClient) RemoveSplitTunnelApp(name string) error {
	resp, err := c.doRequest("DELETE", "/api/v1/vpn/split/apps/"+name, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove failed: %s - %s", resp.Status, string(body))
	}

	fmt.Printf("Removed app: %s\n", name)
	return nil
}

// AddSplitTunnelDomain adds a domain to split tunnel.
func (c *APIClient) AddSplitTunnelDomain(pattern string) error {
	body := fmt.Sprintf(`{"pattern": %q}`, pattern)
	resp, err := c.doRequest("POST", "/api/v1/vpn/split/domains", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add failed: %s - %s", resp.Status, string(respBody))
	}

	fmt.Printf("Added domain: %s\n", pattern)
	return nil
}

// AddSplitTunnelIP adds an IP/CIDR to split tunnel.
func (c *APIClient) AddSplitTunnelIP(cidr string) error {
	body := fmt.Sprintf(`{"cidr": %q}`, cidr)
	resp, err := c.doRequest("POST", "/api/v1/vpn/split/ips", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add failed: %s - %s", resp.Status, string(respBody))
	}

	fmt.Printf("Added IP: %s\n", cidr)
	return nil
}

// ShowVPNConnections shows active VPN connections.
func (c *APIClient) ShowVPNConnections() error {
	var connections []map[string]interface{}
	if err := c.getJSON("/api/v1/vpn/connections", &connections); err != nil {
		return err
	}

	if len(connections) == 0 {
		fmt.Println("No active VPN connections")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROTO\tLOCAL\tREMOTE\tACTION\tDURATION\tBYTES")

	for _, conn := range connections {
		proto := conn["protocol"]
		local := conn["local_addr"]
		remote := conn["remote_addr"]
		action := conn["action"]
		duration := ""
		if start, ok := conn["start_time"].(string); ok {
			if t, err := time.Parse(time.RFC3339, start); err == nil {
				duration = time.Since(t).Round(time.Second).String()
			}
		}
		bytes := fmt.Sprintf("↑%v ↓%v", conn["bytes_sent"], conn["bytes_received"])
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%s\t%s\n", proto, local, remote, action, duration, bytes)
	}

	return w.Flush()
}

// ShowVPNDNSCache shows VPN DNS cache.
func (c *APIClient) ShowVPNDNSCache() error {
	var cache []map[string]interface{}
	if err := c.getJSON("/api/v1/vpn/dns/cache", &cache); err != nil {
		return err
	}

	if len(cache) == 0 {
		fmt.Println("DNS cache is empty")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tADDRESSES\tTTL")

	for _, entry := range cache {
		domain := entry["domain"]
		addrs := entry["addresses"]
		ttl := ""
		if expires, ok := entry["expires"].(string); ok {
			if t, err := time.Parse(time.RFC3339, expires); err == nil {
				remaining := time.Until(t).Round(time.Second)
				if remaining > 0 {
					ttl = remaining.String()
				} else {
					ttl = "expired"
				}
			}
		}
		fmt.Fprintf(w, "%v\t%v\t%s\n", domain, addrs, ttl)
	}

	return w.Flush()
}
