package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/cache"
)

// createTestCacheManager creates a cache manager for testing
func createTestCacheManager(t *testing.T) *cache.Manager {
	cfg := cache.DefaultConfig()
	cfg.Enabled = true
	cfg.Storage.Type = "memory"
	cfg.Storage.Memory.MaxSize = "100MB"

	mgr, err := cache.NewManager(&cfg)
	require.NoError(t, err)
	require.NoError(t, mgr.Start(context.Background()))
	t.Cleanup(func() {
		mgr.Stop(context.Background())
	})
	return mgr
}

func TestNewCacheAPI(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)
	require.NotNil(t, api)
	assert.Equal(t, mgr, api.manager)
}

func TestNewCacheAPI_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)
	require.NotNil(t, api)
	assert.Nil(t, api.manager)
}

func TestCacheAPI_RegisterRoutes(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	r := chi.NewRouter()
	api.RegisterRoutes(r)

	// Test that routes are registered by making requests
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/cache/stats"},
		{"GET", "/api/v1/cache/entries"},
		{"GET", "/api/v1/cache/rules"},
		{"GET", "/api/v1/cache/presets"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code, "Route %s %s should be registered", route.method, route.path)
	}
}

func TestCacheAPI_HandleGetStats(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/stats", nil)
	api.handleGetStats(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp cache.CacheStats
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Enabled)
	assert.Equal(t, "memory", resp.StorageType)
}

func TestCacheAPI_HandleGetStats_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/stats", nil)
	api.handleGetStats(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp["enabled"].(bool))
	assert.Contains(t, resp["error"], "not configured")
}

func TestCacheAPI_HandleListEntries(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/entries", nil)
	api.handleListEntries(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "entries")
	assert.Contains(t, resp, "total")
	assert.Contains(t, resp, "offset")
	assert.Contains(t, resp, "limit")
}

func TestCacheAPI_HandleListEntries_WithPagination(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/entries?offset=10&limit=50", nil)
	api.handleListEntries(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(10), resp["offset"])
	assert.Equal(t, float64(50), resp["limit"])
}

func TestCacheAPI_HandleListEntries_WithDomainFilter(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/entries?domain=example.com", nil)
	api.handleListEntries(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCacheAPI_HandleListEntries_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/entries", nil)
	api.handleListEntries(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandleListEntries_InvalidParams(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Invalid offset should be ignored (default to 0)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/entries?offset=invalid&limit=invalid", nil)
	api.handleListEntries(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCacheAPI_HandleGetEntry(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Put an entry first
	ctx := context.Background()
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Host = "example.com"

	// Add a rule to make this cacheable
	rule := &cache.Rule{
		Name:    "test",
		Domains: []string{"example.com"},
		Enabled: true,
		TTL:     time.Hour,
	}
	mgr.Rules().Add(rule)

	// Create a test entry manually via storage
	key := mgr.KeyFor(req)
	entry := &cache.Entry{
		Metadata: &cache.Metadata{
			Key:         key,
			URL:         "http://example.com/test",
			Host:        "example.com",
			StatusCode:  200,
			ContentType: "text/html",
			CreatedAt:   time.Now(),
			ExpiresAt:   time.Now().Add(time.Hour),
			AccessedAt:  time.Now(),
		},
		Body: io.NopCloser(strings.NewReader("test content")),
	}
	mgr.Storage().Put(ctx, key, entry)

	// Now test getting it via the handler
	r := chi.NewRouter()
	r.Get("/api/v1/cache/entries/{key}", api.handleGetEntry)

	httpReq := httptest.NewRequest("GET", "/api/v1/cache/entries/"+key, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCacheAPI_HandleGetEntry_NotFound(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	r := chi.NewRouter()
	r.Get("/api/v1/cache/entries/{key}", api.handleGetEntry)

	req := httptest.NewRequest("GET", "/api/v1/cache/entries/nonexistent-key", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCacheAPI_HandleGetEntry_EmptyKey(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Call directly without chi context to test empty key path
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/entries/", nil)
	api.handleGetEntry(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCacheAPI_HandleGetEntry_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/entries/somekey", nil)
	api.handleGetEntry(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandleDeleteEntry(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Put an entry first
	ctx := context.Background()
	key := "test-delete-key"
	entry := &cache.Entry{
		Metadata: &cache.Metadata{
			Key:        key,
			URL:        "http://example.com/test",
			Host:       "example.com",
			StatusCode: 200,
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(time.Hour),
			AccessedAt: time.Now(),
		},
		Body: io.NopCloser(strings.NewReader("test content")),
	}
	mgr.Storage().Put(ctx, key, entry)

	r := chi.NewRouter()
	r.Delete("/api/v1/cache/entries/{key}", api.handleDeleteEntry)

	req := httptest.NewRequest("DELETE", "/api/v1/cache/entries/"+key, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Entry deleted", resp["message"])
}

func TestCacheAPI_HandleDeleteEntry_EmptyKey(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/cache/entries/", nil)
	api.handleDeleteEntry(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCacheAPI_HandleDeleteEntry_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/cache/entries/somekey", nil)
	api.handleDeleteEntry(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandleClearCache(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Need confirmation
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/cache/entries?confirm=true", nil)
	api.handleClearCache(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Cache cleared", resp["message"])
}

func TestCacheAPI_HandleClearCache_NoConfirmation(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/cache/entries", nil)
	api.handleClearCache(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "Confirmation required")
}

func TestCacheAPI_HandleClearCache_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/cache/entries?confirm=true", nil)
	api.handleClearCache(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandlePurgeDomain(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	r := chi.NewRouter()
	r.Delete("/api/v1/cache/domain/{domain}", api.handlePurgeDomain)

	req := httptest.NewRequest("DELETE", "/api/v1/cache/domain/example.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Domain purged", resp["message"])
	assert.Equal(t, "example.com", resp["domain"])
}

func TestCacheAPI_HandlePurgeDomain_EmptyDomain(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/cache/domain/", nil)
	api.handlePurgeDomain(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCacheAPI_HandlePurgeDomain_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/cache/domain/example.com", nil)
	api.handlePurgeDomain(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandleListRules(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Add a rule
	rule := &cache.Rule{
		Name:     "test-rule",
		Domains:  []string{"example.com"},
		Enabled:  true,
		TTL:      time.Hour,
		Priority: 10,
	}
	mgr.Rules().Add(rule)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/rules", nil)
	api.handleListRules(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "rules")
	assert.Contains(t, resp, "count")
}

func TestCacheAPI_HandleListRules_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/rules", nil)
	api.handleListRules(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandleAddRule(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	body := `{
		"name": "new-rule",
		"domains": ["*.example.com"],
		"enabled": true,
		"ttl": "1h",
		"priority": 50
	}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Rule added", resp["message"])

	// Verify rule was added
	rule := mgr.Rules().Get("new-rule")
	assert.NotNil(t, rule)
	assert.Equal(t, "new-rule", rule.Name)
}

func TestCacheAPI_HandleAddRule_InvalidJSON(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader("{invalid}"))
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCacheAPI_HandleAddRule_MissingName(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	body := `{"domains": ["example.com"]}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader(body))
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "name is required")
}

func TestCacheAPI_HandleAddRule_MissingDomains(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	body := `{"name": "test-rule"}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader(body))
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "domain is required")
}

func TestCacheAPI_HandleAddRule_InvalidTTL(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	body := `{
		"name": "test-rule",
		"domains": ["example.com"],
		"ttl": "invalid"
	}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader(body))
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCacheAPI_HandleAddRule_InvalidMaxSize(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	body := `{
		"name": "test-rule",
		"domains": ["example.com"],
		"max_size": "invalid"
	}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader(body))
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCacheAPI_HandleAddRule_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	body := `{"name": "test", "domains": ["example.com"]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader(body))
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandleUpdateRule(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Add a rule first
	rule := &cache.Rule{
		Name:    "update-test",
		Domains: []string{"example.com"},
		Enabled: true,
	}
	mgr.Rules().Add(rule)

	router := chi.NewRouter()
	router.Put("/api/v1/cache/rules/{name}", api.handleUpdateRule)

	body := `{"enabled": false}`
	req := httptest.NewRequest("PUT", "/api/v1/cache/rules/update-test", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify rule was updated
	updatedRule := mgr.Rules().Get("update-test")
	assert.False(t, updatedRule.Enabled)
}

func TestCacheAPI_HandleUpdateRule_NotFound(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	router := chi.NewRouter()
	router.Put("/api/v1/cache/rules/{name}", api.handleUpdateRule)

	body := `{"enabled": false}`
	req := httptest.NewRequest("PUT", "/api/v1/cache/rules/nonexistent", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCacheAPI_HandleUpdateRule_InvalidJSON(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Add a rule first
	rule := &cache.Rule{
		Name:    "update-test",
		Domains: []string{"example.com"},
		Enabled: true,
	}
	mgr.Rules().Add(rule)

	router := chi.NewRouter()
	router.Put("/api/v1/cache/rules/{name}", api.handleUpdateRule)

	req := httptest.NewRequest("PUT", "/api/v1/cache/rules/update-test", strings.NewReader("{invalid}"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCacheAPI_HandleUpdateRule_EmptyName(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/cache/rules/", strings.NewReader(`{}`))
	api.handleUpdateRule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCacheAPI_HandleUpdateRule_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/cache/rules/test", strings.NewReader(`{}`))
	api.handleUpdateRule(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandleDeleteRule(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Add a rule first
	rule := &cache.Rule{
		Name:    "delete-test",
		Domains: []string{"example.com"},
		Enabled: true,
	}
	mgr.Rules().Add(rule)

	router := chi.NewRouter()
	router.Delete("/api/v1/cache/rules/{name}", api.handleDeleteRule)

	req := httptest.NewRequest("DELETE", "/api/v1/cache/rules/delete-test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify rule was deleted
	assert.Nil(t, mgr.Rules().Get("delete-test"))
}

func TestCacheAPI_HandleDeleteRule_NotFound(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	router := chi.NewRouter()
	router.Delete("/api/v1/cache/rules/{name}", api.handleDeleteRule)

	req := httptest.NewRequest("DELETE", "/api/v1/cache/rules/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCacheAPI_HandleDeleteRule_EmptyName(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/cache/rules/", nil)
	api.handleDeleteRule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCacheAPI_HandleDeleteRule_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/cache/rules/test", nil)
	api.handleDeleteRule(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandleListPresets(t *testing.T) {
	// HandleListPresets doesn't require a manager
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/presets", nil)
	api.handleListPresets(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "presets")
	assert.Contains(t, resp, "count")

	presets := resp["presets"].([]interface{})
	assert.Greater(t, len(presets), 0)
}

func TestCacheAPI_HandleListPresets_WithManager(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Add a rule from a preset
	preset, _ := cache.GetPresetByString("steam")
	rule := cache.PresetToRule(preset)
	mgr.Rules().Add(rule)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cache/presets", nil)
	api.handleListPresets(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Verify some preset is marked as enabled
	presets := resp["presets"].([]interface{})
	foundEnabled := false
	for _, p := range presets {
		preset := p.(map[string]interface{})
		if preset["name"] == "steam" && preset["enabled"].(bool) {
			foundEnabled = true
			break
		}
	}
	assert.True(t, foundEnabled, "Steam preset should be marked as enabled")
}

func TestCacheAPI_HandleEnablePreset(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	router := chi.NewRouter()
	router.Post("/api/v1/cache/presets/{name}/enable", api.handleEnablePreset)

	req := httptest.NewRequest("POST", "/api/v1/cache/presets/steam/enable", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "enabled")

	// Verify preset was added as a rule
	rule := mgr.Rules().Get("steam")
	assert.NotNil(t, rule)
}

func TestCacheAPI_HandleEnablePreset_AlreadyEnabled(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Enable the preset first
	preset, _ := cache.GetPresetByString("steam")
	rule := cache.PresetToRule(preset)
	mgr.Rules().Add(rule)

	router := chi.NewRouter()
	router.Post("/api/v1/cache/presets/{name}/enable", api.handleEnablePreset)

	req := httptest.NewRequest("POST", "/api/v1/cache/presets/steam/enable", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "already enabled")
}

func TestCacheAPI_HandleEnablePreset_NotFound(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	router := chi.NewRouter()
	router.Post("/api/v1/cache/presets/{name}/enable", api.handleEnablePreset)

	req := httptest.NewRequest("POST", "/api/v1/cache/presets/nonexistent/enable", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCacheAPI_HandleEnablePreset_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/presets/steam/enable", nil)
	api.handleEnablePreset(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_HandleDisablePreset(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	// Enable the preset first
	preset, _ := cache.GetPresetByString("steam")
	rule := cache.PresetToRule(preset)
	mgr.Rules().Add(rule)

	router := chi.NewRouter()
	router.Post("/api/v1/cache/presets/{name}/disable", api.handleDisablePreset)

	req := httptest.NewRequest("POST", "/api/v1/cache/presets/steam/disable", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify rule was disabled
	disabledRule := mgr.Rules().Get("steam")
	assert.NotNil(t, disabledRule)
	assert.False(t, disabledRule.Enabled)
}

func TestCacheAPI_HandleDisablePreset_NotEnabled(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	router := chi.NewRouter()
	router.Post("/api/v1/cache/presets/{name}/disable", api.handleDisablePreset)

	req := httptest.NewRequest("POST", "/api/v1/cache/presets/steam/disable", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCacheAPI_HandleDisablePreset_NilManager(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/presets/steam/disable", nil)
	api.handleDisablePreset(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCacheAPI_WriteJSON(t *testing.T) {
	api := NewCacheAPI(nil)

	w := httptest.NewRecorder()
	api.writeJSON(w, http.StatusOK, map[string]string{"test": "value"})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "value", resp["test"])
}

func TestCacheAPI_HandleAddRule_WithContentTypes(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	body := `{
		"name": "content-type-rule",
		"domains": ["*.example.com"],
		"enabled": true,
		"ttl": "1h",
		"content_types": ["image/*", "application/javascript"]
	}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader(body))
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)

	rule := mgr.Rules().Get("content-type-rule")
	assert.NotNil(t, rule)
	assert.Contains(t, rule.ContentTypes, "image/*")
}

func TestCacheAPI_HandleAddRule_WithMaxSize(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	body := `{
		"name": "max-size-rule",
		"domains": ["*.example.com"],
		"enabled": true,
		"max_size": "100MB"
	}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader(body))
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)

	rule := mgr.Rules().Get("max-size-rule")
	assert.NotNil(t, rule)
	assert.Equal(t, int64(100*1024*1024), rule.MaxSize)
}

func TestCacheAPI_HandleAddRule_FullOptions(t *testing.T) {
	mgr := createTestCacheManager(t)
	api := NewCacheAPI(mgr)

	body := `{
		"name": "full-options-rule",
		"domains": ["*.example.com", "cdn.example.org"],
		"enabled": true,
		"ttl": "24h",
		"priority": 100,
		"content_types": ["application/*"],
		"max_size": "50MB",
		"ignore_query": true,
		"respect_cache_control": true
	}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/cache/rules", strings.NewReader(body))
	api.handleAddRule(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)

	rule := mgr.Rules().Get("full-options-rule")
	assert.NotNil(t, rule)
	assert.Equal(t, "full-options-rule", rule.Name)
	assert.Len(t, rule.Domains, 2)
	assert.True(t, rule.Enabled)
	assert.Equal(t, 24*time.Hour, rule.TTL)
	assert.Equal(t, 100, rule.Priority)
	assert.True(t, rule.IgnoreQuery)
	assert.True(t, rule.RespectCacheControl)
}
