// Package server provides cache management API handlers.
package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rennerdo30/bifrost-proxy/internal/cache"
)

// CacheAPI provides cache management endpoints.
type CacheAPI struct {
	manager *cache.Manager
}

// NewCacheAPI creates a new cache API handler.
func NewCacheAPI(manager *cache.Manager) *CacheAPI {
	return &CacheAPI{
		manager: manager,
	}
}

// RegisterRoutes registers cache API routes on the given router.
func (c *CacheAPI) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/cache", func(r chi.Router) {
		r.Get("/stats", c.handleGetStats)
		r.Get("/entries", c.handleListEntries)
		r.Get("/entries/{key}", c.handleGetEntry)
		r.Delete("/entries/{key}", c.handleDeleteEntry)
		r.Delete("/entries", c.handleClearCache)
		r.Delete("/domain/{domain}", c.handlePurgeDomain)
		r.Get("/rules", c.handleListRules)
		r.Post("/rules", c.handleAddRule)
		r.Put("/rules/{name}", c.handleUpdateRule)
		r.Delete("/rules/{name}", c.handleDeleteRule)
		r.Get("/presets", c.handleListPresets)
		r.Post("/presets/{name}/enable", c.handleEnablePreset)
		r.Post("/presets/{name}/disable", c.handleDisablePreset)
	})
}

// handleGetStats returns cache statistics.
func (c *CacheAPI) handleGetStats(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"enabled": false,
			"error":   "Cache not configured",
		})
		return
	}

	stats := c.manager.Stats()
	c.writeJSON(w, http.StatusOK, stats)
}

// handleListEntries returns cached entries with optional filtering.
func (c *CacheAPI) handleListEntries(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"enabled": false,
			"error":   "Cache not configured",
		})
		return
	}

	// Parse query parameters
	domain := r.URL.Query().Get("domain")
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")

	offset := 0
	limit := 100

	if offsetStr != "" {
		if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
			offset = v
		}
	}

	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	// Get entries from storage
	entries, total, err := c.manager.Storage().List(r.Context(), domain, offset, limit)
	if err != nil {
		c.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Convert to response format
	response := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		response = append(response, map[string]interface{}{
			"key":          entry.Key,
			"url":          entry.URL,
			"host":         entry.Host,
			"size":         entry.Size,
			"content_type": entry.ContentType,
			"created_at":   entry.CreatedAt.Format(time.RFC3339),
			"expires_at":   entry.ExpiresAt.Format(time.RFC3339),
			"access_count": entry.AccessCount,
			"tier":         entry.Tier,
		})
	}

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": response,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
	})
}

// handleGetEntry returns metadata for a specific cache entry.
func (c *CacheAPI) handleGetEntry(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	key := chi.URLParam(r, "key")
	if key == "" {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Key is required",
		})
		return
	}

	meta, err := c.manager.Storage().GetMetadata(r.Context(), key)
	if err != nil {
		c.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Entry not found",
		})
		return
	}

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"key":          meta.Key,
		"url":          meta.URL,
		"host":         meta.Host,
		"status_code":  meta.StatusCode,
		"size":         meta.Size,
		"content_type": meta.ContentType,
		"etag":         meta.ETag,
		"created_at":   meta.CreatedAt.Format(time.RFC3339),
		"expires_at":   meta.ExpiresAt.Format(time.RFC3339),
		"accessed_at":  meta.AccessedAt.Format(time.RFC3339),
		"access_count": meta.AccessCount,
		"tier":         meta.Tier,
	})
}

// handleDeleteEntry deletes a specific cache entry.
func (c *CacheAPI) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	key := chi.URLParam(r, "key")
	if key == "" {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Key is required",
		})
		return
	}

	if err := c.manager.Delete(r.Context(), key); err != nil {
		c.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Entry deleted",
		"key":     key,
	})
}

// handleClearCache clears all cache entries.
func (c *CacheAPI) handleClearCache(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	// Require confirmation
	confirm := r.URL.Query().Get("confirm")
	if confirm != "true" {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Confirmation required",
			"message": "Add ?confirm=true to clear all cache entries",
		})
		return
	}

	if err := c.manager.Clear(r.Context()); err != nil {
		c.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Cache cleared",
		"time":    time.Now().Format(time.RFC3339),
	})
}

// handlePurgeDomain purges all entries for a domain.
func (c *CacheAPI) handlePurgeDomain(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	domain := chi.URLParam(r, "domain")
	if domain == "" {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Domain is required",
		})
		return
	}

	// Get all entries for the domain
	entries, _, err := c.manager.Storage().List(r.Context(), domain, 0, 0)
	if err != nil {
		c.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Delete each entry
	deleted := 0
	for _, entry := range entries {
		if err := c.manager.Delete(r.Context(), entry.Key); err == nil {
			deleted++
		}
	}

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Domain purged",
		"domain":  domain,
		"deleted": deleted,
	})
}

// handleListRules returns all caching rules.
func (c *CacheAPI) handleListRules(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	rules := c.manager.Rules().All()
	response := make([]map[string]interface{}, 0, len(rules))

	for _, rule := range rules {
		response = append(response, map[string]interface{}{
			"name":     rule.Name,
			"domains":  rule.Domains,
			"enabled":  rule.Enabled,
			"ttl":      rule.TTL.String(),
			"priority": rule.Priority,
			"preset":   rule.Preset,
		})
	}

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": response,
		"count": len(rules),
	})
}

// handleAddRule adds a new caching rule.
func (c *CacheAPI) handleAddRule(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	var req struct {
		Name                string   `json:"name"`
		Domains             []string `json:"domains"`
		Enabled             bool     `json:"enabled"`
		TTL                 string   `json:"ttl"`
		Priority            int      `json:"priority"`
		ContentTypes        []string `json:"content_types"`
		MaxSize             string   `json:"max_size"`
		IgnoreQuery         bool     `json:"ignore_query"`
		RespectCacheControl bool     `json:"respect_cache_control"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid JSON: " + err.Error(),
		})
		return
	}

	if req.Name == "" {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule name is required",
		})
		return
	}

	if len(req.Domains) == 0 {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "At least one domain is required",
		})
		return
	}

	// Create rule config
	ruleCfg := cache.RuleConfig{
		Name:                req.Name,
		Domains:             req.Domains,
		Enabled:             req.Enabled,
		Priority:            req.Priority,
		ContentTypes:        req.ContentTypes,
		IgnoreQuery:         req.IgnoreQuery,
		RespectCacheControl: req.RespectCacheControl,
	}

	// Parse TTL using JSON unmarshaling to leverage the Duration type
	if req.TTL != "" {
		var ttl cache.Duration
		if err := json.Unmarshal([]byte(`"`+req.TTL+`"`), &ttl); err != nil {
			c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": "Invalid TTL format: " + err.Error(),
			})
			return
		}
		ruleCfg.TTL = ttl
	}

	// Parse max size using JSON unmarshaling to leverage the ByteSize type
	if req.MaxSize != "" {
		var maxSize cache.ByteSize
		if err := json.Unmarshal([]byte(`"`+req.MaxSize+`"`), &maxSize); err != nil {
			c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": "Invalid max_size format: " + err.Error(),
			})
			return
		}
		ruleCfg.MaxSize = maxSize
	}

	// Create and add the rule
	rule, err := cache.NewRuleFromConfig(ruleCfg)
	if err != nil {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	c.manager.Rules().Add(rule)

	c.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "Rule added",
		"rule":    req.Name,
	})
}

// handleUpdateRule updates an existing rule.
func (c *CacheAPI) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	name := chi.URLParam(r, "name")
	if name == "" {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule name is required",
		})
		return
	}

	var req struct {
		Enabled *bool `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid JSON: " + err.Error(),
		})
		return
	}

	rule := c.manager.Rules().Get(name)
	if rule == nil {
		c.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Rule not found",
		})
		return
	}

	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Rule updated",
		"rule":    name,
		"enabled": rule.Enabled,
	})
}

// handleDeleteRule deletes a caching rule.
func (c *CacheAPI) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	name := chi.URLParam(r, "name")
	if name == "" {
		c.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule name is required",
		})
		return
	}

	if !c.manager.Rules().Remove(name) {
		c.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Rule not found",
		})
		return
	}

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Rule deleted",
		"rule":    name,
	})
}

// handleListPresets returns all available cache presets.
func (c *CacheAPI) handleListPresets(w http.ResponseWriter, r *http.Request) {
	presets := cache.AllPresets()
	response := make([]map[string]interface{}, 0, len(presets))

	// Get currently enabled presets
	enabledPresets := make(map[string]bool)
	if c.manager != nil {
		for _, rule := range c.manager.Rules().All() {
			if rule.Preset != "" {
				enabledPresets[rule.Preset] = true
			}
		}
	}

	for name, preset := range presets {
		response = append(response, map[string]interface{}{
			"name":        string(name),
			"description": preset.Description,
			"domains":     preset.Domains,
			"ttl":         preset.TTL.String(),
			"enabled":     enabledPresets[string(name)],
		})
	}

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"presets": response,
		"count":   len(presets),
	})
}

// handleEnablePreset enables a cache preset.
func (c *CacheAPI) handleEnablePreset(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	name := chi.URLParam(r, "name")
	preset, ok := cache.GetPresetByString(name)
	if !ok {
		c.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Preset not found",
		})
		return
	}

	// Check if already enabled
	existing := c.manager.Rules().Get(name)
	if existing != nil {
		existing.Enabled = true
		c.writeJSON(w, http.StatusOK, map[string]interface{}{
			"message": "Preset already enabled",
			"preset":  name,
		})
		return
	}

	// Add the preset as a rule
	rule := cache.PresetToRule(preset)
	c.manager.Rules().Add(rule)

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Preset enabled",
		"preset":  name,
	})
}

// handleDisablePreset disables a cache preset.
func (c *CacheAPI) handleDisablePreset(w http.ResponseWriter, r *http.Request) {
	if c.manager == nil {
		c.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Cache not configured",
		})
		return
	}

	name := chi.URLParam(r, "name")

	rule := c.manager.Rules().Get(name)
	if rule == nil {
		c.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "Preset not enabled",
			"message": "Use POST /api/v1/cache/presets/{name}/enable to enable first",
		})
		return
	}

	rule.Enabled = false

	c.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Preset disabled",
		"preset":  name,
	})
}

func (c *CacheAPI) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
