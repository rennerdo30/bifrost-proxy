package cache

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Manager coordinates caching operations.
type Manager struct {
	mu sync.RWMutex

	// config is the cache configuration.
	config *Config

	// storage is the underlying storage backend.
	storage Storage

	// rules manages caching rules.
	rules *RuleSet

	// keyGen generates cache keys.
	keyGen *KeyGenerator

	// defaultTTL is the default time-to-live for cached entries.
	defaultTTL time.Duration

	// maxFileSize is the maximum file size to cache.
	maxFileSize int64

	// running indicates if the manager is started.
	running bool
}

// NewManager creates a new cache manager.
func NewManager(cfg *Config) (*Manager, error) {
	if cfg == nil {
		defaultCfg := DefaultConfig()
		cfg = &defaultCfg
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid cache config: %w", err)
	}

	// Create storage based on config
	storage, err := createStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create rule set
	rules := NewRuleSet()

	// Load presets
	for _, presetName := range cfg.Presets {
		preset, ok := GetPresetByString(presetName)
		if !ok {
			slog.Warn("unknown cache preset", "preset", presetName)
			continue
		}
		rules.Add(PresetToRule(preset))
		slog.Info("loaded cache preset", "preset", presetName)
	}

	// Load custom rules
	for _, ruleCfg := range cfg.Rules {
		rule, err := NewRuleFromConfig(ruleCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create rule %s: %w", ruleCfg.Name, err)
		}
		rules.Add(rule)
		slog.Info("loaded cache rule", "rule", ruleCfg.Name, "enabled", ruleCfg.Enabled)
	}

	return &Manager{
		config:      cfg,
		storage:     storage,
		rules:       rules,
		keyGen:      DefaultKeyGenerator(),
		defaultTTL:  cfg.DefaultTTL.Duration(),
		maxFileSize: cfg.MaxFileSize.Int64(),
	}, nil
}

// createStorage creates the appropriate storage backend.
func createStorage(cfg *Config) (Storage, error) {
	switch cfg.Storage.Type {
	case "memory":
		return NewMemoryStorage(cfg.Storage.Memory), nil
	case "disk":
		return NewDiskStorage(cfg.Storage.Disk)
	case "tiered":
		return NewTieredStorage(cfg.Storage.Tiered, cfg.Storage.Memory, cfg.Storage.Disk)
	default:
		return nil, fmt.Errorf("unknown storage type: %s", cfg.Storage.Type)
	}
}

// Start starts the cache manager.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	if err := m.storage.Start(ctx); err != nil {
		return fmt.Errorf("failed to start storage: %w", err)
	}

	m.running = true
	slog.Info("cache manager started",
		"enabled", m.config.Enabled,
		"storage_type", m.config.Storage.Type,
		"rules_count", len(m.rules.All()),
	)

	return nil
}

// Stop stops the cache manager.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	if err := m.storage.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop storage: %w", err)
	}

	m.running = false
	slog.Info("cache manager stopped")

	return nil
}

// IsEnabled returns whether caching is enabled.
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.Enabled && m.running
}

// ShouldCache checks if a request should be cached.
func (m *Manager) ShouldCache(req *http.Request) bool {
	if !m.IsEnabled() {
		return false
	}

	// Only cache GET requests by default
	if req.Method != http.MethodGet {
		return false
	}

	// Check if a rule matches
	rule := m.rules.Match(req)
	return rule != nil && rule.Enabled
}

// Get retrieves a cached response for a request.
// Returns nil if not found or expired.
func (m *Manager) Get(ctx context.Context, req *http.Request) (*Entry, error) {
	if !m.IsEnabled() {
		return nil, ErrNotFound
	}

	rule := m.rules.Match(req)
	if rule == nil {
		return nil, ErrNotFound
	}

	// Generate cache key
	m.keyGen.IgnoreQuery = rule.IgnoreQuery
	key := m.keyGen.GenerateKey(req)

	entry, err := m.storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	// Check if still fresh
	if entry.Metadata.IsExpired() {
		_ = m.storage.Delete(ctx, key) //nolint:errcheck // Best effort cleanup of expired entry
		return nil, ErrNotFound
	}

	slog.Debug("cache hit",
		"key", truncateKey(key),
		"host", req.Host,
		"path", req.URL.Path,
	)

	return entry, nil
}

// Put stores a response in the cache.
func (m *Manager) Put(ctx context.Context, req *http.Request, resp *http.Response, body io.ReadCloser) error {
	if !m.IsEnabled() {
		return nil
	}

	// Find matching rule
	rule := m.rules.Match(req)
	if rule == nil {
		return nil
	}

	// Check status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil
	}

	// Check content type if rule specifies
	if len(rule.ContentTypes) > 0 {
		contentType := resp.Header.Get("Content-Type")
		if !rule.MatchesContentType(contentType) {
			return nil
		}
	}

	// Check content length
	contentLength := resp.ContentLength
	if contentLength > 0 {
		if m.maxFileSize > 0 && contentLength > m.maxFileSize {
			slog.Debug("content too large for cache",
				"content_length", contentLength,
				"max_size", m.maxFileSize,
			)
			return nil
		}
		if rule.MaxSize > 0 && contentLength > rule.MaxSize {
			slog.Debug("content too large for rule",
				"content_length", contentLength,
				"rule_max_size", rule.MaxSize,
			)
			return nil
		}
	}

	// Check Cache-Control if rule respects it
	if rule.RespectCacheControl {
		cc := ParseCacheControl(resp.Header.Get("Cache-Control"))
		if cc != nil && (cc.NoStore || cc.Private) {
			return nil
		}
	}

	// Generate cache key
	m.keyGen.IgnoreQuery = rule.IgnoreQuery
	key := m.keyGen.GenerateKey(req)

	// Build metadata
	now := time.Now()
	ttl := rule.TTL
	if ttl == 0 {
		ttl = m.defaultTTL
	}

	// Check for Cache-Control max-age if respecting it
	if rule.RespectCacheControl {
		cc := ParseCacheControl(resp.Header.Get("Cache-Control"))
		if cc != nil && cc.MaxAge > 0 {
			maxAgeTTL := time.Duration(cc.MaxAge) * time.Second
			if maxAgeTTL < ttl {
				ttl = maxAgeTTL
			}
		}
	}

	// Build headers to cache (strip sensitive ones)
	headers := make(http.Header)
	for k, v := range resp.Header {
		k = http.CanonicalHeaderKey(k)
		// Skip sensitive headers
		if isSensitiveHeader(k) {
			continue
		}
		// Skip headers rule wants to strip
		if rule.ShouldStripHeader(k) {
			continue
		}
		headers[k] = v
	}

	metadata := &Metadata{
		Key:           key,
		URL:           req.URL.String(),
		Host:          req.Host,
		Method:        req.Method,
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		ContentLength: contentLength,
		ContentType:   resp.Header.Get("Content-Type"),
		ETag:          resp.Header.Get("ETag"),
		CacheControl:  ParseCacheControl(resp.Header.Get("Cache-Control")),
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
		AccessedAt:    now,
		AccessCount:   0,
	}

	// Parse Last-Modified
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			metadata.LastModified = t
		}
	}

	entry := &Entry{
		Metadata: metadata,
		Body:     body,
	}

	if err := m.storage.Put(ctx, key, entry); err != nil {
		slog.Error("failed to store in cache",
			"key", truncateKey(key),
			"error", err,
		)
		return err
	}

	slog.Debug("cached response",
		"key", truncateKey(key),
		"host", req.Host,
		"path", req.URL.Path,
		"size", contentLength,
		"ttl", ttl,
	)

	return nil
}

// Delete removes an entry from the cache.
func (m *Manager) Delete(ctx context.Context, key string) error {
	return m.storage.Delete(ctx, key)
}

// Clear removes all entries from the cache.
func (m *Manager) Clear(ctx context.Context) error {
	return m.storage.Clear(ctx)
}

// Stats returns cache statistics.
func (m *Manager) Stats() CacheStats {
	storageStats := m.storage.Stats()

	return CacheStats{
		Enabled:          m.IsEnabled(),
		StorageType:      m.config.Storage.Type,
		Entries:          storageStats.Entries,
		TotalSize:        storageStats.TotalSize,
		MaxSize:          storageStats.MaxSize,
		UsedPercent:      storageStats.UsedPercent,
		HitCount:         storageStats.HitCount,
		MissCount:        storageStats.MissCount,
		HitRate:          storageStats.HitRate(),
		EvictionCount:    storageStats.EvictionCount,
		RulesCount:       len(m.rules.All()),
		PresetsCount:     len(m.config.Presets),
		CustomRulesCount: len(m.config.Rules),
	}
}

// Rules returns the rule set.
func (m *Manager) Rules() *RuleSet {
	return m.rules
}

// Storage returns the storage backend (for advanced operations).
func (m *Manager) Storage() Storage {
	return m.storage
}

// Reload hot-reloads cache rules from config.
func (m *Manager) Reload(cfg *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid cache config: %w", err)
	}

	// Create new rule set
	rules := NewRuleSet()

	// Load presets
	for _, presetName := range cfg.Presets {
		preset, ok := GetPresetByString(presetName)
		if !ok {
			slog.Warn("unknown cache preset", "preset", presetName)
			continue
		}
		rules.Add(PresetToRule(preset))
	}

	// Load custom rules
	for _, ruleCfg := range cfg.Rules {
		rule, err := NewRuleFromConfig(ruleCfg)
		if err != nil {
			return fmt.Errorf("failed to create rule %s: %w", ruleCfg.Name, err)
		}
		rules.Add(rule)
	}

	m.rules = rules
	m.config = cfg
	m.defaultTTL = cfg.DefaultTTL.Duration()
	m.maxFileSize = cfg.MaxFileSize.Int64()

	slog.Info("cache rules reloaded", "rules_count", len(rules.All()))
	return nil
}

// CacheStats holds overall cache statistics.
type CacheStats struct {
	Enabled          bool    `json:"enabled"`
	StorageType      string  `json:"storage_type"`
	Entries          int64   `json:"entries"`
	TotalSize        int64   `json:"total_size_bytes"`
	MaxSize          int64   `json:"max_size_bytes"`
	UsedPercent      float64 `json:"used_percent"`
	HitCount         int64   `json:"hit_count"`
	MissCount        int64   `json:"miss_count"`
	HitRate          float64 `json:"hit_rate"`
	EvictionCount    int64   `json:"eviction_count"`
	RulesCount       int     `json:"rules_count"`
	PresetsCount     int     `json:"presets_count"`
	CustomRulesCount int     `json:"custom_rules_count"`
}

// isSensitiveHeader checks if a header should not be cached.
func isSensitiveHeader(header string) bool {
	sensitive := []string{
		"Authorization",
		"Cookie",
		"Set-Cookie",
		"Proxy-Authorization",
		"Proxy-Authenticate",
		"WWW-Authenticate",
	}

	header = strings.ToLower(header)
	for _, s := range sensitive {
		if strings.ToLower(s) == header {
			return true
		}
	}
	return false
}

// GetKeyGenerator returns the key generator.
func (m *Manager) GetKeyGenerator() *KeyGenerator {
	return m.keyGen
}

// KeyFor generates a cache key for a request.
func (m *Manager) KeyFor(req *http.Request) string {
	rule := m.rules.Match(req)
	if rule != nil {
		m.keyGen.IgnoreQuery = rule.IgnoreQuery
	}
	return m.keyGen.GenerateKey(req)
}
