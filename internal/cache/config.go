package cache

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config contains all cache configuration settings.
type Config struct {
	// Enabled enables or disables caching.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// DefaultTTL is the default time-to-live for cached entries.
	DefaultTTL Duration `yaml:"default_ttl" json:"default_ttl"`

	// MaxFileSize is the maximum size of a single cached file.
	MaxFileSize ByteSize `yaml:"max_file_size" json:"max_file_size"`

	// Storage configures the storage backend.
	Storage StorageConfig `yaml:"storage" json:"storage"`

	// Presets are built-in cache rules for common CDNs.
	Presets []string `yaml:"presets,omitempty" json:"presets,omitempty"`

	// Rules are custom caching rules.
	Rules []RuleConfig `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// StorageConfig configures the cache storage backend.
type StorageConfig struct {
	// Type is the storage type: memory, disk, or tiered.
	Type string `yaml:"type" json:"type"`

	// Tiered contains tiered storage settings.
	Tiered *TieredConfig `yaml:"tiered,omitempty" json:"tiered,omitempty"`

	// Memory contains memory storage settings.
	Memory *MemoryConfig `yaml:"memory,omitempty" json:"memory,omitempty"`

	// Disk contains disk storage settings.
	Disk *DiskConfig `yaml:"disk,omitempty" json:"disk,omitempty"`
}

// TieredConfig configures tiered storage behavior.
type TieredConfig struct {
	// MemoryThreshold is the size threshold for memory vs disk storage.
	// Files smaller than this are stored in memory, larger in disk.
	MemoryThreshold ByteSize `yaml:"memory_threshold" json:"memory_threshold"`
}

// MemoryConfig configures in-memory storage.
type MemoryConfig struct {
	// MaxSize is the maximum total size of the memory cache.
	MaxSize ByteSize `yaml:"max_size" json:"max_size"`

	// MaxEntries is the maximum number of entries in memory.
	MaxEntries int `yaml:"max_entries" json:"max_entries"`

	// EvictPolicy is the eviction policy: lru, lfu, or fifo.
	EvictPolicy string `yaml:"evict_policy" json:"evict_policy"`
}

// DiskConfig configures disk storage.
type DiskConfig struct {
	// Path is the directory for storing cached files.
	Path string `yaml:"path" json:"path"`

	// MaxSize is the maximum total size of the disk cache.
	MaxSize ByteSize `yaml:"max_size" json:"max_size"`

	// CleanupInterval is how often to run cleanup of expired entries.
	CleanupInterval Duration `yaml:"cleanup_interval" json:"cleanup_interval"`

	// ShardCount is the number of subdirectories for sharding (default: 256).
	ShardCount int `yaml:"shard_count,omitempty" json:"shard_count,omitempty"`
}

// RuleConfig defines a caching rule.
type RuleConfig struct {
	// Name is the unique name for this rule.
	Name string `yaml:"name" json:"name"`

	// Domains are the domain patterns to match.
	Domains []string `yaml:"domains" json:"domains"`

	// Enabled enables or disables this rule.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TTL is the time-to-live for entries matching this rule.
	TTL Duration `yaml:"ttl" json:"ttl"`

	// MaxSize is the maximum file size to cache for this rule.
	MaxSize ByteSize `yaml:"max_size,omitempty" json:"max_size,omitempty"`

	// Priority determines which rule applies when multiple match.
	// Higher priority rules take precedence.
	Priority int `yaml:"priority" json:"priority"`

	// Methods are HTTP methods to cache (default: GET only).
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`

	// ContentTypes are MIME types to cache (empty = all).
	ContentTypes []string `yaml:"content_types,omitempty" json:"content_types,omitempty"`

	// IgnoreQuery ignores query string in cache key generation.
	IgnoreQuery bool `yaml:"ignore_query,omitempty" json:"ignore_query,omitempty"`

	// RespectCacheControl honors Cache-Control headers from origin.
	RespectCacheControl bool `yaml:"respect_cache_control,omitempty" json:"respect_cache_control,omitempty"`

	// StripHeaders removes these headers before caching.
	StripHeaders []string `yaml:"strip_headers,omitempty" json:"strip_headers,omitempty"`
}

// DefaultConfig returns a cache configuration with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:     false,
		DefaultTTL:  Duration(30 * 24 * time.Hour),     // 30 days
		MaxFileSize: ByteSize(50 * 1024 * 1024 * 1024), // 50GB
		Storage: StorageConfig{
			Type: "tiered",
			Tiered: &TieredConfig{
				MemoryThreshold: ByteSize(10 * 1024 * 1024), // 10MB
			},
			Memory: &MemoryConfig{
				MaxSize:     ByteSize(2 * 1024 * 1024 * 1024), // 2GB
				MaxEntries:  50000,
				EvictPolicy: "lru",
			},
			Disk: &DiskConfig{
				Path:            "/var/cache/bifrost",
				MaxSize:         ByteSize(500 * 1024 * 1024 * 1024), // 500GB
				CleanupInterval: Duration(1 * time.Hour),
				ShardCount:      256,
			},
		},
		Presets: []string{},
		Rules:   []RuleConfig{},
	}
}

// Validate validates the cache configuration.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil // Skip validation if disabled
	}

	switch c.Storage.Type {
	case "memory":
		if c.Storage.Memory == nil {
			return fmt.Errorf("memory storage config required when type is 'memory'")
		}
	case "disk":
		if c.Storage.Disk == nil {
			return fmt.Errorf("disk storage config required when type is 'disk'")
		}
		if c.Storage.Disk.Path == "" {
			return fmt.Errorf("disk storage path is required")
		}
	case "tiered":
		if c.Storage.Memory == nil {
			return fmt.Errorf("memory storage config required for tiered storage")
		}
		if c.Storage.Disk == nil {
			return fmt.Errorf("disk storage config required for tiered storage")
		}
		if c.Storage.Disk.Path == "" {
			return fmt.Errorf("disk storage path is required")
		}
	default:
		return fmt.Errorf("invalid storage type: %s (must be memory, disk, or tiered)", c.Storage.Type)
	}

	// Validate rules
	ruleNames := make(map[string]bool)
	for i, rule := range c.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule %d: name is required", i)
		}
		if ruleNames[rule.Name] {
			return fmt.Errorf("duplicate rule name: %s", rule.Name)
		}
		ruleNames[rule.Name] = true

		if len(rule.Domains) == 0 {
			return fmt.Errorf("rule %s: at least one domain pattern is required", rule.Name)
		}
	}

	return nil
}

// Duration is a time.Duration that can be unmarshaled from YAML/JSON strings.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	dur, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// parseDuration parses a duration string with extended support for days.
func parseDuration(s string) (time.Duration, error) {
	// Try standard parsing first
	if dur, err := time.ParseDuration(s); err == nil {
		return dur, nil
	}

	// Handle extended format with days (e.g., "30d", "7d12h")
	re := regexp.MustCompile(`^(\d+)d(.*)$`)
	if matches := re.FindStringSubmatch(s); len(matches) == 3 {
		days, _ := strconv.Atoi(matches[1]) //nolint:errcheck // Regex guarantees digits
		remainder := matches[2]
		daysDur := time.Duration(days) * 24 * time.Hour
		if remainder == "" {
			return daysDur, nil
		}
		remainderDur, err := time.ParseDuration(remainder)
		if err != nil {
			return 0, err
		}
		return daysDur + remainderDur, nil
	}

	return 0, fmt.Errorf("invalid duration: %s", s)
}

// ByteSize is a size in bytes that can be unmarshaled from human-readable strings.
type ByteSize int64

const (
	_           = iota
	KB ByteSize = 1 << (10 * iota)
	MB
	GB
	TB
	PB
)

func (b *ByteSize) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	size, err := parseByteSize(s)
	if err != nil {
		return err
	}
	*b = size
	return nil
}

func (b ByteSize) MarshalYAML() (interface{}, error) {
	return b.String(), nil
}

func (b ByteSize) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.String())
}

func (b *ByteSize) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// Try as number
		var n int64
		if err := json.Unmarshal(data, &n); err != nil {
			return err
		}
		*b = ByteSize(n)
		return nil
	}
	size, err := parseByteSize(s)
	if err != nil {
		return err
	}
	*b = size
	return nil
}

func (b ByteSize) String() string {
	switch {
	case b >= PB:
		return fmt.Sprintf("%.2fPB", float64(b)/float64(PB))
	case b >= TB:
		return fmt.Sprintf("%.2fTB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2fGB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2fMB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2fKB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func (b ByteSize) Int64() int64 {
	return int64(b)
}

// parseByteSize parses a human-readable size string (e.g., "10MB", "500GB").
func parseByteSize(s string) (ByteSize, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "0" {
		return 0, nil
	}

	// Find where the number ends and the unit begins
	var numStr string
	var unit string
	for i, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			numStr = s[:i]
			unit = strings.TrimSpace(s[i:])
			break
		}
	}
	if numStr == "" {
		numStr = s
	}

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size: %s", s)
	}

	var multiplier float64 = 1
	switch unit {
	case "", "B":
		multiplier = 1
	case "K", "KB", "KIB":
		multiplier = float64(KB)
	case "M", "MB", "MIB":
		multiplier = float64(MB)
	case "G", "GB", "GIB":
		multiplier = float64(GB)
	case "T", "TB", "TIB":
		multiplier = float64(TB)
	case "P", "PB", "PIB":
		multiplier = float64(PB)
	default:
		return 0, fmt.Errorf("invalid byte size unit: %s", unit)
	}

	return ByteSize(num * multiplier), nil
}
