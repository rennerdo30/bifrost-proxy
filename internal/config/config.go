// Package config provides configuration loading and validation for Bifrost.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// MaxRingBufferEntries is an upper sanity bound on operator-configured ring
// buffer sizes (e.g. debug.max_entries, api.request_log_size). These values
// size buffers allocated up front; they are trusted operator config rather than
// untrusted request input, but bounding them keeps worst-case memory
// predictable and rejects obvious misconfiguration at load time.
const MaxRingBufferEntries = 1_000_000

// EnvAllowUnknownKeys names the environment variable that downgrades unknown
// configuration keys from a load failure to a warning.
//
// Unknown keys are rejected by default: a misspelled or obsolete key that is
// silently ignored is indistinguishable, from the operator's seat, from a
// setting that does not work. This escape hatch exists so an unknown key cannot
// keep a previously running deployment from starting during an upgrade; it is a
// transitional measure and is documented as such.
const EnvAllowUnknownKeys = "BIFROST_CONFIG_ALLOW_UNKNOWN_KEYS"

const (
	// unknownKeyHint tells the operator how to get a deployment running again
	// while they clean up their config file.
	unknownKeyHint = "remove or correct the key, or set " + EnvAllowUnknownKeys +
		"=1 to downgrade unknown keys to warnings while migrating"
	// unknownKeyWarnHint is the counterpart used once the escape hatch is
	// already in effect, where repeating the opt-out would be nonsense.
	unknownKeyWarnHint = "this key has no effect; remove or correct it, as it will be rejected once " +
		EnvAllowUnknownKeys + " is unset"
)

// unknownFieldPattern matches the "field not found" diagnostics produced by
// gopkg.in/yaml.v3 when KnownFields(true) is set, e.g.
// `line 3: field listem not found in type config.ListenerConfig`.
var unknownFieldPattern = regexp.MustCompile(`^(?:line (\d+): )?field (.+) not found in type (.+)$`)

// UnknownKey is a configuration key that no setting corresponds to.
type UnknownKey struct {
	// Key is the key exactly as written in the config file.
	Key string
	// Section is the Go type the key was expected to belong to. It is the most
	// precise locator yaml.v3 gives us for the enclosing block.
	Section string
	// Line is the 1-based line in the (environment-expanded) config file.
	Line int
}

// String renders one unknown key as "line 3: \"listem\" (in ListenerConfig)".
func (k UnknownKey) String() string {
	var b strings.Builder
	if k.Line > 0 {
		b.WriteString("line ")
		b.WriteString(strconv.Itoa(k.Line))
		b.WriteString(": ")
	}
	b.WriteString(strconv.Quote(k.Key))
	if k.Section != "" {
		b.WriteString(" (in ")
		b.WriteString(k.Section)
		b.WriteString(")")
	}
	return b.String()
}

// UnknownKeysError reports configuration keys that Bifrost does not understand.
// It never includes config values, only key names and line numbers.
type UnknownKeysError struct {
	// Path is the config file the keys were found in.
	Path string
	// Keys lists every unknown key, in the order yaml.v3 reported them.
	Keys []UnknownKey
	// err is the underlying *yaml.TypeError.
	err error
}

// Error implements error.
func (e *UnknownKeysError) Error() string {
	keys := make([]string, 0, len(e.Keys))
	for _, k := range e.Keys {
		keys = append(keys, k.String())
	}
	return fmt.Sprintf("config file %s contains %d unknown key(s): %s; %s",
		e.Path, len(e.Keys), strings.Join(keys, "; "), unknownKeyHint)
}

// Unwrap exposes the underlying YAML error.
func (e *UnknownKeysError) Unwrap() error { return e.err }

// Load reads and parses a configuration file into the given struct.
//
// Environment-variable references are expanded first (see ExpandEnvRefs), then
// the YAML is decoded strictly: a key that does not correspond to a setting is
// an error naming the key and its line, unless EnvAllowUnknownKeys is set.
func Load(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	expanded, warnings := ExpandEnvRefs(data)
	logEnvWarnings(path, warnings)

	return decodeStrict(path, expanded, v)
}

// DecodeStrict decodes YAML config bytes into v with the same key checking Load
// applies, without touching the filesystem or expanding environment variables.
// It is for callers that receive a config document from somewhere other than a
// file — an API request body, for instance — where silently dropping an
// unrecognized key is just as misleading as it is at startup. source names the
// document in error messages ("request body", a filename, ...).
func DecodeStrict(source string, data []byte, v any) error {
	return decodeStrict(source, data, v)
}

// ValidateKnownKeys applies the same unknown-key rejection KnownFields gives
// typed sections to a dynamic map[string]any section, by re-encoding the map
// and strict-decoding it into prototype (a pointer to a struct whose yaml tags
// enumerate every key the consumer reads). yaml.v3's KnownFields cannot see
// into map-typed fields, so without this a typo inside backends[].config or
// auth.providers[].config loaded silently — including security-sensitive keys
// such as a user's "disabled" flag. The EnvAllowUnknownKeys escape hatch
// applies here exactly as it does to file loading.
func ValidateKnownKeys(section string, m map[string]any, prototype any) error {
	if len(m) == 0 {
		return nil
	}
	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("%s: %w", section, err)
	}
	return decodeStrict(section, data, prototype)
}

// decodeStrict decodes YAML into v, rejecting unknown keys.
func decodeStrict(path string, data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	err := dec.Decode(v)
	switch {
	case err == nil:
		// Exactly one document: content after a `---` separator used to be
		// silently ignored, which is another way for a setting to look
		// configured while nothing reads it.
		var extra any
		if extraErr := dec.Decode(&extra); !errors.Is(extraErr, io.EOF) {
			return fmt.Errorf("config %s contains more than one YAML document; everything after the first `---` separator would be ignored", path)
		}
		return nil
	case errors.Is(err, io.EOF):
		// An empty or comment-only file leaves the defaults in place, which is
		// what yaml.Unmarshal did before.
		return nil
	}

	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	unknown, other := splitUnknownFieldErrors(typeErr.Errors)

	if len(unknown) > 0 && !allowUnknownKeys() {
		unknownErr := &UnknownKeysError{Path: path, Keys: unknown, err: typeErr}
		if len(other) == 0 {
			return unknownErr
		}
		return fmt.Errorf("%w; additional problems: %s", unknownErr, strings.Join(other, "; "))
	}

	for _, k := range unknown {
		slog.Warn("ignoring unknown configuration key",
			slog.String("config", path),
			slog.Int("line", k.Line),
			slog.String("key", k.Key),
			slog.String("section", k.Section),
			slog.String("hint", unknownKeyWarnHint),
		)
	}

	if len(other) > 0 {
		return fmt.Errorf("failed to parse config file %s: %s", path, strings.Join(other, "; "))
	}
	return nil
}

// splitUnknownFieldErrors partitions yaml.v3 type errors into unknown-key
// findings and everything else (genuine type mismatches, which always fail).
func splitUnknownFieldErrors(errs []string) (unknown []UnknownKey, other []string) {
	for _, e := range errs {
		m := unknownFieldPattern.FindStringSubmatch(e)
		if m == nil {
			other = append(other, e)
			continue
		}
		line, err := strconv.Atoi(m[1])
		if err != nil {
			line = 0
		}
		unknown = append(unknown, UnknownKey{
			Key:     m[2],
			Section: strings.TrimPrefix(m[3], "config."),
			Line:    line,
		})
	}
	return unknown, other
}

// allowUnknownKeys reports whether the operator opted out of strict key
// checking via EnvAllowUnknownKeys.
func allowUnknownKeys() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvAllowUnknownKeys))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// logEnvWarnings reports environment-expansion diagnostics. Only key metadata
// (file, line, variable name) is logged, never config content, which may
// contain credentials.
func logEnvWarnings(path string, warnings []EnvWarning) {
	for _, w := range warnings {
		attrs := []any{
			slog.String("config", path),
			slog.Int("line", w.Line),
			slog.String("kind", string(w.Kind)),
		}
		if w.Name != "" {
			attrs = append(attrs, slog.String("variable", w.Name))
		}
		slog.Warn(w.Message(), attrs...)
	}
}

// Save writes a configuration struct to a file.
func Save(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil { //nolint:gosec // G301: Config directory permissions are appropriate
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Escape dollar signs that would be read back as a variable reference, so
	// that a value such as "a${b}c" survives a save/load round trip.
	data = EscapeEnvRefs(data)

	// Use 0600 permissions - config files may contain sensitive data (passwords, tokens)
	if err := os.WriteFile(path, data, 0600); err != nil { //nolint:gosec // G302: Config file permissions are restricted
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates the given configuration using validator functions.
type Validator interface {
	Validate() error
}

// ValidateConfig validates a configuration if it implements Validator.
func ValidateConfig(v any) error {
	if validator, ok := v.(Validator); ok {
		return validator.Validate()
	}
	return nil
}

// LoadAndValidate loads and validates a configuration file.
func LoadAndValidate(path string, v any) error {
	if err := Load(path, v); err != nil {
		return err
	}
	return ValidateConfig(v)
}

// Backup creates a timestamped backup of the config file.
func Backup(path string) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.backup.%s", path, timestamp)

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read config: %w", err)
	}

	// Use 0600 permissions - config files may contain sensitive data (passwords, tokens)
	if err := os.WriteFile(backupPath, data, 0600); err != nil { //nolint:gosec // G302: Config file permissions are restricted
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	return backupPath, nil
}
