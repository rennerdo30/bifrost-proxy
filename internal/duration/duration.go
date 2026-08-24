// Package duration provides a time.Duration wrapper that serializes to and from
// the human-readable Go duration syntax ("30s", "1m30s") in both YAML and JSON.
//
// The wire convention is identical to the one internal/config has always used for
// its own Duration type: MarshalJSON emits time.Duration.String() and UnmarshalJSON
// accepts anything time.ParseDuration accepts. It lives in its own package because
// internal/config imports internal/vpn and internal/mesh, so those two packages
// cannot import internal/config back without an import cycle.
package duration

import (
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that round-trips as a duration string.
//
// A bare number is also accepted on input and interpreted as nanoseconds, which
// keeps configs and API payloads written against the old, unmarshaled
// time.Duration representation working.
type Duration time.Duration

// Zero is the zero duration, used when an empty string is decoded.
const Zero = Duration(0)

// yamlIntTag is the YAML resolved tag for a plain integer scalar.
const yamlIntTag = "!!int"

// Duration returns the wrapped time.Duration.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// String returns the human-readable duration form, e.g. "1m30s".
func (d Duration) String() string {
	return time.Duration(d).String()
}

// MarshalJSON encodes the duration as a string, e.g. "30s".
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON decodes a duration string ("30s") or a bare number of nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		parsed, err := parse(s)
		if err != nil {
			return err
		}
		*d = parsed
		return nil
	}

	var ns int64
	if err := json.Unmarshal(b, &ns); err != nil {
		return fmt.Errorf("duration: expected a duration string or a number of nanoseconds, got %s", b)
	}
	*d = Duration(ns)
	return nil
}

// MarshalYAML encodes the duration as a string, e.g. "30s".
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// UnmarshalYAML decodes a duration string ("30s") or a bare number of nanoseconds.
//
// A plain YAML integer decodes into a string just as happily as into an int64, so
// the node tag decides which branch applies rather than trial decoding.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Tag == yamlIntTag {
		var ns int64
		if err := value.Decode(&ns); err != nil {
			return fmt.Errorf("duration: invalid nanosecond count at line %d: %w", value.Line, err)
		}
		*d = Duration(ns)
		return nil
	}

	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration: expected a duration string or a number of nanoseconds at line %d: %w", value.Line, err)
	}
	parsed, err := parse(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// parse converts a duration string to a Duration, treating "" as Zero.
func parse(s string) (Duration, error) {
	if s == "" {
		return Zero, nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return Zero, fmt.Errorf("duration: invalid duration %q: %w", s, err)
	}
	return Duration(parsed), nil
}
