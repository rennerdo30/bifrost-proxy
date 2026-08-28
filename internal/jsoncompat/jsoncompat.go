// Package jsoncompat decodes JSON that may use either a struct's canonical
// snake_case keys or the legacy Go field names the same struct emitted before
// it had json tags.
//
// The VPN and mesh configuration structs shipped untagged for several
// releases, so every JSON export from that era says "SplitTunnel", "CacheTTL"
// or "HeartbeatInterval". encoding/json matches keys case-insensitively, which
// quietly covers single-word fields ("Mode" finds `json:"mode"`), but a
// multi-word field name never matches its snake_case tag — those values were
// silently dropped on import and reset to defaults. This package restores
// them, output stays canonical: marshaling is untouched.
package jsoncompat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Unmarshal decodes data into v, accepting the legacy Go field name for every
// struct field alongside its canonical json-tag key. When both keys are
// present with different values the input is ambiguous and rejected; equal
// values are tolerated. v must be a non-nil pointer to a struct — pass a
// local alias type from inside an UnmarshalJSON method to avoid recursion.
func Unmarshal(data []byte, v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("jsoncompat: target must be a non-nil pointer, got %T", v)
	}
	t := rv.Elem().Type()
	if t.Kind() != reflect.Struct {
		return json.Unmarshal(data, v)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		canonical := canonicalKey(f)
		if canonical == "" || canonical == f.Name {
			continue
		}
		legacyVal, hasLegacy := raw[f.Name]
		if !hasLegacy {
			continue
		}
		if canonVal, hasCanonical := raw[canonical]; hasCanonical {
			if !bytes.Equal(canonVal, legacyVal) {
				return fmt.Errorf("jsoncompat: keys %q and %q both present with different values", canonical, f.Name)
			}
		} else {
			raw[canonical] = legacyVal
		}
		delete(raw, f.Name)
	}

	normalized, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(normalized, v)
}

// canonicalKey returns the field's json key, or "" when the field is skipped.
func canonicalKey(f reflect.StructField) string {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	if name == "" {
		return f.Name
	}
	return name
}
