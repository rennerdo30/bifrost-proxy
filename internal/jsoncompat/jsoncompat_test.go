package jsoncompat

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type inner struct {
	CacheTTL string `json:"cache_ttl"`
}

type outer struct {
	SplitTunnel string `json:"split_tunnel"`
	Mode        string `json:"mode"`
	Nested      inner  `json:"nested"`
	Skipped     string `json:"-"`
	untagged    string
}

func decode(t *testing.T, data string) outer {
	t.Helper()
	var v outer
	require.NoError(t, Unmarshal([]byte(data), &v))
	return v
}

func TestUnmarshal_CanonicalKeys(t *testing.T) {
	v := decode(t, `{"split_tunnel":"a","mode":"b","nested":{"cache_ttl":"5m"}}`)
	assert.Equal(t, "a", v.SplitTunnel)
	assert.Equal(t, "b", v.Mode)
	assert.Equal(t, "5m", v.Nested.CacheTTL)
}

func TestUnmarshal_LegacyGoFieldNames(t *testing.T) {
	v := decode(t, `{"SplitTunnel":"a","Mode":"b"}`)
	assert.Equal(t, "a", v.SplitTunnel)
	assert.Equal(t, "b", v.Mode)
}

func TestUnmarshal_ConflictingKeysRejected(t *testing.T) {
	var v outer
	err := Unmarshal([]byte(`{"split_tunnel":"a","SplitTunnel":"b"}`), &v)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "split_tunnel")
	assert.Contains(t, err.Error(), "SplitTunnel")
}

func TestUnmarshal_EqualDuplicatesTolerated(t *testing.T) {
	v := decode(t, `{"split_tunnel":"a","SplitTunnel":"a"}`)
	assert.Equal(t, "a", v.SplitTunnel)
}

func TestUnmarshal_NullAndEmptyAreNoOps(t *testing.T) {
	v := outer{Mode: "keep"}
	require.NoError(t, Unmarshal([]byte("null"), &v))
	assert.Equal(t, "keep", v.Mode)
}

func TestUnmarshal_UnknownKeysStayIgnored(t *testing.T) {
	v := decode(t, `{"mode":"b","something_else":1}`)
	assert.Equal(t, "b", v.Mode)
}

func TestUnmarshal_RejectsNonPointer(t *testing.T) {
	require.Error(t, Unmarshal([]byte(`{}`), outer{}))
	var p *outer
	require.Error(t, Unmarshal([]byte(`{}`), p))
}

func TestUnmarshal_InvalidJSON(t *testing.T) {
	var v outer
	require.Error(t, Unmarshal([]byte(`{`), &v))
}

// A field skipped with json:"-" must never be resurrected via its Go name.
func TestUnmarshal_SkippedFieldStaysSkipped(t *testing.T) {
	v := decode(t, `{"Skipped":"x"}`)
	assert.Empty(t, v.Skipped)
}

// An unexported field must never be populated, whatever key the input uses.
// This also gives the field a real assertion: it previously existed only to
// document the behavior and carried a nolint to keep the linters quiet, which
// the standalone staticcheck step does not honor anyway.
func TestUnmarshal_UnexportedFieldIsNeverPopulated(t *testing.T) {
	for _, input := range []string{`{"untagged":"x"}`, `{"Untagged":"x"}`} {
		v := decode(t, input)
		assert.Empty(t, v.untagged, "input: %s", input)
	}
}

// Marshaling is untouched: output is always canonical.
func TestMarshal_StaysCanonical(t *testing.T) {
	out, err := json.Marshal(outer{SplitTunnel: "a"})
	require.NoError(t, err)
	assert.Contains(t, string(out), `"split_tunnel"`)
	assert.NotContains(t, string(out), `"SplitTunnel"`)
}
