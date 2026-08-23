package duration_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/rennerdo30/bifrost-proxy/internal/duration"
)

func TestMarshalJSONEmitsDurationString(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{"seconds", 30 * time.Second, `"30s"`},
		{"composite", 90 * time.Second, `"1m30s"`},
		{"minutes", 5 * time.Minute, `"5m0s"`},
		{"milliseconds", 250 * time.Millisecond, `"250ms"`},
		{"zero", 0, `"0s"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(duration.Duration(tt.in))
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(b))
		})
	}
}

func TestUnmarshalJSONAcceptsString(t *testing.T) {
	var d duration.Duration
	require.NoError(t, json.Unmarshal([]byte(`"1m30s"`), &d))
	assert.Equal(t, 90*time.Second, d.Duration())
}

func TestUnmarshalJSONAcceptsEmptyString(t *testing.T) {
	d := duration.Duration(time.Hour)
	require.NoError(t, json.Unmarshal([]byte(`""`), &d))
	assert.Equal(t, duration.Zero, d)
}

// TestUnmarshalJSONAcceptsNanosecondNumber covers payloads written against the
// previous representation, where a plain time.Duration marshalled as an integer.
func TestUnmarshalJSONAcceptsNanosecondNumber(t *testing.T) {
	var d duration.Duration
	require.NoError(t, json.Unmarshal([]byte(`30000000000`), &d))
	assert.Equal(t, 30*time.Second, d.Duration())
}

func TestUnmarshalJSONRejectsGarbage(t *testing.T) {
	var d duration.Duration
	require.Error(t, json.Unmarshal([]byte(`"not-a-duration"`), &d))
	require.Error(t, json.Unmarshal([]byte(`{}`), &d))
}

func TestJSONRoundTrip(t *testing.T) {
	original := duration.Duration(2*time.Hour + 15*time.Minute)
	b, err := json.Marshal(original)
	require.NoError(t, err)

	var back duration.Duration
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, original, back)
}

func TestYAMLRoundTrip(t *testing.T) {
	type holder struct {
		Interval duration.Duration `yaml:"interval"`
	}

	var h holder
	require.NoError(t, yaml.Unmarshal([]byte("interval: 45s\n"), &h))
	assert.Equal(t, 45*time.Second, h.Interval.Duration())

	out, err := yaml.Marshal(h)
	require.NoError(t, err)
	assert.Equal(t, "interval: 45s\n", string(out))
}

// TestUnmarshalYAMLAcceptsNanosecondNumber keeps configs that were written as
// bare integers (the representation gopkg.in/yaml.v3 accepts for time.Duration)
// loading unchanged.
func TestUnmarshalYAMLAcceptsNanosecondNumber(t *testing.T) {
	type holder struct {
		Interval duration.Duration `yaml:"interval"`
	}

	var h holder
	require.NoError(t, yaml.Unmarshal([]byte("interval: 30000000000\n"), &h))
	assert.Equal(t, 30*time.Second, h.Interval.Duration())
}

func TestUnmarshalYAMLRejectsGarbage(t *testing.T) {
	type holder struct {
		Interval duration.Duration `yaml:"interval"`
	}

	var h holder
	require.Error(t, yaml.Unmarshal([]byte("interval: nope\n"), &h))
	require.Error(t, yaml.Unmarshal([]byte("interval: [1, 2]\n"), &h))
}

func TestStringAndDuration(t *testing.T) {
	d := duration.Duration(90 * time.Second)
	assert.Equal(t, "1m30s", d.String())
	assert.Equal(t, 90*time.Second, d.Duration())
}
