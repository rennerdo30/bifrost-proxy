package duration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// A nanosecond count that passed through map[string]interface{} becomes a
// float64 and YAML re-encodes it in scientific notation. Configs written that
// way by the old PUT path must keep loading.
func TestUnmarshalYAML_ScientificNotationFloat(t *testing.T) {
	var d Duration
	require.NoError(t, yaml.Unmarshal([]byte("3e+11"), &d))
	assert.Equal(t, 5*time.Minute, d.Duration())
}

func TestUnmarshalYAML_FractionalFloatRejected(t *testing.T) {
	var d Duration
	err := yaml.Unmarshal([]byte("1.5"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fractional")
}

func TestUnmarshalJSON_IntegralFloat(t *testing.T) {
	var d Duration
	require.NoError(t, json.Unmarshal([]byte("3e+11"), &d))
	assert.Equal(t, 5*time.Minute, d.Duration())
}

func TestUnmarshalJSON_FractionalFloatRejected(t *testing.T) {
	var d Duration
	err := json.Unmarshal([]byte("1.5"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fractional")
}

func TestUnmarshalJSON_OverflowRejected(t *testing.T) {
	var d Duration
	err := json.Unmarshal([]byte("1e300"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "overflows")
}
