package debug

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// duration_ms must carry milliseconds: the raw time.Duration marshaled as
// nanoseconds under that name, making the traffic table off by a factor of a
// million.
func TestEntryJSON_DurationIsMilliseconds(t *testing.T) {
	data, err := json.Marshal(Entry{Duration: 1500 * time.Millisecond})
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.EqualValues(t, 1500, decoded["duration_ms"])
}
