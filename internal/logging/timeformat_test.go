package logging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logging.time_format was documented, defaulted and never read: slog's
// handlers used their own fixed timestamp format. It must now shape the
// timestamp in both output formats.
func TestSetup_TimeFormatIsApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	require.NoError(t, Setup(Config{
		Level:      "info",
		Format:     "text",
		Output:     path,
		TimeFormat: "2006/01/02-15:04",
	}))
	Info("time format probe")
	require.NoError(t, Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	line := string(data)
	// The custom layout uses slashes and a dash; slog's default RFC3339 form
	// would contain a "T" separator and colon-separated offset instead.
	assert.Regexp(t, `time=\d{4}/\d{2}/\d{2}-\d{2}:\d{2}`, line,
		"the configured layout must shape the timestamp, got: %s", line)

	// Restore a sane default for other tests.
	require.NoError(t, Setup(DefaultConfig()))
}
