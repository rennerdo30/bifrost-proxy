package service

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// commandRan is the classification the status helpers rely on: a tool that
// executed and answered non-zero is a meaningful state, a tool that could not
// be executed at all is an unknown state that must surface as an error —
// laundering the latter into "inactive"/"not installed" was the audit finding.
func TestCommandRan(t *testing.T) {
	// A command that runs and exits non-zero.
	err := exec.Command("sh", "-c", "exit 3").Run()
	require.Error(t, err)
	assert.True(t, commandRan(err), "a non-zero exit means the tool ran and answered")

	// A command that cannot be executed at all.
	err = exec.Command("/nonexistent/definitely-not-a-binary-bifrost-test").Run()
	require.Error(t, err)
	assert.False(t, commandRan(err), "a missing binary is an unknown state, not an answer")

	assert.False(t, commandRan(nil))
}
