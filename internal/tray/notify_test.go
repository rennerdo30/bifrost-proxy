package tray

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNotifier records notifications for assertions.
type mockNotifier struct {
	title   string
	message string
	calls   int
	err     error
}

func (m *mockNotifier) Notify(title, message string) error {
	m.calls++
	m.title = title
	m.message = message
	return m.err
}

func TestTrayNotify(t *testing.T) {
	tr := New(Config{})
	mock := &mockNotifier{}
	tr.SetNotifier(mock)

	err := tr.Notify("Bifrost", "Connected")
	require.NoError(t, err)
	assert.Equal(t, 1, mock.calls)
	assert.Equal(t, "Bifrost", mock.title)
	assert.Equal(t, "Connected", mock.message)
}

func TestTrayNotifyPropagatesError(t *testing.T) {
	tr := New(Config{})
	wantErr := errors.New("boom")
	tr.SetNotifier(&mockNotifier{err: wantErr})

	err := tr.Notify("Bifrost", "Disconnected")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestTrayNotifyNilNotifierIsNoop(t *testing.T) {
	tr := New(Config{})
	tr.SetNotifier(nil)

	require.NoError(t, tr.Notify("Bifrost", "Connected"))
}

func TestNewSetsDefaultNotifier(t *testing.T) {
	tr := New(Config{})
	assert.NotNil(t, tr.notifier, "default notifier should be set")

	tr2 := NewWithAdapter(Config{}, newMockAdapter())
	assert.NotNil(t, tr2.notifier, "default notifier should be set for adapter constructor")
}

func TestOSNotifierNotify(t *testing.T) {
	// The osNotifier shells out to a platform command. We cannot assert a
	// notification actually appears in CI, but Notify should return without
	// panicking. On platforms where the command is missing it returns an error;
	// either outcome is acceptable here, we only guard against panics.
	n := &osNotifier{}
	_ = n.Notify("Test", "Message") //nolint:errcheck // best-effort; command may be absent in CI
}
