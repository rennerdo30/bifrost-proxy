package updater

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.Enabled)
	assert.Equal(t, 24*time.Hour, cfg.CheckInterval)
	assert.Equal(t, ChannelStable, cfg.Channel)
	assert.Equal(t, "rennerdo30", cfg.GitHubOwner)
	assert.Equal(t, "bifrost-proxy", cfg.GitHubRepo)
	assert.NotEmpty(t, cfg.StateFile)
}

func TestChannel_IsPrerelease(t *testing.T) {
	tests := []struct {
		name    string
		channel Channel
		want    bool
	}{
		{
			name:    "stable channel",
			channel: ChannelStable,
			want:    false,
		},
		{
			name:    "prerelease channel",
			channel: ChannelPrerelease,
			want:    true,
		},
		{
			name:    "unknown channel",
			channel: Channel("unknown"),
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.channel.IsPrerelease()
			assert.Equal(t, tt.want, got)
		})
	}
}
