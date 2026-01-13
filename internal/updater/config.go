package updater

import (
	"time"
)

// Config holds updater configuration.
type Config struct {
	// Enabled enables automatic update checking.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CheckInterval is how often to check for updates.
	CheckInterval time.Duration `yaml:"check_interval" json:"check_interval"`

	// Channel specifies which release channel to follow.
	Channel Channel `yaml:"channel" json:"channel"`

	// GitHubOwner is the GitHub repository owner.
	GitHubOwner string `yaml:"github_owner" json:"github_owner"`

	// GitHubRepo is the GitHub repository name.
	GitHubRepo string `yaml:"github_repo" json:"github_repo"`

	// StateFile is the path to the state file.
	StateFile string `yaml:"state_file" json:"state_file"`
}

// Channel specifies which release channel to follow.
type Channel string

const (
	// ChannelStable only includes stable releases.
	ChannelStable Channel = "stable"

	// ChannelPrerelease includes prereleases.
	ChannelPrerelease Channel = "prerelease"
)

// DefaultConfig returns a default configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:       false,
		CheckInterval: 24 * time.Hour,
		Channel:       ChannelStable,
		GitHubOwner:   "rennerdo30",
		GitHubRepo:    "bifrost-proxy",
		StateFile:     DefaultStatePath(),
	}
}

// IsPrerelease returns true if the channel includes prereleases.
func (c Channel) IsPrerelease() bool {
	return c == ChannelPrerelease
}
