package server

import (
	"context"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/updater"
)

// defaultUpdateCheckInterval is used when auto_update.check_interval is unset or
// non-positive. It mirrors updater.DefaultConfig().
const defaultUpdateCheckInterval = 24 * time.Hour

// minUpdateCheckInterval is the lower bound enforced on the configured
// interval. The checker talks to the GitHub releases API, which is rate limited
// for unauthenticated clients, so a misconfigured tiny interval must not turn
// the daemon into a polling loop.
const minUpdateCheckInterval = 1 * time.Hour

// serverUpdateNotifier surfaces an available update from the background checker
// as an info-level log line. The server is headless, so a log entry (plus the
// operator's log pipeline) is the notification channel.
type serverUpdateNotifier struct{}

func (serverUpdateNotifier) NotifyUpdateAvailable(info updater.UpdateInfo) {
	logging.Info("Update available",
		"new_version", info.NewVersion,
		"current_version", info.CurrentVersion,
		"published_at", info.PublishedAt,
		"url", info.ReleaseURL,
	)
}

// updaterConfig translates the server's auto_update config block into an
// updater.Config, filling in defaults and clamping the check interval.
func (s *Server) updaterConfig() updater.Config {
	cfg := updater.DefaultConfig()
	cfg.Enabled = true

	interval := s.config.AutoUpdate.CheckInterval.Duration()
	switch {
	case interval <= 0:
		interval = defaultUpdateCheckInterval
	case interval < minUpdateCheckInterval:
		logging.Warn("auto_update.check_interval below minimum; clamping",
			"configured", interval,
			"minimum", minUpdateCheckInterval,
		)
		interval = minUpdateCheckInterval
	}
	cfg.CheckInterval = interval

	if channel := s.config.AutoUpdate.Channel; channel != "" {
		cfg.Channel = updater.Channel(channel)
	}

	return cfg
}

// startUpdater constructs the auto-updater from the server's auto_update config
// and starts the periodic background checker. It is only called when
// auto_update.enabled is true. Initialization errors are logged and the server
// continues without automatic update checks — a failed update check must never
// keep the proxy from serving traffic.
func (s *Server) startUpdater(ctx context.Context) {
	cfg := s.updaterConfig()

	u, err := updater.New(cfg, updater.BinaryTypeServer, serverUpdateNotifier{})
	if err != nil {
		logging.Error("Failed to initialize auto-updater", "error", err)
		return
	}

	s.mu.Lock()
	s.updater = u
	s.mu.Unlock()

	u.StartBackgroundChecker(ctx)
	logging.Info("Auto-update background checker started",
		"channel", cfg.Channel,
		"check_interval", cfg.CheckInterval,
	)
}

// stopUpdater stops the background update checker if one is running. Safe to
// call when auto-update is disabled.
func (s *Server) stopUpdater() {
	s.mu.Lock()
	u := s.updater
	s.updater = nil
	s.mu.Unlock()

	if u != nil {
		u.StopBackgroundChecker()
		logging.Debug("Auto-update background checker stopped")
	}
}
