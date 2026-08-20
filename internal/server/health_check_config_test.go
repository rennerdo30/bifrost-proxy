package server

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/health"
)

// TestHealthCheckConfig_ForwardsEveryField asserts the operator-facing health
// check block is fully forwarded to the runtime checker. A field present in both
// structs but missing from the mapping is silently inert at runtime — that is
// exactly how scheme/insecure_skip_verify ended up unreachable from config.
func TestHealthCheckConfig_ForwardsEveryField(t *testing.T) {
	hc := &config.HealthCheckConfig{
		Type:               config.HealthCheckTypeHTTP,
		Target:             "backend.internal:8443",
		Interval:           config.Duration(15 * time.Second),
		Timeout:            config.Duration(3 * time.Second),
		Path:               "/healthz",
		Scheme:             config.HealthCheckSchemeHTTPS,
		InsecureSkipVerify: true,
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
	}

	got := healthCheckConfig(hc)

	assert.Equal(t, health.Config{
		Type:               config.HealthCheckTypeHTTP,
		Target:             "backend.internal:8443",
		Interval:           15 * time.Second,
		Timeout:            3 * time.Second,
		Path:               "/healthz",
		Scheme:             config.HealthCheckSchemeHTTPS,
		InsecureSkipVerify: true,
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
	}, got)

	// Guard against a future health.Config field being added without being
	// wired through: with every source field set to a non-zero value, no
	// destination field may be left at its zero value.
	typ := reflect.TypeOf(got)
	val := reflect.ValueOf(got)
	for i := 0; i < typ.NumField(); i++ {
		assert.False(t, val.Field(i).IsZero(),
			"health.Config.%s was not forwarded by healthCheckConfig", typ.Field(i).Name)
	}
}

func TestHealthCheckConfig_Defaults(t *testing.T) {
	got := healthCheckConfig(&config.HealthCheckConfig{Type: "tcp", Target: "127.0.0.1:80"})

	require.Equal(t, "tcp", got.Type)
	assert.Empty(t, got.Scheme, "scheme must stay unset so the checker applies its own default")
	assert.False(t, got.InsecureSkipVerify)
	assert.Zero(t, got.HealthyThreshold)
	assert.Zero(t, got.UnhealthyThreshold)
}
