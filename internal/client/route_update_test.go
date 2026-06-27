package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRouteUpdate(t *testing.T) {
	route, err := parseRouteUpdate(map[string]interface{}{
		"name":     "example",
		"domains":  []interface{}{"example.com", "*.example.com"},
		"action":   "direct",
		"priority": float64(5),
	})
	require.NoError(t, err)
	assert.Equal(t, "example", route.Name)
	assert.Equal(t, "direct", route.Action)
	assert.Equal(t, 5, route.Priority)
	assert.Equal(t, []string{"example.com", "*.example.com"}, route.Domains)
}

func TestParseRouteUpdate_DefaultsAction(t *testing.T) {
	route, err := parseRouteUpdate(map[string]interface{}{
		"name":    "example",
		"domains": []interface{}{"example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "server", route.Action)
}

func TestParseRouteUpdate_NoDomains(t *testing.T) {
	_, err := parseRouteUpdate(map[string]interface{}{
		"name":    "example",
		"domains": []interface{}{},
	})
	assert.Error(t, err)
}

func TestParseRouteUpdate_InvalidPayload(t *testing.T) {
	_, err := parseRouteUpdate("not-a-map")
	assert.Error(t, err)
}
