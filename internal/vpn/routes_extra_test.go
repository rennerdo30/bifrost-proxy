package vpn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// routeAlreadyExists is what lets Setup distinguish "the desired route is
// already present" (the desired state) from a real failure that must be fatal.
func TestRouteAlreadyExists(t *testing.T) {
	assert.True(t, routeAlreadyExists("route: writing to routing socket: File exists"))
	assert.True(t, routeAlreadyExists("RTNETLINK answers: File exists"))
	assert.True(t, routeAlreadyExists("The route addition failed: The object already exists."))
	assert.True(t, routeAlreadyExists("Element already exists"))

	assert.False(t, routeAlreadyExists("route: writing to routing socket: Network is unreachable"))
	assert.False(t, routeAlreadyExists("RTNETLINK answers: Operation not permitted"))
	assert.False(t, routeAlreadyExists("The requested operation requires elevation."))
	assert.False(t, routeAlreadyExists(""))
}
