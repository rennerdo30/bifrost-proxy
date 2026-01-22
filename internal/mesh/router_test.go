package mesh

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouteTypeString(t *testing.T) {
	tests := []struct {
		routeType RouteType
		expected  string
	}{
		{RouteTypeDirect, "direct"},
		{RouteTypeNextHop, "next_hop"},
		{RouteTypeRelay, "relay"},
		{RouteType(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.routeType.String())
		})
	}
}

func TestDefaultRouterConfig(t *testing.T) {
	config := DefaultRouterConfig()

	assert.Equal(t, 8, config.MaxHops)
	assert.Equal(t, 5*time.Minute, config.RouteTimeout)
	assert.NotNil(t, config.PathCostFunc)
}

func TestDefaultPathCostFunc(t *testing.T) {
	tests := []struct {
		latency  time.Duration
		hopCount int
		expected int
	}{
		{10 * time.Millisecond, 1, 110},  // 10 + 100
		{50 * time.Millisecond, 2, 250},  // 50 + 200
		{100 * time.Millisecond, 3, 400}, // 100 + 300
		{0, 1, 100},                      // 0 + 100
	}

	for _, tt := range tests {
		cost := DefaultPathCostFunc(tt.latency, tt.hopCount)
		assert.Equal(t, tt.expected, cost)
	}
}

func TestNewMeshRouter(t *testing.T) {
	t.Run("with default config", func(t *testing.T) {
		config := RouterConfig{
			LocalPeerID: "local-peer",
			LocalIP:     netip.MustParseAddr("10.100.0.1"),
		}

		router := NewMeshRouter(config)

		assert.NotNil(t, router)
		assert.Equal(t, "local-peer", router.localPeerID)
		assert.Equal(t, netip.MustParseAddr("10.100.0.1"), router.localIP)
		assert.NotNil(t, router.pathCostFunc)
	})

	t.Run("with custom config", func(t *testing.T) {
		customCostFunc := func(latency time.Duration, hopCount int) int {
			return hopCount * 50
		}

		config := RouterConfig{
			LocalPeerID:  "local-peer",
			LocalIP:      netip.MustParseAddr("10.100.0.1"),
			MaxHops:      4,
			RouteTimeout: 1 * time.Minute,
			PathCostFunc: customCostFunc,
		}

		router := NewMeshRouter(config)

		assert.Equal(t, 4, router.maxHops)
		assert.Equal(t, 1*time.Minute, router.routeTimeout)
		assert.Equal(t, 50, router.pathCostFunc(0, 1))
	})
}

func TestMeshRouterAddDirectRoute(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	peerID := "peer1"
	peerIP := netip.MustParseAddr("10.100.0.2")
	latency := 20 * time.Millisecond

	router.AddDirectRoute(peerID, peerIP, latency)

	// Verify route exists
	route := router.GetRoute(peerID)
	require.NotNil(t, route)
	assert.Equal(t, peerID, route.DestPeerID)
	assert.Equal(t, peerIP, route.DestIP)
	assert.Equal(t, RouteTypeDirect, route.Type)
	assert.Equal(t, latency, route.Latency)
	assert.Equal(t, 1, route.HopCount)
	assert.True(t, route.Active)
	assert.Empty(t, route.NextHop)

	// Verify by IP lookup
	routeByIP := router.GetRouteByIP(peerIP)
	require.NotNil(t, routeByIP)
	assert.Equal(t, peerID, routeByIP.DestPeerID)

	// Verify in direct peers
	assert.True(t, router.IsDirect(peerID))
	directPeers := router.GetDirectPeers()
	assert.Contains(t, directPeers, peerID)
}

func TestMeshRouterRemoveDirectRoute(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
	}

	router := NewMeshRouter(config)

	peerID := "peer1"
	peerIP := netip.MustParseAddr("10.100.0.2")

	router.AddDirectRoute(peerID, peerIP, 20*time.Millisecond)
	assert.True(t, router.IsDirect(peerID))

	router.RemoveDirectRoute(peerID)

	assert.False(t, router.IsDirect(peerID))
	assert.Nil(t, router.GetRoute(peerID))
	assert.Nil(t, router.GetRouteByIP(peerIP))
}

func TestMeshRouterAddRoute(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	route := &Route{
		DestPeerID: "peer1",
		DestIP:     netip.MustParseAddr("10.100.0.2"),
		NextHop:    "neighbor1",
		Type:       RouteTypeNextHop,
		Metric:     150,
		HopCount:   2,
		Active:     true,
	}

	router.AddRoute(route)

	retrieved := router.GetRoute("peer1")
	require.NotNil(t, retrieved)
	assert.Equal(t, "peer1", retrieved.DestPeerID)
	assert.Equal(t, "neighbor1", retrieved.NextHop)
	assert.Equal(t, RouteTypeNextHop, retrieved.Type)
}

func TestMeshRouterAddRouteExceedsMaxHops(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     4,
	}

	router := NewMeshRouter(config)

	route := &Route{
		DestPeerID: "peer1",
		DestIP:     netip.MustParseAddr("10.100.0.2"),
		NextHop:    "neighbor1",
		Type:       RouteTypeNextHop,
		Metric:     500,
		HopCount:   5, // Exceeds max
	}

	router.AddRoute(route)

	// Route should not be added
	assert.Nil(t, router.GetRoute("peer1"))
}

func TestMeshRouterAddRouteToSelf(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
	}

	router := NewMeshRouter(config)

	route := &Route{
		DestPeerID: "local-peer", // Self
		DestIP:     netip.MustParseAddr("10.100.0.1"),
		Type:       RouteTypeDirect,
	}

	router.AddRoute(route)

	// Route to self should not be added
	assert.Nil(t, router.GetRoute("local-peer"))
}

func TestMeshRouterUpdateExistingRoute(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	// Add initial route
	route1 := &Route{
		DestPeerID: "peer1",
		DestIP:     netip.MustParseAddr("10.100.0.2"),
		NextHop:    "neighbor1",
		Type:       RouteTypeNextHop,
		Metric:     200,
		HopCount:   2,
	}
	router.AddRoute(route1)

	// Update same route with better metric
	route2 := &Route{
		DestPeerID: "peer1",
		DestIP:     netip.MustParseAddr("10.100.0.2"),
		NextHop:    "neighbor1",
		Type:       RouteTypeNextHop,
		Metric:     150, // Better metric
		HopCount:   2,
	}
	router.AddRoute(route2)

	// Should have updated metric
	retrieved := router.GetRoute("peer1")
	require.NotNil(t, retrieved)
	assert.Equal(t, 150, retrieved.Metric)
}

func TestMeshRouterMultipleRoutesToSameDestination(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	// Add route via neighbor1 (worse)
	route1 := &Route{
		DestPeerID: "peer1",
		DestIP:     netip.MustParseAddr("10.100.0.2"),
		NextHop:    "neighbor1",
		Type:       RouteTypeNextHop,
		Metric:     200,
		HopCount:   3,
	}
	router.AddRoute(route1)

	// Add route via neighbor2 (better)
	route2 := &Route{
		DestPeerID: "peer1",
		DestIP:     netip.MustParseAddr("10.100.0.2"),
		NextHop:    "neighbor2",
		Type:       RouteTypeNextHop,
		Metric:     100, // Better metric
		HopCount:   2,
	}
	router.AddRoute(route2)

	// Best route should be returned
	best := router.GetRoute("peer1")
	require.NotNil(t, best)
	assert.Equal(t, "neighbor2", best.NextHop)
	assert.Equal(t, 100, best.Metric)

	// All routes should be in GetAllRoutes
	allRoutes := router.GetAllRoutes()
	assert.GreaterOrEqual(t, len(allRoutes), 2)
}

func TestMeshRouterGetNextHop(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	t.Run("direct route returns destination", func(t *testing.T) {
		router.AddDirectRoute("peer1", netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)

		nextHop := router.GetNextHop("peer1")
		assert.Equal(t, "peer1", nextHop)
	})

	t.Run("next-hop route returns next hop", func(t *testing.T) {
		route := &Route{
			DestPeerID: "peer2",
			DestIP:     netip.MustParseAddr("10.100.0.3"),
			NextHop:    "neighbor1",
			Type:       RouteTypeNextHop,
			Metric:     200,
			HopCount:   2,
		}
		router.AddRoute(route)

		nextHop := router.GetNextHop("peer2")
		assert.Equal(t, "neighbor1", nextHop)
	})

	t.Run("no route returns empty", func(t *testing.T) {
		nextHop := router.GetNextHop("nonexistent")
		assert.Empty(t, nextHop)
	})
}

func TestMeshRouterGetNextHopByIP(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
	}

	router := NewMeshRouter(config)

	peerIP := netip.MustParseAddr("10.100.0.2")
	router.AddDirectRoute("peer1", peerIP, 10*time.Millisecond)

	nextHop := router.GetNextHopByIP(peerIP)
	assert.Equal(t, "peer1", nextHop)

	// Nonexistent IP
	nextHop = router.GetNextHopByIP(netip.MustParseAddr("10.100.0.99"))
	assert.Empty(t, nextHop)
}

func TestMeshRouterUpdateLatency(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
	}

	router := NewMeshRouter(config)

	router.AddDirectRoute("peer1", netip.MustParseAddr("10.100.0.2"), 20*time.Millisecond)

	// Update latency
	router.UpdateLatency("peer1", 5*time.Millisecond)

	route := router.GetRoute("peer1")
	require.NotNil(t, route)
	assert.Equal(t, 5*time.Millisecond, route.Latency)
}

func TestMeshRouterExpireRoutes(t *testing.T) {
	config := RouterConfig{
		LocalPeerID:  "local-peer",
		LocalIP:      netip.MustParseAddr("10.100.0.1"),
		RouteTimeout: 50 * time.Millisecond,
	}

	router := NewMeshRouter(config)

	// Add direct route (should not expire)
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)

	// Add next-hop route (should expire)
	route := &Route{
		DestPeerID:  "peer2",
		DestIP:      netip.MustParseAddr("10.100.0.3"),
		NextHop:     "neighbor1",
		Type:        RouteTypeNextHop,
		Metric:      200,
		HopCount:    2,
		LastUpdated: time.Now().Add(-100 * time.Millisecond), // Already expired
	}
	router.AddRoute(route)

	router.ExpireRoutes()

	// Direct route should still exist
	assert.NotNil(t, router.GetRoute("peer1"))

	// Next-hop route should be expired
	assert.Nil(t, router.GetRoute("peer2"))
}

func TestMeshRouterRemoveRoutesViaDisconnectedPeer(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	// Add direct route to neighbor
	router.AddDirectRoute("neighbor1", netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)

	// Add route to peer3 via neighbor1
	route := &Route{
		DestPeerID: "peer3",
		DestIP:     netip.MustParseAddr("10.100.0.4"),
		NextHop:    "neighbor1",
		Type:       RouteTypeNextHop,
		Metric:     200,
		HopCount:   2,
	}
	router.AddRoute(route)

	// Verify routes exist
	assert.NotNil(t, router.GetRoute("neighbor1"))
	assert.NotNil(t, router.GetRoute("peer3"))

	// Remove direct route to neighbor
	router.RemoveDirectRoute("neighbor1")

	// Route via neighbor should also be removed
	assert.Nil(t, router.GetRoute("peer3"))
}

func TestMeshRouterOnRouteChanged(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
	}

	router := NewMeshRouter(config)

	var callbackCalled bool
	var callbackRoute *Route

	router.OnRouteChanged(func(route *Route) {
		callbackCalled = true
		callbackRoute = route
	})

	router.AddDirectRoute("peer1", netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)

	assert.True(t, callbackCalled)
	require.NotNil(t, callbackRoute)
	assert.Equal(t, "peer1", callbackRoute.DestPeerID)
}

func TestMeshRouterGetStats(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	// Empty stats
	stats := router.GetStats()
	assert.Equal(t, 0, stats.TotalRoutes)
	assert.Equal(t, 0, stats.DirectRoutes)
	assert.Equal(t, 0, stats.NextHopRoutes)
	assert.Equal(t, 0, stats.RelayRoutes)
	assert.Equal(t, 0, stats.Destinations)

	// Add routes
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)

	route := &Route{
		DestPeerID: "peer2",
		DestIP:     netip.MustParseAddr("10.100.0.3"),
		NextHop:    "peer1",
		Type:       RouteTypeNextHop,
		Metric:     200,
		HopCount:   2,
	}
	router.AddRoute(route)

	relayRoute := &Route{
		DestPeerID: "peer3",
		DestIP:     netip.MustParseAddr("10.100.0.4"),
		NextHop:    "relay1",
		Type:       RouteTypeRelay,
		Metric:     300,
		HopCount:   2,
	}
	router.AddRoute(relayRoute)

	stats = router.GetStats()
	assert.Equal(t, 3, stats.TotalRoutes)
	assert.Equal(t, 1, stats.DirectRoutes)
	assert.Equal(t, 1, stats.NextHopRoutes)
	assert.Equal(t, 1, stats.RelayRoutes)
	assert.Equal(t, 3, stats.Destinations)
}

func TestMeshRouterGetBestRoutes(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	// Add multiple routes to same destination
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)

	route1 := &Route{
		DestPeerID: "peer1",
		DestIP:     netip.MustParseAddr("10.100.0.2"),
		NextHop:    "neighbor1",
		Type:       RouteTypeNextHop,
		Metric:     500, // Worse than direct
		HopCount:   3,
	}
	router.AddRoute(route1)

	bestRoutes := router.GetBestRoutes()
	assert.Len(t, bestRoutes, 1)
	assert.Equal(t, RouteTypeDirect, bestRoutes[0].Type)
}

func TestMeshRouterGetForwardingTable(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	router.AddDirectRoute("peer1", netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)

	table := router.GetForwardingTable()
	assert.NotEmpty(t, table)

	// Find entry for peer1
	var foundEntry *ForwardingEntry
	for i := range table {
		if table[i].DestIP.Addr() == netip.MustParseAddr("10.100.0.2") {
			foundEntry = &table[i]
			break
		}
	}

	require.NotNil(t, foundEntry)
	assert.Equal(t, netip.MustParseAddr("10.100.0.2"), foundEntry.NextHopIP)
}

func TestMeshRouterGetAllRoutes(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	// Empty
	routes := router.GetAllRoutes()
	assert.Empty(t, routes)

	// Add routes
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)
	router.AddDirectRoute("peer2", netip.MustParseAddr("10.100.0.3"), 20*time.Millisecond)

	routes = router.GetAllRoutes()
	assert.Len(t, routes, 2)
}

func TestMeshRouterIsDirect(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)

	assert.False(t, router.IsDirect("peer1"))

	router.AddDirectRoute("peer1", netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)

	assert.True(t, router.IsDirect("peer1"))
	assert.False(t, router.IsDirect("peer2"))
}

func TestMeshRouterConcurrentAccess(t *testing.T) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
		MaxHops:     8,
	}

	router := NewMeshRouter(config)
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			peerID := "peer" + string(rune('A'+i%26))
			ip := netip.MustParseAddr(fmt.Sprintf("10.100.0.%d", 2+i%200))
			router.AddDirectRoute(peerID, ip, time.Duration(i)*time.Millisecond)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			peerID := "peer" + string(rune('A'+i%26))
			router.GetRoute(peerID)
			router.GetNextHop(peerID)
			router.GetStats()
			router.GetAllRoutes()
		}(i)
	}

	wg.Wait()
}

func TestRouteStruct(t *testing.T) {
	route := Route{
		DestPeerID:  "peer1",
		DestIP:      netip.MustParseAddr("10.100.0.2"),
		NextHop:     "neighbor1",
		Type:        RouteTypeNextHop,
		Metric:      200,
		Latency:     25 * time.Millisecond,
		HopCount:    2,
		LastUpdated: time.Now(),
		Active:      true,
	}

	assert.Equal(t, "peer1", route.DestPeerID)
	assert.Equal(t, netip.MustParseAddr("10.100.0.2"), route.DestIP)
	assert.Equal(t, "neighbor1", route.NextHop)
	assert.Equal(t, RouteTypeNextHop, route.Type)
	assert.Equal(t, 200, route.Metric)
	assert.Equal(t, 25*time.Millisecond, route.Latency)
	assert.Equal(t, 2, route.HopCount)
	assert.True(t, route.Active)
}

func TestForwardingEntryStruct(t *testing.T) {
	entry := ForwardingEntry{
		DestIP:    netip.MustParsePrefix("10.100.0.2/32"),
		NextHopIP: netip.MustParseAddr("10.100.0.1"),
		Interface: "mesh0",
		Metric:    100,
	}

	assert.Equal(t, "10.100.0.2/32", entry.DestIP.String())
	assert.Equal(t, "10.100.0.1", entry.NextHopIP.String())
	assert.Equal(t, "mesh0", entry.Interface)
	assert.Equal(t, 100, entry.Metric)
}

func TestRouteTableStatsStruct(t *testing.T) {
	stats := RouteTableStats{
		TotalRoutes:   10,
		DirectRoutes:  5,
		NextHopRoutes: 3,
		RelayRoutes:   2,
		Destinations:  8,
	}

	assert.Equal(t, 10, stats.TotalRoutes)
	assert.Equal(t, 5, stats.DirectRoutes)
	assert.Equal(t, 3, stats.NextHopRoutes)
	assert.Equal(t, 2, stats.RelayRoutes)
	assert.Equal(t, 8, stats.Destinations)
}

func BenchmarkAddDirectRoute(b *testing.B) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
	}

	router := NewMeshRouter(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peerID := "peer" + string(rune(i%1000))
		router.AddDirectRoute(peerID, netip.MustParseAddr("10.100.0.2"), 10*time.Millisecond)
	}
}

func BenchmarkGetRoute(b *testing.B) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
	}

	router := NewMeshRouter(config)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		peerID := "peer" + string(rune(i))
		router.AddDirectRoute(peerID, netip.MustParseAddr("10.100.0."+string(rune('2'+i%200))), 10*time.Millisecond)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peerID := "peer" + string(rune(i%1000))
		router.GetRoute(peerID)
	}
}

func BenchmarkGetNextHop(b *testing.B) {
	config := RouterConfig{
		LocalPeerID: "local-peer",
		LocalIP:     netip.MustParseAddr("10.100.0.1"),
	}

	router := NewMeshRouter(config)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		peerID := "peer" + string(rune(i))
		router.AddDirectRoute(peerID, netip.MustParseAddr("10.100.0."+string(rune('2'+i%200))), 10*time.Millisecond)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peerID := "peer" + string(rune(i%1000))
		router.GetNextHop(peerID)
	}
}
