package vpn

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConnForTracker implements net.Conn for connection tracking tests
type mockConnForTracker struct {
	closed bool
}

func (m *mockConnForTracker) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConnForTracker) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConnForTracker) Close() error                       { m.closed = true; return nil }
func (m *mockConnForTracker) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConnForTracker) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConnForTracker) SetDeadline(t time.Time) error      { return nil }
func (m *mockConnForTracker) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConnForTracker) SetWriteDeadline(t time.Time) error { return nil }

// TestNewConnTracker tests creating a new ConnTracker
func TestNewConnTracker(t *testing.T) {
	ct := NewConnTracker()
	defer ct.Close()

	assert.NotNil(t, ct)
	assert.NotNil(t, ct.connections)
	assert.Equal(t, 5*time.Minute, ct.idleTimeout)
	assert.Equal(t, 30*time.Second, ct.cleanupTick)
	assert.Equal(t, 0, ct.Count())
}

// TestConnTrackerAdd tests adding connections
func TestConnTrackerAdd(t *testing.T) {
	ct := NewConnTracker()
	defer ct.Close()

	conn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    netip.MustParseAddr("192.168.1.100"),
			DstIP:    netip.MustParseAddr("93.184.216.34"),
			SrcPort:  12345,
			DstPort:  443,
			Protocol: ProtocolTCP,
		},
		ProxyConn: &mockConnForTracker{},
	}

	ct.Add(conn)
	assert.Equal(t, 1, ct.Count())
	assert.Equal(t, ConnStateNew, conn.State)
	assert.False(t, conn.Created.IsZero())
	assert.False(t, conn.LastActivity.IsZero())
}

// TestConnTrackerAddAfterClose tests adding connection after close
func TestConnTrackerAddAfterClose(t *testing.T) {
	ct := NewConnTracker()
	ct.Close()

	conn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    netip.MustParseAddr("192.168.1.100"),
			DstIP:    netip.MustParseAddr("93.184.216.34"),
			SrcPort:  12345,
			DstPort:  443,
			Protocol: ProtocolTCP,
		},
	}

	ct.Add(conn)
	assert.Equal(t, 0, ct.Count())
}

// TestConnTrackerGet tests getting connections
func TestConnTrackerGet(t *testing.T) {
	ct := NewConnTracker()
	defer ct.Close()

	key := ConnKey{
		SrcIP:    netip.MustParseAddr("192.168.1.100"),
		DstIP:    netip.MustParseAddr("93.184.216.34"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: ProtocolTCP,
	}

	// Get non-existent
	assert.Nil(t, ct.Get(key))

	conn := &TrackedConnection{
		Key:       key,
		ProxyConn: &mockConnForTracker{},
	}
	ct.Add(conn)

	// Get existing
	got := ct.Get(key)
	assert.NotNil(t, got)
	assert.Equal(t, key, got.Key)
}

// TestConnTrackerGetByRemote tests getting connections by remote address
func TestConnTrackerGetByRemote(t *testing.T) {
	ct := NewConnTracker()
	defer ct.Close()

	key := ConnKey{
		SrcIP:    netip.MustParseAddr("192.168.1.100"),
		DstIP:    netip.MustParseAddr("93.184.216.34"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: ProtocolTCP,
	}

	conn := &TrackedConnection{
		Key:       key,
		ProxyConn: &mockConnForTracker{},
	}
	ct.Add(conn)

	// Get by remote
	got := ct.GetByRemote(netip.MustParseAddr("93.184.216.34"), 443, ProtocolTCP)
	assert.NotNil(t, got)
	assert.Equal(t, key, got.Key)

	// Wrong port
	got = ct.GetByRemote(netip.MustParseAddr("93.184.216.34"), 80, ProtocolTCP)
	assert.Nil(t, got)

	// Wrong protocol
	got = ct.GetByRemote(netip.MustParseAddr("93.184.216.34"), 443, ProtocolUDP)
	assert.Nil(t, got)

	// Wrong IP
	got = ct.GetByRemote(netip.MustParseAddr("8.8.8.8"), 443, ProtocolTCP)
	assert.Nil(t, got)
}

// TestConnTrackerRemove tests removing connections
func TestConnTrackerRemove(t *testing.T) {
	ct := NewConnTracker()
	defer ct.Close()

	key := ConnKey{
		SrcIP:    netip.MustParseAddr("192.168.1.100"),
		DstIP:    netip.MustParseAddr("93.184.216.34"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: ProtocolTCP,
	}

	conn := &TrackedConnection{
		Key:       key,
		ProxyConn: &mockConnForTracker{},
	}
	ct.Add(conn)
	assert.Equal(t, 1, ct.Count())

	ct.Remove(key)
	assert.Equal(t, 0, ct.Count())
	assert.Nil(t, ct.Get(key))
}

// TestConnTrackerUpdateActivity tests updating activity
func TestConnTrackerUpdateActivity(t *testing.T) {
	ct := NewConnTracker()
	defer ct.Close()

	key := ConnKey{
		SrcIP:    netip.MustParseAddr("192.168.1.100"),
		DstIP:    netip.MustParseAddr("93.184.216.34"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: ProtocolTCP,
	}

	conn := &TrackedConnection{
		Key:       key,
		ProxyConn: &mockConnForTracker{},
	}
	ct.Add(conn)
	initialActivity := conn.LastActivity

	time.Sleep(10 * time.Millisecond)
	ct.UpdateActivity(key)

	got := ct.Get(key)
	assert.True(t, got.LastActivity.After(initialActivity))

	// Update non-existent key (should not panic)
	ct.UpdateActivity(ConnKey{})
}

// TestConnTrackerSetState tests setting connection state
func TestConnTrackerSetState(t *testing.T) {
	ct := NewConnTracker()
	defer ct.Close()

	key := ConnKey{
		SrcIP:    netip.MustParseAddr("192.168.1.100"),
		DstIP:    netip.MustParseAddr("93.184.216.34"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: ProtocolTCP,
	}

	conn := &TrackedConnection{
		Key:       key,
		ProxyConn: &mockConnForTracker{},
	}
	ct.Add(conn)
	assert.Equal(t, ConnStateNew, conn.State)

	ct.SetState(key, ConnStateEstablished)
	got := ct.Get(key)
	assert.Equal(t, ConnStateEstablished, got.State)

	ct.SetState(key, ConnStateClosing)
	got = ct.Get(key)
	assert.Equal(t, ConnStateClosing, got.State)

	// Set state on non-existent key (should not panic)
	ct.SetState(ConnKey{}, ConnStateClosed)
}

// TestConnTrackerAll tests getting all connections
func TestConnTrackerAll(t *testing.T) {
	ct := NewConnTracker()
	defer ct.Close()

	// Empty
	assert.Len(t, ct.All(), 0)

	// Add connections
	for i := uint16(0); i < 3; i++ {
		conn := &TrackedConnection{
			Key: ConnKey{
				SrcIP:    netip.MustParseAddr("192.168.1.100"),
				DstIP:    netip.MustParseAddr("93.184.216.34"),
				SrcPort:  12345 + i,
				DstPort:  443,
				Protocol: ProtocolTCP,
			},
			ProxyConn: &mockConnForTracker{},
		}
		ct.Add(conn)
	}

	all := ct.All()
	assert.Len(t, all, 3)
}

// TestConnTrackerClose tests closing the tracker
func TestConnTrackerClose(t *testing.T) {
	ct := NewConnTracker()

	mock := &mockConnForTracker{}
	conn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    netip.MustParseAddr("192.168.1.100"),
			DstIP:    netip.MustParseAddr("93.184.216.34"),
			SrcPort:  12345,
			DstPort:  443,
			Protocol: ProtocolTCP,
		},
		ProxyConn: mock,
	}
	ct.Add(conn)

	ct.Close()
	assert.True(t, mock.closed)
	assert.Equal(t, 0, ct.Count())

	// Double close should not panic
	ct.Close()
}

// TestConnTrackerStats tests stats collection
func TestConnTrackerStats(t *testing.T) {
	ct := NewConnTracker()
	defer ct.Close()

	// Add TCP connection
	tcpConn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    netip.MustParseAddr("192.168.1.100"),
			DstIP:    netip.MustParseAddr("93.184.216.34"),
			SrcPort:  12345,
			DstPort:  443,
			Protocol: ProtocolTCP,
		},
		ProxyConn: &mockConnForTracker{},
	}
	ct.Add(tcpConn)
	tcpConn.BytesSent.Store(100)
	tcpConn.BytesReceived.Store(200)

	// Add UDP connection
	udpConn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    netip.MustParseAddr("192.168.1.100"),
			DstIP:    netip.MustParseAddr("8.8.8.8"),
			SrcPort:  12346,
			DstPort:  53,
			Protocol: ProtocolUDP,
		},
		ProxyConn: &mockConnForTracker{},
	}
	ct.Add(udpConn)

	// Set different states
	ct.SetState(tcpConn.Key, ConnStateEstablished)
	ct.SetState(udpConn.Key, ConnStateClosing)

	stats := ct.Stats()
	assert.Equal(t, 2, stats.TotalConnections)
	assert.Equal(t, 1, stats.TCPConnections)
	assert.Equal(t, 1, stats.UDPConnections)
	assert.Equal(t, 1, stats.EstablishedConnections)
	assert.Equal(t, 1, stats.ClosingConnections)
	assert.Equal(t, int64(100), stats.TotalBytesSent)
	assert.Equal(t, int64(200), stats.TotalBytesReceived)
}

// TestConnStateConstants tests connection state constants
func TestConnStateConstants(t *testing.T) {
	assert.Equal(t, ConnState(0), ConnStateNew)
	assert.Equal(t, ConnState(1), ConnStateEstablished)
	assert.Equal(t, ConnState(2), ConnStateClosing)
	assert.Equal(t, ConnState(3), ConnStateClosed)
}

// TestNATTableNew tests creating a new NAT table
func TestNATTableNew(t *testing.T) {
	nt := NewNATTable(netip.MustParseAddr("10.255.0.1"), 10000, 20000)
	require.NotNil(t, nt)
	assert.Equal(t, netip.MustParseAddr("10.255.0.1"), nt.localAddr)
	assert.Equal(t, uint16(10000), nt.basePort)
	assert.Equal(t, uint16(20000), nt.maxPort)
	assert.Equal(t, uint16(10000), nt.nextPort)
}

// TestNATTableAllocate tests NAT allocation
func TestNATTableAllocate(t *testing.T) {
	nt := NewNATTable(netip.MustParseAddr("10.255.0.1"), 10000, 10010)

	src := netip.MustParseAddrPort("192.168.1.100:12345")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Allocate first entry
	entry, err := nt.Allocate(src, dst, ProtocolTCP)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, src, entry.OriginalSrc)
	assert.Equal(t, dst, entry.Destination)
	assert.Equal(t, uint8(ProtocolTCP), entry.Protocol)
	assert.Equal(t, uint16(10000), entry.MappedSrc.Port())

	// Allocate same source/dst should return existing
	entry2, err := nt.Allocate(src, dst, ProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, entry.MappedSrc, entry2.MappedSrc)

	// Allocate different source
	src2 := netip.MustParseAddrPort("192.168.1.101:12345")
	entry3, err := nt.Allocate(src2, dst, ProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, uint16(10001), entry3.MappedSrc.Port())
}

// TestNATTableAllocateFull tests NAT table full condition
func TestNATTableAllocateFull(t *testing.T) {
	nt := NewNATTable(netip.MustParseAddr("10.255.0.1"), 10000, 10002)

	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Fill up the table
	for i := uint16(0); i < 3; i++ {
		src := netip.MustParseAddrPort("192.168.1." + string(rune('0'+i%10)) + ":12345")
		_, err := nt.Allocate(src, dst, ProtocolTCP)
		require.NoError(t, err)
	}

	// Try to allocate one more
	src := netip.MustParseAddrPort("192.168.2.1:12345")
	_, err := nt.Allocate(src, dst, ProtocolTCP)
	assert.Equal(t, ErrNATTableFull, err)
}

// TestNATTableLookup tests NAT lookup
func TestNATTableLookup(t *testing.T) {
	nt := NewNATTable(netip.MustParseAddr("10.255.0.1"), 10000, 20000)

	src := netip.MustParseAddrPort("192.168.1.100:12345")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Lookup non-existent
	assert.Nil(t, nt.Lookup(src, dst, ProtocolTCP))

	// Allocate and lookup
	entry, _ := nt.Allocate(src, dst, ProtocolTCP)
	got := nt.Lookup(src, dst, ProtocolTCP)
	assert.Equal(t, entry, got)
}

// TestNATTableLookupReverse tests reverse NAT lookup
func TestNATTableLookupReverse(t *testing.T) {
	nt := NewNATTable(netip.MustParseAddr("10.255.0.1"), 10000, 20000)

	src := netip.MustParseAddrPort("192.168.1.100:12345")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	entry, _ := nt.Allocate(src, dst, ProtocolTCP)

	// Reverse lookup
	got := nt.LookupReverse(entry.MappedSrc, ProtocolTCP)
	assert.Equal(t, entry, got)

	// Wrong protocol
	got = nt.LookupReverse(entry.MappedSrc, ProtocolUDP)
	assert.Nil(t, got)
}

// TestNATTableRelease tests releasing NAT entries
func TestNATTableRelease(t *testing.T) {
	nt := NewNATTable(netip.MustParseAddr("10.255.0.1"), 10000, 20000)

	src := netip.MustParseAddrPort("192.168.1.100:12345")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	entry, _ := nt.Allocate(src, dst, ProtocolTCP)
	require.NotNil(t, entry)

	nt.Release(src, dst, ProtocolTCP)

	// Should be gone
	assert.Nil(t, nt.Lookup(src, dst, ProtocolTCP))
	assert.Nil(t, nt.LookupReverse(entry.MappedSrc, ProtocolTCP))

	// Release non-existent (should not panic)
	nt.Release(src, dst, ProtocolTCP)
}

// TestNATTableCleanup tests NAT entry cleanup
func TestNATTableCleanup(t *testing.T) {
	nt := NewNATTable(netip.MustParseAddr("10.255.0.1"), 10000, 20000)

	src1 := netip.MustParseAddrPort("192.168.1.100:12345")
	src2 := netip.MustParseAddrPort("192.168.1.101:12345")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Create entries
	entry1, _ := nt.Allocate(src1, dst, ProtocolTCP)
	_, _ = nt.Allocate(src2, dst, ProtocolTCP)

	// Make entry1 old
	entry1.LastActivity = time.Now().Add(-10 * time.Minute)

	// Cleanup with 5 minute age
	removed := nt.Cleanup(5 * time.Minute)
	assert.Equal(t, 1, removed)

	// entry1 should be gone, entry2 should remain
	assert.Nil(t, nt.Lookup(src1, dst, ProtocolTCP))
	assert.NotNil(t, nt.Lookup(src2, dst, ProtocolTCP))
}

// TestNATTablePortWraparound tests port wraparound
func TestNATTablePortWraparound(t *testing.T) {
	nt := NewNATTable(netip.MustParseAddr("10.255.0.1"), 10000, 10002)

	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Fill up and release middle
	src1 := netip.MustParseAddrPort("192.168.1.1:12345")
	src2 := netip.MustParseAddrPort("192.168.1.2:12345")
	src3 := netip.MustParseAddrPort("192.168.1.3:12345")

	_, _ = nt.Allocate(src1, dst, ProtocolTCP)
	_, _ = nt.Allocate(src2, dst, ProtocolTCP)
	_, _ = nt.Allocate(src3, dst, ProtocolTCP)

	// Release middle
	nt.Release(src2, dst, ProtocolTCP)

	// Allocate new - should find released port
	src4 := netip.MustParseAddrPort("192.168.1.4:12345")
	entry, err := nt.Allocate(src4, dst, ProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, uint16(10001), entry.MappedSrc.Port())
}

// TestNATError tests NAT error type
func TestNATError(t *testing.T) {
	err := &NATError{Message: "test error"}
	assert.Equal(t, "test error", err.Error())
	assert.Equal(t, ErrNATTableFull.Error(), "NAT table is full, no ports available")
}

// TestTrackedConnectionBytes tests byte counting
func TestTrackedConnectionBytes(t *testing.T) {
	conn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    netip.MustParseAddr("192.168.1.100"),
			DstIP:    netip.MustParseAddr("93.184.216.34"),
			SrcPort:  12345,
			DstPort:  443,
			Protocol: ProtocolTCP,
		},
	}

	conn.BytesSent.Add(100)
	conn.BytesSent.Add(50)
	conn.BytesReceived.Add(200)

	assert.Equal(t, int64(150), conn.BytesSent.Load())
	assert.Equal(t, int64(200), conn.BytesReceived.Load())
}

// TestNATEntry tests NAT entry struct
func TestNATEntry(t *testing.T) {
	entry := NATEntry{
		OriginalSrc:  netip.MustParseAddrPort("192.168.1.100:12345"),
		MappedSrc:    netip.MustParseAddrPort("10.255.0.1:10000"),
		Destination:  netip.MustParseAddrPort("93.184.216.34:443"),
		Protocol:     ProtocolTCP,
		Created:      time.Now(),
		LastActivity: time.Now(),
	}

	assert.Equal(t, uint16(12345), entry.OriginalSrc.Port())
	assert.Equal(t, uint16(10000), entry.MappedSrc.Port())
	assert.Equal(t, uint16(443), entry.Destination.Port())
}
