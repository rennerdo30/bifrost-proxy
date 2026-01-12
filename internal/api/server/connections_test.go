package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionTracker_New(t *testing.T) {
	ct := NewConnectionTracker()
	assert.NotNil(t, ct)
	assert.Equal(t, 0, ct.Count())
}

func TestConnectionTracker_Add(t *testing.T) {
	ct := NewConnectionTracker()

	id := ct.Add("192.168.1.100", "12345", "example.com:443", "default", "HTTP")
	assert.NotEmpty(t, id)
	assert.Equal(t, 1, ct.Count())
}

func TestConnectionTracker_Remove(t *testing.T) {
	ct := NewConnectionTracker()

	id := ct.Add("192.168.1.100", "12345", "example.com:443", "default", "HTTP")
	assert.Equal(t, 1, ct.Count())

	ct.Remove(id)
	assert.Equal(t, 0, ct.Count())
}

func TestConnectionTracker_GetAll(t *testing.T) {
	ct := NewConnectionTracker()

	ct.Add("192.168.1.100", "12345", "example.com:443", "default", "HTTP")
	ct.Add("192.168.1.101", "12346", "google.com:443", "vpn", "SOCKS5")

	conns := ct.GetAll()
	assert.Len(t, conns, 2)
}

func TestConnectionTracker_UpdateBytes(t *testing.T) {
	ct := NewConnectionTracker()

	id := ct.Add("192.168.1.100", "12345", "example.com:443", "default", "HTTP")
	ct.UpdateBytes(id, 100, 200)
	ct.UpdateBytes(id, 50, 100)

	conns := ct.GetAll()
	require.Len(t, conns, 1)
	assert.Equal(t, int64(150), conns[0].BytesSent)
	assert.Equal(t, int64(300), conns[0].BytesRecv)
}

func TestConnectionTracker_GetByClient(t *testing.T) {
	ct := NewConnectionTracker()

	ct.Add("192.168.1.100", "12345", "example.com:443", "default", "HTTP")
	ct.Add("192.168.1.100", "12346", "google.com:443", "default", "HTTP")
	ct.Add("192.168.1.101", "12347", "github.com:443", "vpn", "SOCKS5")

	conns := ct.GetByClient("192.168.1.100")
	assert.Len(t, conns, 2)

	conns = ct.GetByClient("192.168.1.101")
	assert.Len(t, conns, 1)

	conns = ct.GetByClient("192.168.1.200")
	assert.Len(t, conns, 0)
}

func TestConnectionTracker_GetUniqueClients(t *testing.T) {
	ct := NewConnectionTracker()

	ct.Add("192.168.1.100", "12345", "example.com:443", "default", "HTTP")
	ct.Add("192.168.1.100", "12346", "google.com:443", "default", "HTTP")
	ct.Add("192.168.1.101", "12347", "github.com:443", "vpn", "SOCKS5")

	clients := ct.GetUniqueClients()
	assert.Len(t, clients, 2)

	// Find the client with 2 connections
	var client100 *ClientSummary
	for i := range clients {
		if clients[i].ClientIP == "192.168.1.100" {
			client100 = &clients[i]
			break
		}
	}
	require.NotNil(t, client100)
	assert.Equal(t, 2, client100.Connections)
}

func TestConnectionTracker_ConnectionFields(t *testing.T) {
	ct := NewConnectionTracker()

	id := ct.Add("192.168.1.100", "12345", "example.com:443", "default", "CONNECT")

	conns := ct.GetAll()
	require.Len(t, conns, 1)

	conn := conns[0]
	assert.Equal(t, id, conn.ID)
	assert.Equal(t, "192.168.1.100", conn.ClientIP)
	assert.Equal(t, "12345", conn.ClientPort)
	assert.Equal(t, "example.com:443", conn.Host)
	assert.Equal(t, "default", conn.Backend)
	assert.Equal(t, "CONNECT", conn.Protocol)
	assert.False(t, conn.StartTime.IsZero())
	assert.True(t, conn.StartTime.Before(time.Now().Add(time.Second)))
}

func TestConnectionTracker_Concurrent(t *testing.T) {
	ct := NewConnectionTracker()

	// Concurrent adds
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 100; j++ {
				id := ct.Add("192.168.1.100", "12345", "example.com", "default", "HTTP")
				ct.UpdateBytes(id, 100, 100)
				ct.Remove(id)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have no connections left
	assert.Equal(t, 0, ct.Count())
}
