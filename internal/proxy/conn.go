package proxy

import (
	"net"
	"sync/atomic"
)

// countingConn wraps a net.Conn and tracks bytes read/written.
type countingConn struct {
	net.Conn
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
}

func newCountingConn(conn net.Conn) *countingConn {
	return &countingConn{Conn: conn}
}

// Read reads data and tracks bytes read.
func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.bytesRead.Add(int64(n))
	}
	return n, err
}

// Write writes data and tracks bytes written.
func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.bytesWritten.Add(int64(n))
	}
	return n, err
}

// CloseWrite forwards CloseWrite when supported.
func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead forwards CloseRead when supported.
func (c *countingConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *countingConn) BytesRead() int64 {
	return c.bytesRead.Load()
}

func (c *countingConn) BytesWritten() int64 {
	return c.bytesWritten.Load()
}
