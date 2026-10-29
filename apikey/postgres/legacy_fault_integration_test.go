//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// This is the existing password native test's bounded loopback-only transport
// fault, selected by the legacy owner's final SQL marker. Real SQL, protected
// participants and the sole command coordinator remain unchanged. It drops
// only the final COMMIT acknowledgement, after PostgreSQL actually committed.
type legacyCommitFault struct {
	hit    atomic.Bool
	marker []byte // Immutable SQL-owner marker selected by the test before dial.
}

func (f *legacyCommitFault) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &legacyCommitConn{Conn: c, fault: f}, nil
}

type legacyCommitConn struct {
	net.Conn
	fault    *legacyCommitFault
	mutation atomic.Bool
	pending  []byte // Sole pgx backend-message reader owns this bounded buffer.
}

func (c *legacyCommitConn) Write(p []byte) (int, error) {
	if len(p) >= 5 && p[0] == 'Q' && bytes.EqualFold(p[5:], []byte("rollback\x00")) {
		c.mutation.Store(false)
	}
	marker := c.fault.marker
	if len(marker) == 0 {
		marker = []byte("INSERT INTO identity_api_keys.legacy_imports")
	}
	if bytes.Contains(p, marker) {
		c.mutation.Store(true)
	}
	return c.Conn.Write(p)
}

func (c *legacyCommitConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if len(c.pending)+n > (16<<20)+5 {
		return 0, io.ErrUnexpectedEOF
	}
	c.pending = append(c.pending, p[:n]...)
	for len(c.pending) >= 5 {
		size := binary.BigEndian.Uint32(c.pending[1:5])
		if size < 4 || size > 16<<20 {
			return 0, io.ErrUnexpectedEOF
		}
		if len(c.pending) < int(size)+1 {
			break
		}
		message := c.pending[:int(size)+1]
		if message[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.mutation.Load() && c.fault.hit.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		if message[0] == 'Z' && len(message) == 6 && message[5] == 'I' {
			c.mutation.Store(false)
		}
		c.pending = c.pending[len(message):]
	}
	return n, err
}

func TestLegacyFaultReaderPreservesInterruptedPartialFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() { defer close(done); _, _ = server.Write([]byte{'Z', 0, 0}); _ = server.Close() }()
	defer func() { <-done }()
	c := &legacyCommitConn{Conn: client, fault: &legacyCommitFault{}}
	var out [8]byte
	n, _ := c.Read(out[:])
	if n != 3 || !bytes.Equal(out[:n], []byte{'Z', 0, 0}) {
		t.Fatal("fault reader discarded partial frame")
	}
}
