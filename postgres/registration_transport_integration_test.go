//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
)

// Fault only the disposable connection's original mutation transaction. The
// earlier reservation COMMIT must remain intact; no production SQL is replaced.
type registrationCommitFault struct {
	before bool
	hit    atomic.Bool
	// Other protected workflows select their actual owned INSERT. Empty keeps
	// the established registration target; never arm on an earlier reservation.
	marker []byte
}

func (f *registrationCommitFault) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &registrationFaultConn{Conn: c, fault: f}, nil
}

type registrationFaultConn struct {
	net.Conn
	fault    *registrationCommitFault
	mutation atomic.Bool
	pending  []byte // Owned by the sole pgx backend-message reader.
}

func (c *registrationFaultConn) Write(p []byte) (int, error) {
	marker := c.fault.marker
	if len(marker) == 0 {
		marker = []byte("identity.registration_bindings(")
	}
	if bytes.Contains(p, marker) {
		c.mutation.Store(true)
	}
	if c.fault.before && c.mutation.Load() && len(p) >= 5 && p[0] == 'Q' && bytes.EqualFold(p[5:], []byte("commit\x00")) && c.fault.hit.CompareAndSwap(false, true) {
		_ = c.Conn.Close()
		return 0, io.ErrUnexpectedEOF
	}
	return c.Conn.Write(p)
}

func (c *registrationFaultConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 16<<20 {
			return 0, io.ErrUnexpectedEOF
		}
		message := make([]byte, int(size)+1)
		copy(message, header[:])
		if _, err := io.ReadFull(c.Conn, message[5:]); err != nil {
			return 0, err
		}
		if !c.fault.before && c.mutation.Load() && header[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.fault.hit.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		c.pending = message
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
