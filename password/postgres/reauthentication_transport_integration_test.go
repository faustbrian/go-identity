//go:build integration

package passwordpostgres_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
)

// The disposable loopback server executes real SQL. This connection drops
// either the original COMMIT write or its server acknowledgement, never a
// substituted transaction, contributor, durable store or recovery result.
type reauthenticationCommitFault struct {
	before bool
	marker []byte // Immutable before any pool connection is opened.
	hit    atomic.Bool
}

func (f *reauthenticationCommitFault) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &reauthenticationCommitConn{Conn: c, fault: f}, nil
}

type reauthenticationCommitConn struct {
	net.Conn
	fault    *reauthenticationCommitFault
	mutation atomic.Bool
	pending  []byte // pgx owns the sole backend-message reader.
}

func (c *reauthenticationCommitConn) Write(p []byte) (int, error) {
	marker := c.fault.marker
	if len(marker) == 0 {
		marker = []byte("identity_password.reauthentication_records(")
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

func (c *reauthenticationCommitConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		// SSL is disabled only for this owned cluster; backend messages are
		// bounded before allocation and never retained outside this connection.
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
		if !c.fault.before && header[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.mutation.Load() && c.fault.hit.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		c.pending = message
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
