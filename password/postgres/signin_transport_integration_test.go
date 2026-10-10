//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
)

// Only the disposable loopback connection is intercepted. SQL, transaction
// owners and recovery remain real. The final native record marks staged rehash
// and session effects; earlier reservation transactions must not be faulted.
type signinCommitFault struct {
	before bool
	cancel context.CancelFunc
	hit    atomic.Bool
}

func (f *signinCommitFault) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &signinCommitConn{Conn: c, fault: f}, nil
}

type signinCommitConn struct {
	net.Conn
	fault    *signinCommitFault
	mutation atomic.Bool
	pending  []byte // Sole pgx backend-message reader owns this buffer.
}

func (c *signinCommitConn) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("identity_password.signin_records(")) {
		c.mutation.Store(true)
		if c.fault.cancel != nil && c.fault.hit.CompareAndSwap(false, true) {
			c.fault.cancel()
		}
	}
	if c.fault.cancel == nil && c.fault.before && c.mutation.Load() && len(p) >= 5 && p[0] == 'Q' && bytes.EqualFold(p[5:], []byte("commit\x00")) && c.fault.hit.CompareAndSwap(false, true) {
		_ = c.Conn.Close()
		return 0, io.ErrUnexpectedEOF
	}
	return c.Conn.Write(p)
}

func (c *signinCommitConn) Read(p []byte) (int, error) {
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
		if c.fault.cancel == nil && !c.fault.before && header[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.mutation.Load() && c.fault.hit.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		c.pending = message
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
