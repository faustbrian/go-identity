//go:build integration

package anonymouspostgres_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
)

// The real loopback server owns every transaction and result. This fault only
// drops the final anonymous transaction's COMMIT or its acknowledgement. It
// never decodes/records Bind parameters, cookies, credentials or SQL results.
type anonymousCommitFault struct {
	before   bool
	disposal bool
	hit      atomic.Bool
}

func (f *anonymousCommitFault) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &anonymousCommitConn{Conn: c, fault: f}, nil
}

type anonymousCommitConn struct {
	net.Conn
	fault    *anonymousCommitFault
	mutation atomic.Bool
	pending  []byte // The pgx backend-message reader is the sole owner.
}

func (c *anonymousCommitConn) Write(p []byte) (int, error) {
	if !c.fault.disposal && bytes.Contains(p, []byte(`.subjects(tenant_id,user_id,subject_id,created_at,expires_at,state,version,cleanup,creation_command_id)`)) || c.fault.disposal && bytes.Contains(p, []byte(`identity.anonymous_disposals(`)) {
		c.mutation.Store(true)
	}
	if c.fault.before && c.mutation.Load() && len(p) >= 5 && p[0] == 'Q' && bytes.EqualFold(p[5:], []byte("commit\x00")) && c.fault.hit.CompareAndSwap(false, true) {
		_ = c.Conn.Close()
		return 0, io.ErrUnexpectedEOF
	}
	return c.Conn.Write(p)
}

func (c *anonymousCommitConn) Read(p []byte) (int, error) {
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
		if !c.fault.before && header[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.mutation.Load() && c.fault.hit.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		if header[0] == 'Z' && len(message) == 6 && message[5] == 'I' {
			c.mutation.Store(false)
		}
		c.pending = message
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
