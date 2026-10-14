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

// The real PostgreSQL server executes every statement and commit. Only the
// commit acknowledgment for the connection writing the new session issuance
// is lost. No transaction, contributor, store or recovery result is substituted.
type signinCommitFault struct {
	enabled, hit atomic.Bool
	denial       bool
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
	pending  []byte // The pgx connection owns exactly one protocol reader.
}

func (c *signinCommitConn) Write(p []byte) (int, error) {
	// The first session issuance statement is parsed on this fresh test
	// composition; this marker cannot be a code/recipient payload.
	marker := []byte(".session_issuances(")
	if c.fault.denial {
		marker = []byte("failed_attempts=$9")
	}
	if c.fault.enabled.Load() && bytes.Contains(p, marker) {
		c.mutation.Store(true)
	}
	return c.Conn.Write(p)
}

func (c *signinCommitConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		// SSL is disabled for this disposable loopback cluster. All backend
		// messages have the standard one-byte tag and four-byte length.
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
		if header[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.mutation.Load() && c.fault.hit.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		c.pending = message
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
