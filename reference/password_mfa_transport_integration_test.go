//go:build integration

package reference_test

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

// Intercept only the disposable loopback driver's final session transaction.
// The database receives COMMIT, but its acknowledgement never reaches pgx.
// No SQL values, proof bytes, cookies or credentials are recorded or logged.
type completionCommitFault struct {
	factorProof      bool
	regeneration     bool
	factorManagement bool
	armed            atomic.Bool
	hit              atomic.Bool
}

func (f *completionCommitFault) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &completionCommitConn{Conn: c, fault: f}, nil
}

type completionCommitConn struct {
	net.Conn
	fault    *completionCommitFault
	mutation atomic.Bool
	pending  []byte // The sole pgx backend-message reader owns this bounded buffer.
}

func TestCompletionFaultReaderPreservesPartialFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline := time.Now().Add(time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = server.Write([]byte{'Z', 0, 0})
		_ = server.Close()
	}()
	defer func() { <-done }()
	c := &completionCommitConn{Conn: client, fault: &completionCommitFault{}}
	var output [8]byte
	n, _ := c.Read(output[:])
	if n != 3 || !bytes.Equal(output[:n], []byte{'Z', 0, 0}) {
		t.Fatal("fault reader discarded partial frame bytes")
	}
}

func (c *completionCommitConn) Write(p []byte) (int, error) {
	if len(p) >= 5 && p[0] == 'Q' && bytes.EqualFold(p[5:], []byte("rollback\x00")) {
		c.mutation.Store(false)
	}
	selected := bytes.Contains(p, []byte(".sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record)"))
	if c.fault.factorProof {
		selected = bytes.Contains(p, []byte("INSERT INTO identity_mfa.factor_verifications("))
	}
	if c.fault.regeneration {
		selected = bytes.Contains(p, []byte("INSERT INTO identity_mfa.recovery_sets("))
	}
	if c.fault.factorManagement {
		selected = bytes.Contains(p, []byte("INSERT INTO identity_mfa.factor_update_effects("))
	}
	if c.fault.armed.Load() && selected {
		c.mutation.Store(true)
	}
	return c.Conn.Write(p)
}

func (c *completionCommitConn) Read(p []byte) (int, error) {
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
		if message[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.mutation.Load() && c.fault.armed.Load() && c.fault.hit.CompareAndSwap(false, true) {
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
