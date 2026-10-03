//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
)

// commitAckFault selects only the successful terminal write for one command.
// It never fabricates a database outcome or changes executor behavior.
type commitAckFault struct {
	command []byte
	hits    atomic.Int32
}

type ackTargetKey struct{}

func (f *commitAckFault) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	c, ok := conn.PgConn().Conn().(*commitAckConn)
	if !ok {
		return ctx
	}
	if data.SQL == "commit" && c.ready.Swap(false) {
		c.armed.Store(true)
	}
	if strings.Contains(data.SQL, "UPDATE identity.commands SET state=$4,result_version=1") && len(data.Args) == 6 {
		id, ok := data.Args[0].([]byte)
		if ok && bytes.Equal(id, f.command) && data.Args[3] == "committed" && data.Args[4] == "committed" {
			return context.WithValue(ctx, ackTargetKey{}, true)
		}
	}
	return ctx
}

func (*commitAckFault) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if ctx.Value(ackTargetKey{}) == true && data.Err == nil && data.CommandTag.RowsAffected() == 1 {
		if c, ok := conn.PgConn().Conn().(*commitAckConn); ok {
			c.ready.Store(true)
		}
	}
}

// All socket reads have pgx's single reader owner. Atomics publish tracer arming
// to that reader; no helper goroutine, listener, timer or unbounded buffer exists.
type commitAckConn struct {
	net.Conn
	fault        *commitAckFault
	ready, armed atomic.Bool
	pending      []byte
}

func (c *commitAckConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) != 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if !c.armed.Swap(false) {
		return c.Conn.Read(p)
	}
	var response []byte
	committed := false
	for {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 65536 || len(response)+int(size)+1 > 65536 {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		body := make([]byte, int(size)-4)
		if _, err := io.ReadFull(c.Conn, body); err != nil {
			return 0, err
		}
		response = append(response, header[:]...)
		response = append(response, body...)
		if header[0] == 'C' {
			committed = bytes.Equal(body, []byte("COMMIT\x00"))
		}
		if header[0] == 'Z' {
			if committed && bytes.Equal(body, []byte{'I'}) && c.fault.hits.CompareAndSwap(0, 1) {
				_ = c.Conn.Close()
				return 0, io.EOF
			}
			c.pending = response
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
	}
}
