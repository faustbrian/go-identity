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
	"testing"
	"time"

	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// commitAckFault selects only the successful terminal write for one command.
// It never fabricates a database outcome or changes executor behavior.
type commitAckFault struct {
	command          []byte
	hits             atomic.Int32
	velocitySequence atomic.Int64
	velocityEpoch    atomic.Pointer[[16]byte]
	velocityReplay   atomic.Int64
}

type ackTargetKey struct{}

func newCommitAckPool(t *testing.T, ctx context.Context, dsn, name string, command []byte) (*database.Pool, *commitAckFault) {
	t.Helper()
	fault := &commitAckFault{command: bytes.Clone(command)}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = name
		c.ConnConfig.TLSConfig = nil
		c.ConnConfig.Fallbacks = nil
		c.ConnConfig.RuntimeParams["synchronous_commit"] = "on"
		c.ConnConfig.Tracer = fault
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &commitAckConn{Conn: conn, fault: fault}, nil
		}
		return nil
	}})
	if err != nil {
		t.Fatal("fault pool", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("fault pool cleanup")
		}
	})
	return pool, fault
}

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
	if f.velocitySequence.Load() > 0 && strings.Contains(data.SQL, ".velocity_attempts SET outcome=$1 WHERE sequence=$2") && len(data.Args) == 2 {
		sequence, ok := data.Args[1].(int64)
		if ok && sequence == f.velocitySequence.Load() && data.Args[0] == "committed" {
			return context.WithValue(ctx, ackTargetKey{}, true)
		}
	}
	if sequence := f.velocityReplay.Load(); sequence > 0 && strings.Contains(data.SQL, ".velocity_attempts SET replay_seal=$2,replay_position=$3,position_seal=$4") && len(data.Args) == 4 {
		if value, ok := data.Args[0].(int64); ok && value == sequence {
			return context.WithValue(ctx, ackTargetKey{}, true)
		}
	}
	if epoch := f.velocityEpoch.Load(); epoch != nil && strings.Contains(data.SQL, ".velocity_epochs(tenant_id,namespace_digest,epoch,") && len(data.Args) == 8 {
		value, ok := data.Args[2].([]byte)
		if ok && bytes.Equal(value, epoch[:]) {
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
