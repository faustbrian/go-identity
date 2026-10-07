package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// An empty borrowed cursor may complete without a driver error while the caller
// cancels. Context classification must not depend on a particular driver's Err.
type cancelledPreAuthRows struct {
	cancel context.CancelFunc
	closed bool
}

func (r *cancelledPreAuthRows) Next() bool      { r.cancel(); return false }
func (*cancelledPreAuthRows) Scan(...any) error { panic("empty cursor scanned") }
func (*cancelledPreAuthRows) Err() error        { return nil }
func (r *cancelledPreAuthRows) Close()          { r.closed = true }

type cancelledPreAuthQuery struct{ rows *cancelledPreAuthRows }

func (q cancelledPreAuthQuery) Query(context.Context, string, ...any) (*cancelledPreAuthRows, error) {
	return q.rows, nil
}

func TestReadPreAuthCancellationOnEmptyCursor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows := &cancelledPreAuthRows{cancel: cancel}
	_, err := ReadPreAuth(ctx, cancelledPreAuthQuery{rows}, Config{Schema: "session_store", MaximumDuration: time.Second}, "tenant-a", "AQEBAQEBAQEBAQEBAQEBAQ")
	var cancelled identity.CancelledError
	if !errors.As(err, &cancelled) {
		t.Fatalf("cancellation misclassified: %T", err)
	}
	if !rows.closed {
		t.Fatal("borrowed cursor leaked")
	}
}
