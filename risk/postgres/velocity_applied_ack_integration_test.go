//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// The fault hides only PostgreSQL's successful COMMIT response. Native issuance
// is simulated here; this proves durable resume, not external native execution.
func testVelocityAppliedAck(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig, dsn, databaseName string) {
	t.Helper()
	var now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command, err := coordinator.Prepare(risk.Context{Tenant: "applied-ack-tenant", Operation: "identity.profile.get", Attempt: "original"}, risk.Subject{User: "subject"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := journal.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, receipt, risk.CounterNotCommitted, nil); err != nil {
		t.Fatal(err)
	}
	pool, fault := newCommitAckPool(t, ctx, dsn, databaseName, nil)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(cleanup); err != nil {
			t.Error("applied acknowledgement fault pool cleanup")
		}
	}()
	cfg.Pool = pool
	faultJournal, err := NewVelocityJournal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	issuer, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	recovery, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: faultJournal, MaximumWindow: time.Hour, LeaseDuration: 5 * time.Second, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := recovery.Acquire(ctx, "applied-ack-tenant", [16]byte{73})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := recovery.OwnedLease(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	page, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 100)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("original replay missing", err)
	}
	history, err := recovery.OwnedHistory(ctx, lease, owned, page.Records()[0])
	if err != nil {
		t.Fatal(err)
	}
	facts, err := reader.History(ctx, owned, history)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := native.Acknowledge(ctx, owned, history)
	if err != nil {
		t.Fatal(err)
	}
	fault.velocityApplied.Store(facts.Position)
	var unavailable identity.UnavailableError
	if err := recovery.RecordApplied(ctx, lease, owned, ack); !errors.As(err, &unavailable) || fault.hits.Load() != 1 {
		t.Fatal("lost applied acknowledgement was not unavailable", err)
	}
	var applied int64
	if err := journal.state.pool.Raw().QueryRow(ctx, `SELECT applied_position FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]).Scan(&applied); err != nil || applied != facts.Position {
		t.Fatal("fault did not preserve actual committed progress", err)
	}
	cursor, err := recovery.ResumeApplied(ctx, lease)
	if err != nil {
		t.Fatal("committed progress not recoverable after lost acknowledgement", err)
	}
	remaining, err := recovery.ReadPage(ctx, lease, cursor, 100)
	if err != nil || len(remaining.Records()) != 0 {
		t.Fatal("lost acknowledgement caused acknowledged effect to repeat", err)
	}
	// Now hide the read transaction's successful commit: no speculative cursor
	// escapes, and the next authoritative read recovers the same position.
	fault.velocityApplied.Store(0)
	fault.hits.Store(0)
	fault.velocityResume.Store(&lease.state.epoch)
	if cursor, err := recovery.ResumeApplied(ctx, lease); !errors.As(err, &unavailable) || cursor != (VelocityReplayCursor{}) || fault.hits.Load() != 1 {
		t.Fatal("lost resume acknowledgement disclosed cursor", err)
	}
	cursor, err = recovery.ResumeApplied(ctx, lease)
	if err != nil {
		t.Fatal("resume retry did not recover original progress", err)
	}
	remaining, err = recovery.ReadPage(ctx, lease, cursor, 100)
	if err != nil || len(remaining.Records()) != 0 {
		t.Fatal("resume retry replaced original applied continuation", err)
	}
	if err := recovery.RecordApplied(ctx, lease, owned, ack); err != nil {
		t.Fatal("duplicate acknowledgement after recovery not idempotent", err)
	}
}
