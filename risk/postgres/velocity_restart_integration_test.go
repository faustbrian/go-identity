//go:build integration

package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func testVelocityRestart(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig, dsn, databaseName string) {
	t.Helper()
	issuer, _, native, verifier := risk.NewVelocityRecoveryAuthorities()
	r, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 20 * time.Second, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	restarter, ok := any(r).(interface {
		Restart(context.Context, VelocityRecoveryLease) (VelocityRecoveryLease, error)
	})
	if !ok {
		t.Fatal("primary cannot restart lost projection from zero under current custody")
	}
	var now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command, err := c.Prepare(risk.Context{Tenant: "restart-tenant", Operation: "identity.profile.get", Attempt: "original"}, risk.Subject{User: "subject"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	a, err := journal.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, a, risk.CounterNotCommitted, nil); err != nil {
		t.Fatal(err)
	}
	l, err := r.Acquire(ctx, "restart-tenant", [16]byte{111})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := r.OwnedLease(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.ReadPage(ctx, l, VelocityReplayCursor{}, 100)
	if err != nil || len(p.Records()) != 1 {
		t.Fatal("original history missing", err)
	}
	h, err := r.OwnedHistory(ctx, l, owned, p.Records()[0])
	if err != nil {
		t.Fatal(err)
	}
	// Native effect is simulated; this test proves actual primary restart and
	// invalidation, not Valkey restoration or continuity.
	ack, err := native.Acknowledge(ctx, owned, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RecordApplied(ctx, l, owned, ack); err != nil {
		t.Fatal(err)
	}
	// Test-only provenance establishes a covered cut so the regression can
	// exercise actual recorded publication invalidation, not already-NULL fields.
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '1 hour 1 second' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	cut, err := r.PrepareCoveredClosure(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := r.OwnedClosure(ctx, l, owned, cut)
	if err != nil {
		t.Fatal(err)
	}
	published, err := native.AcknowledgePublication(ctx, owned, closed)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmPublication(ctx, l, owned, cut, closed, published); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckPublication(ctx, l, owned, cut, closed, published); err != nil {
		t.Fatal("recorded publication missing before restart", err)
	}
	confirmedCustody, err := r.OwnedConfirmation(ctx, l, owned, cut, closed, published)
	if err != nil {
		t.Fatal(err)
	}
	var before, through time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT replay_from,replay_through FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]).Scan(&before, &through); err != nil || !through.After(before) {
		t.Fatal("original stable cut missing", err)
	}
	next, err := restarter.Restart(ctx, l)
	if err != nil {
		t.Fatal("current owner cannot restart", err)
	}
	if next.state.generation != l.state.generation+1 || next.state.token == l.state.token || !next.state.expires.Equal(l.state.expires) {
		t.Fatal("restart reused custody or renewed expiry")
	}
	if err := r.CheckLease(ctx, l); err == nil {
		t.Fatal("old lease survived restart")
	}
	if err := r.CheckClosure(ctx, cut); err == nil {
		t.Fatal("old cut survived restart")
	}
	if err := r.CheckPublication(ctx, l, owned, cut, closed, published); err == nil {
		t.Fatal("old publication survived restart")
	}
	if _, err := verifier.Confirmation(ctx, owned, closed, published, confirmedCustody); err == nil {
		t.Fatal("retained confirmation survived restart")
	}
	if err := r.RecordApplied(ctx, next, owned, ack); err == nil {
		t.Fatal("old native acknowledgement restored successor progress")
	}
	if err := r.CheckLease(ctx, next); err != nil {
		t.Fatal("successor not current", err)
	}
	cursor, err := r.ResumeApplied(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.ReadPage(ctx, next, cursor, 100)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("restart skipped old applied history", err)
	}
	var after, end time.Time
	var position int64
	var appliedGeneration *string
	var seal, publication []byte
	var confirmed *time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT replay_from,replay_through,applied_generation::text,applied_position,applied_seal,publication_id,publication_confirmed_at FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]).Scan(&after, &end, &appliedGeneration, &position, &seal, &publication, &confirmed); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(before) || !end.Equal(before) || position != 0 || appliedGeneration != nil || len(seal) != 0 || len(publication) != 0 || confirmed != nil {
		t.Fatal("restart retained progress/cut/publication or changed traversal origin")
	}
	retry, err := restarter.Restart(ctx, l)
	if err != nil || retry.state.token != next.state.token || retry.state.generation != next.state.generation || !retry.state.expires.Equal(next.state.expires) {
		t.Fatal("same restart did not reconcile exact successor", err)
	}
	newOwned, err := r.OwnedLease(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	newHistory, err := r.OwnedHistory(ctx, next, newOwned, page.Records()[0])
	if err != nil {
		t.Fatal(err)
	}
	newAck, err := native.Acknowledge(ctx, newOwned, newHistory)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RecordApplied(ctx, next, newOwned, newAck); err != nil {
		t.Fatal(err)
	}
	if _, err := restarter.Restart(ctx, l); err != nil {
		t.Fatal("retry after progress failed", err)
	}
	resumed, err := r.ResumeApplied(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := r.ReadPage(ctx, next, resumed, 100)
	if err != nil || len(remaining.Records()) != 0 {
		t.Fatal("reconciled restart erased successor progress", err)
	}
	if _, err := restarter.Restart(nil, next); err == nil {
		t.Fatal("nil context admitted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := restarter.Restart(canceled, next); err != context.Canceled {
		t.Fatal("cancellation not preserved", err)
	}
	if _, err := restarter.Restart(ctx, VelocityRecoveryLease{}); err == nil {
		t.Fatal("zero lease admitted")
	}
	foreign, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Restart(ctx, next); err == nil {
		t.Fatal("foreign owner admitted")
	}
	renewed, err := r.Renew(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarter.Restart(ctx, l); err == nil {
		t.Fatal("old restart reconciled after successor renewal")
	}
	if err := r.CheckLease(ctx, renewed); err != nil {
		t.Fatal("rejected stale retry affected renewed owner", err)
	}
	// Matching concurrent invocations reconcile one transition, not a sequence
	// of generations. Their acknowledgements must identify the same successor.
	var wg sync.WaitGroup
	results := make(chan VelocityRecoveryLease, 6)
	failures := make(chan error, 6)
	for range 6 {
		wg.Go(func() {
			got, err := r.Restart(ctx, renewed)
			if err != nil {
				failures <- err
				return
			}
			results <- got
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal("concurrent reconciliation failed", err)
	}
	var winner VelocityRecoveryLease
	for got := range results {
		if winner.state == nil {
			winner = got
		}
		if got.state.token != winner.state.token || got.state.generation != renewed.state.generation+1 || !got.state.expires.Equal(renewed.state.expires) {
			t.Fatal("concurrent restart advanced more than once")
		}
	}
	// Drop an actual successful COMMIT response. The primary must commit one
	// restart, expose no receipt, and reconcile it without extending custody.
	faultPool, fault := newCommitAckPool(t, ctx, dsn, databaseName, nil)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if err := faultPool.Close(cleanup); err != nil {
			t.Error("restart fault pool cleanup")
		}
	}()
	faultCfg := cfg
	faultCfg.Pool = faultPool
	faultJournal, err := NewVelocityJournal(faultCfg)
	if err != nil {
		t.Fatal(err)
	}
	faultRecovery, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: faultJournal, MaximumWindow: time.Hour, LeaseDuration: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	faultLease, err := faultRecovery.Acquire(ctx, "restart-lost-ack", [16]byte{112})
	if err != nil {
		t.Fatal(err)
	}
	fault.velocityRestart.Store(&faultLease.state.epoch)
	if got, err := faultRecovery.Restart(ctx, faultLease); err == nil || got.state != nil || fault.hits.Load() != 1 {
		t.Fatal("lost successful restart COMMIT exposed custody", err)
	}
	fault.velocityRestart.Store(nil)
	if err := faultRecovery.CheckLease(ctx, faultLease); err == nil {
		t.Fatal("lost acknowledgement did not actually supersede primary owner")
	}
	reconciled, err := faultRecovery.Restart(ctx, faultLease)
	if err != nil || reconciled.state.generation != faultLease.state.generation+1 || !reconciled.state.expires.Equal(faultLease.state.expires) || fault.hits.Load() != 1 {
		t.Fatal("lost-ack restart failed exact primary reconciliation", err)
	}
	if err := faultRecovery.CheckLease(ctx, reconciled); err != nil {
		t.Fatal("reconciled custody not current", err)
	}
}
