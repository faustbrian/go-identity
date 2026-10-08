//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func testVelocityActivation(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig) {
	t.Helper()
	j, _, native, verifier := risk.NewVelocityRecoveryAuthorities()
	r, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 20 * time.Second, JournalIssuer: j, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	l, err := r.Acquire(ctx, "activation-tenant", [16]byte{113})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := r.OwnedLease(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	var originalNow time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&originalNow); err != nil {
		t.Fatal(err)
	}
	originalCoordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return originalNow }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	originalCommand, err := originalCoordinator.Prepare(risk.Context{Tenant: l.state.tenant, Operation: "identity.profile.get", Attempt: "original-applied"}, risk.Subject{User: "subject"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	originalAttempt, err := journal.RecordAttempt(ctx, originalCommand)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, originalAttempt, risk.CounterNotCommitted, nil); err != nil {
		t.Fatal(err)
	}
	page, err := r.ReadPage(ctx, l, VelocityReplayCursor{}, 100)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("original applied history missing", err)
	}
	history, err := r.OwnedHistory(ctx, l, owned, page.Records()[0])
	if err != nil {
		t.Fatal(err)
	}
	// Simulated native restoration proves primary seals, not live Valkey IO.
	applied, err := native.Acknowledge(ctx, owned, history)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RecordApplied(ctx, l, owned, applied); err != nil {
		t.Fatal(err)
	}
	// Test-only provenance; this does not attest a live Valkey projection.
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
	confirmed, err := r.OwnedConfirmation(ctx, l, owned, cut, closed, published)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Activate(ctx, l, owned, cut, closed, published, confirmed, risk.VelocityNativeConfirmation{}); err == nil || got.state != nil {
		t.Fatal("primary publication alone activated traffic")
	}
	ack, err := native.AcknowledgeNativeConfirmation(ctx, owned, closed, published, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.Activate(ctx, l, owned, cut, closed, published, confirmed, ack)
	if err != nil {
		t.Fatal("primary cannot activate exact native confirmed cut", err)
	}
	if err := r.CheckHealthy(ctx, h); err != nil {
		t.Fatal("activated primary eligibility unavailable", err)
	}
	if err := r.CheckLease(ctx, l); err == nil {
		t.Fatal("healthy traffic widened replay custody")
	}
	if err := r.CheckPublication(ctx, l, owned, cut, closed, published); err == nil {
		t.Fatal("healthy traffic widened publication checks")
	}
	var state string
	var from, through, healthyAt, activatedAt, expires, confirmedAt time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT state,replay_from,replay_through,healthy_at,activated_at,lease_expires_at,publication_confirmed_at FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]).Scan(&state, &from, &through, &healthyAt, &activatedAt, &expires, &confirmedAt); err != nil {
		t.Fatal(err)
	}
	if state != "healthy" || !from.Equal(cut.state.from) || !through.Equal(cut.state.through) || !healthyAt.Equal(through) || activatedAt.Before(confirmedAt) || !activatedAt.After(through) || !expires.Equal(l.state.expires) {
		t.Fatal("activation fabricated cut, refreshed expiry, or lost real activation time")
	}
	retry, err := r.Activate(ctx, l, owned, cut, closed, published, confirmed, ack)
	if err != nil || !retry.state.activated.Equal(h.state.activated) {
		t.Fatal("activation retry did not reconcile original timestamp", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			got, err := r.Activate(ctx, l, owned, cut, closed, published, confirmed, ack)
			if err != nil || !got.state.activated.Equal(h.state.activated) {
				t.Error("concurrent healthy reconciliation refreshed activation", err)
			}
		})
	}
	wg.Wait()
	if err := r.CheckHealthy(nil, h); err == nil {
		t.Fatal("nil health context admitted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := r.CheckHealthy(canceled, h); !errors.Is(err, context.Canceled) {
		t.Fatal("health cancellation lost", err)
	}
	foreign, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := foreign.CheckHealthy(ctx, h); err == nil {
		t.Fatal("foreign instance accepted health")
	}
	if err := r.CheckHealthy(ctx, VelocityHealthy{}); err == nil {
		t.Fatal("zero health accepted")
	}
	if _, err := json.Marshal(h); !errors.Is(err, risk.ErrSensitiveSerialization) {
		t.Fatal("health serialized", err)
	}
	if got := fmt.Sprintf("%#v", h); got != "postgres.VelocityHealthy(redacted)" {
		t.Fatal("health formatting leaked custody", got)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_seal=set_byte(applied_seal,0,get_byte(applied_seal,0)#1) WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckHealthy(ctx, h); err == nil {
		t.Fatal("corrupt applied progress remained healthy")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_seal=set_byte(applied_seal,0,get_byte(applied_seal,0)#1) WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	// Writer admission reopens, but the historical cut remains immutable.
	var now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command, err := coordinator.Prepare(risk.Context{Tenant: l.state.tenant, Operation: "identity.profile.get", Attempt: "after-activation"}, risk.Subject{User: "subject"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := journal.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal("activation did not reopen journal", err)
	}
	if err := journal.RecordResult(ctx, attempt, risk.CounterNotCommitted, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckHealthy(ctx, h); err != nil {
		t.Fatal("new retained history changed current epoch eligibility", err)
	}
	if err := r.InvalidateHealthy(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := r.InvalidateHealthy(ctx, h); err != nil {
		t.Fatal("invalidation did not reconcile terminal state", err)
	}
	if err := r.CheckHealthy(ctx, h); err == nil {
		t.Fatal("invalidated primary remained healthy")
	}
	if got, err := r.Activate(ctx, l, owned, cut, closed, published, confirmed, ack); err == nil || got.state != nil {
		t.Fatal("historical native acknowledgement resurrected invalidated health")
	}
}

type velocityActivationCase struct {
	r         VelocityRecovery
	l         VelocityRecoveryLease
	owned     risk.VelocityLease
	cut       VelocityRecoveryClosure
	closed    risk.VelocityClosure
	published risk.VelocityPublication
	confirmed risk.VelocityConfirmation
	ack       risk.VelocityNativeConfirmation
}

func prepareEmptyVelocityActivation(t *testing.T, ctx context.Context, journal VelocityJournal, tenant string, epoch [16]byte, duration time.Duration) velocityActivationCase {
	t.Helper()
	j, _, native, verifier := risk.NewVelocityRecoveryAuthorities()
	f := velocityActivationCase{}
	var err error
	f.r, err = NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: duration, JournalIssuer: j, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	f.l, err = f.r.Acquire(ctx, tenant, epoch)
	if err != nil {
		t.Fatal(err)
	}
	f.owned, err = f.r.OwnedLease(ctx, f.l)
	if err != nil {
		t.Fatal(err)
	}
	// Empty native projection/provenance is simulated; only PG is real here.
	if _, err := journal.state.pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '1 hour 1 second' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, tenant, journal.state.namespace, epoch[:]); err != nil {
		t.Fatal(err)
	}
	f.cut, err = f.r.PrepareCoveredClosure(ctx, f.l)
	if err != nil {
		t.Fatal(err)
	}
	f.closed, err = f.r.OwnedClosure(ctx, f.l, f.owned, f.cut)
	if err != nil {
		t.Fatal(err)
	}
	f.published, err = native.AcknowledgePublication(ctx, f.owned, f.closed)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.r.ConfirmPublication(ctx, f.l, f.owned, f.cut, f.closed, f.published); err != nil {
		t.Fatal(err)
	}
	f.confirmed, err = f.r.OwnedConfirmation(ctx, f.l, f.owned, f.cut, f.closed, f.published)
	if err != nil {
		t.Fatal(err)
	}
	f.ack, err = native.AcknowledgeNativeConfirmation(ctx, f.owned, f.closed, f.published, f.confirmed)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f velocityActivationCase) activate(ctx context.Context) (VelocityHealthy, error) {
	return f.r.Activate(ctx, f.l, f.owned, f.cut, f.closed, f.published, f.confirmed, f.ack)
}

func testVelocityActivationCommitAndExpiry(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig, dsn, databaseName string) {
	t.Helper()
	pool, fault := newCommitAckPool(t, ctx, dsn, databaseName, nil)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("activation fault pool cleanup")
		}
	}()
	faultCfg := cfg
	faultCfg.Pool = pool
	faultJournal, err := NewVelocityJournal(faultCfg)
	if err != nil {
		t.Fatal(err)
	}
	f := prepareEmptyVelocityActivation(t, ctx, faultJournal, "activation-lost-ack", [16]byte{116}, 20*time.Second)
	fault.velocityActivation.Store(&f.l.state.epoch)
	if got, err := f.activate(ctx); err == nil || got.state != nil || fault.hits.Load() != 1 {
		t.Fatal("lost successful activation commit exposed custody", err)
	}
	fault.velocityActivation.Store(nil)
	var originalAt time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT activated_at FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, f.l.state.tenant, journal.state.namespace, f.l.state.epoch[:]).Scan(&originalAt); err != nil {
		t.Fatal("activation did not actually commit", err)
	}
	h, err := f.activate(ctx)
	if err != nil || !h.state.activated.Equal(originalAt) {
		t.Fatal("lost-ack activation did not reconcile original primary timestamp", err)
	}
	// The transport drops one successful response per armed target. Start a
	// separate fault observation for invalidation, not a second implicit retry.
	fault.hits.Store(0)
	fault.velocityInvalidate.Store(&f.l.state.epoch)
	if err := f.r.InvalidateHealthy(ctx, h); err == nil || fault.hits.Load() != 1 {
		t.Fatal("lost successful invalidation commit exposed success", err)
	}
	fault.velocityInvalidate.Store(nil)
	if err := f.r.CheckHealthy(ctx, h); err == nil {
		t.Fatal("lost-ack invalidation did not actually deny")
	}
	if err := f.r.InvalidateHealthy(ctx, h); err != nil {
		t.Fatal("lost-ack invalidation failed reconciliation", err)
	}
	f = prepareEmptyVelocityActivation(t, ctx, journal, "activation-expiry", [16]byte{117}, 2*time.Second)
	h, err = f.activate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.005)`, f.l.state.expires); err != nil {
		t.Fatal(err)
	}
	if err := f.r.CheckHealthy(ctx, h); err == nil {
		t.Fatal("expired original health admitted")
	}
	if got, err := f.activate(ctx); err == nil || got.state != nil {
		t.Fatal("retry refreshed expired health")
	}
	if err := f.r.InvalidateHealthy(ctx, h); err != nil {
		t.Fatal("expired current owner cannot invalidate its activation", err)
	}
	next, err := f.r.Acquire(ctx, f.l.state.tenant, f.l.state.epoch)
	if err != nil || next.state.generation != f.l.state.generation+1 {
		t.Fatal("unavailable expired activation could not enter new recovery", err)
	}
	if err := f.r.InvalidateHealthy(ctx, h); err == nil {
		t.Fatal("old health invalidated successor")
	}
}
