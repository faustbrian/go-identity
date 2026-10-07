//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func testVelocityPublication(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig, dsn, databaseName string) {
	t.Helper()
	j, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	r, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 20 * time.Second, JournalIssuer: j, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	confirmer, ok := any(r).(interface {
		ConfirmPublication(context.Context, VelocityRecoveryLease, risk.VelocityLease, VelocityRecoveryClosure, risk.VelocityClosure, risk.VelocityPublication) error
	})
	if !ok {
		t.Fatal("primary cannot durably confirm original native publication")
	}
	exporter, ok := any(r).(interface {
		OwnedConfirmation(context.Context, VelocityRecoveryLease, risk.VelocityLease, VelocityRecoveryClosure, risk.VelocityClosure, risk.VelocityPublication) (risk.VelocityConfirmation, error)
	})
	if !ok {
		t.Fatal("primary cannot export recorded confirmation custody")
	}
	l, err := r.Acquire(ctx, "publication-tenant", [16]byte{101})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := r.OwnedLease(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	// Test-only primary provenance. Production cannot backdate coverage.
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '1 hour 1 second' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	cut, err := r.PrepareCoveredClosure(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := r.OwnedClosure(ctx, l, owned, cut)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CheckPublication(ctx, l, owned, cut, exported, risk.VelocityPublication{}); err == nil {
		t.Fatal("missing native publication became confirmation")
	}
	// This fixture simulates attributable native publication; it does not prove
	// Valkey IO, marker continuity or present admission.
	published, err := native.AcknowledgePublication(ctx, owned, exported)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CheckPublication(ctx, l, owned, cut, exported, published); err == nil {
		t.Fatal("native acknowledgement alone became primary confirmation")
	}
	if k, err := exporter.OwnedConfirmation(ctx, l, owned, cut, exported, published); err == nil || k != (risk.VelocityConfirmation{}) {
		t.Fatal("publication alone exported primary confirmation")
	}
	if err := confirmer.ConfirmPublication(ctx, l, owned, cut, exported, published); err != nil {
		t.Fatal("exact native publication not confirmed", err)
	}
	b, err := reader.Closure(ctx, owned, exported)
	if err != nil {
		t.Fatal("confirmation invalidated original custody", err)
	}
	var id []byte
	var at, expiry time.Time
	var state string
	var healthy *time.Time
	read := func() {
		t.Helper()
		if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT publication_id,publication_confirmed_at,lease_expires_at,state,healthy_at FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]).Scan(&id, &at, &expiry, &state, &healthy); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if string(id) != string(b.ID[:]) || at.Before(b.ReplayThrough) || !at.Before(l.state.expires) || !expiry.Equal(l.state.expires) || state != "replaying" || healthy != nil {
		t.Fatal("confirmation changed original cut, expiry or admission state")
	}
	originalAt := at
	confirmation, err := exporter.OwnedConfirmation(ctx, l, owned, cut, exported, published)
	if err != nil {
		t.Fatal("recorded confirmation cannot export", err)
	}
	if got, err := verifier.Confirmation(ctx, owned, exported, published, confirmation); err != nil || got != b {
		t.Fatal("configured native consumer lost original confirmed cut", err)
	}
	if err := confirmer.ConfirmPublication(ctx, l, owned, cut, exported, published); err != nil {
		t.Fatal("matching confirmation replay unavailable", err)
	}
	read()
	if !at.Equal(originalAt) || !expiry.Equal(l.state.expires) {
		t.Fatal("confirmation replay refreshed original facts")
	}
	if err := r.CheckPublication(ctx, l, owned, cut, exported, published); err != nil {
		t.Fatal("acknowledged confirmation cannot be rechecked", err)
	}
	var wg sync.WaitGroup
	var failures [4]error
	for i := range failures {
		wg.Add(1)
		go func() {
			defer wg.Done()
			failures[i] = r.ConfirmPublication(ctx, l, owned, cut, exported, published)
			if failures[i] == nil {
				k, err := exporter.OwnedConfirmation(ctx, l, owned, cut, exported, published)
				failures[i] = err
				if err == nil {
					_, failures[i] = verifier.Confirmation(ctx, owned, exported, published, k)
				}
			}
		}()
	}
	wg.Wait()
	for _, err := range failures {
		if err != nil {
			t.Fatal("concurrent matching confirmation failed", err)
		}
	}
	read()
	if !at.Equal(originalAt) {
		t.Fatal("concurrent confirmation renewed time")
	}
	replacement, err := r.OwnedClosure(ctx, l, owned, cut)
	if err != nil {
		t.Fatal(err)
	}
	for _, negative := range []struct {
		lease       VelocityRecoveryLease
		owned       risk.VelocityLease
		cut         VelocityRecoveryClosure
		exported    risk.VelocityClosure
		publication risk.VelocityPublication
	}{
		{VelocityRecoveryLease{}, owned, cut, exported, published},
		{l, risk.VelocityLease{}, cut, exported, published},
		{l, owned, VelocityRecoveryClosure{}, exported, published},
		{l, owned, cut, risk.VelocityClosure{}, published},
		{l, owned, cut, replacement, published},
		{l, owned, cut, exported, risk.VelocityPublication{}},
	} {
		if err := r.ConfirmPublication(ctx, negative.lease, negative.owned, negative.cut, negative.exported, negative.publication); err == nil {
			t.Fatal("substituted custody confirmed publication")
		}
		if k, err := exporter.OwnedConfirmation(ctx, negative.lease, negative.owned, negative.cut, negative.exported, negative.publication); err == nil || k != (risk.VelocityConfirmation{}) {
			t.Fatal("substituted custody exported confirmation")
		}
	}
	foreignJ, _, foreignN, _ := risk.NewVelocityRecoveryAuthorities()
	lb, err := reader.Lease(owned)
	if err != nil {
		t.Fatal(err)
	}
	foreignLease, err := foreignJ.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	foreignCut, err := foreignJ.Closure(foreignLease, b, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	foreignPublication, err := foreignN.AcknowledgePublication(ctx, foreignLease, foreignCut)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmPublication(ctx, l, foreignLease, cut, foreignCut, foreignPublication); err == nil {
		t.Fatal("foreign graph confirmed same projected fields")
	}
	for _, change := range []func(*velocityRecoveryClosure){
		func(c *velocityRecoveryClosure) { c.position++ },
		func(c *velocityRecoveryClosure) { c.from = c.from.Add(-time.Microsecond) },
		func(c *velocityRecoveryClosure) { c.through = c.through.Add(time.Microsecond) },
		func(c *velocityRecoveryClosure) { c.started = c.started.Add(-time.Microsecond) },
		func(c *velocityRecoveryClosure) { c.started = time.Time{} },
	} {
		altered := *cut.state
		change(&altered)
		if err := r.ConfirmPublication(ctx, l, owned, VelocityRecoveryClosure{state: &altered}, exported, published); err == nil {
			t.Fatal("altered primary cut confirmed publication")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.ConfirmPublication(canceled, l, owned, cut, exported, published); !errors.Is(err, context.Canceled) {
		t.Fatal("confirmation lost cancellation", err)
	}
	if err := r.ConfirmPublication(nil, l, owned, cut, exported, published); err == nil {
		t.Fatal("nil context confirmed publication")
	}
	for _, badCtx := range []context.Context{nil, canceled} {
		if k, err := exporter.OwnedConfirmation(badCtx, l, owned, cut, exported, published); err == nil || k != (risk.VelocityConfirmation{}) {
			t.Fatal("invalid context exported confirmation")
		}
	}
	if k, err := exporter.OwnedConfirmation(canceled, l, owned, cut, exported, published); !errors.Is(err, context.Canceled) || k != (risk.VelocityConfirmation{}) {
		t.Fatal("export lost cancellation", err)
	}
	// Waiting on the existing primary fence is bounded and returns no success.
	blocker, err := cfg.Pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer velocityRollback(blocker)
	if err := journal.state.scopeLock(ctx, blocker, l.state.tenant, false); err != nil {
		t.Fatal(err)
	}
	waiting, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	err = r.CheckPublication(waiting, l, owned, cut, exported, published)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked primary confirmation ignored deadline", err)
	}
	waiting, stop = context.WithTimeout(ctx, 20*time.Millisecond)
	if k, err := exporter.OwnedConfirmation(waiting, l, owned, cut, exported, published); !errors.Is(err, context.DeadlineExceeded) || k != (risk.VelocityConfirmation{}) {
		t.Fatal("blocked export ignored deadline", err)
	}
	stop()
	waiting, stop = context.WithTimeout(ctx, 20*time.Millisecond)
	if got, err := verifier.Confirmation(waiting, owned, exported, published, confirmation); !errors.Is(err, context.DeadlineExceeded) || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("retained custody ignored primary deadline", err)
	}
	stop()
	velocityRollback(blocker)
	// Corrupt primary confirmation cannot be replaced by replaying good custody.
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET publication_id=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:], wrappingKey(8)); err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmPublication(ctx, l, owned, cut, exported, published); err == nil {
		t.Fatal("corrupt confirmation replaced by retry")
	}
	if err := r.CheckPublication(ctx, l, owned, cut, exported, published); err == nil {
		t.Fatal("corrupt confirmation remained valid")
	}
	if got, err := verifier.Confirmation(ctx, owned, exported, published, confirmation); err == nil || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("retained confirmation bypassed corrupt primary record")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET publication_id=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:], b.ID[:]); err != nil {
		t.Fatal(err)
	}
	// Removing the actual record invalidates retained custody even though the
	// original publication and covered cut remain genuine.
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET publication_id=NULL,publication_confirmed_at=NULL WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if got, err := verifier.Confirmation(ctx, owned, exported, published, confirmation); err == nil || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("missing primary confirmation admitted retained custody")
	}
	if k, err := exporter.OwnedConfirmation(ctx, l, owned, cut, exported, published); err == nil || k != (risk.VelocityConfirmation{}) {
		t.Fatal("export implicitly rewrote missing confirmation")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET publication_id=$4,publication_confirmed_at=$5 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:], b.ID[:], originalAt); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:], b.ReplayThrough); err != nil {
		t.Fatal(err)
	}
	if got, err := verifier.Confirmation(ctx, owned, exported, published, confirmation); err == nil || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("lost coverage admitted retained custody")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:], b.JournalStartedAt); err != nil {
		t.Fatal(err)
	}
	// Confirmation retains closure: a late new writer cannot escape it.
	var now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command, err := coordinator.Prepare(risk.Context{Tenant: l.state.tenant, Operation: "identity.profile.get", Attempt: "late"}, risk.Subject{User: "subject"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	if attempt, err := journal.RecordAttempt(ctx, command); err == nil || attempt != (VelocityAttempt{}) {
		t.Fatal("confirmation reopened journal admission")
	}
	read()
	if !at.Equal(originalAt) || string(id) != string(b.ID[:]) || !expiry.Equal(l.state.expires) {
		t.Fatal("negative confirmation changed durable facts")
	}
	// Same-owner renewal preserves coverage but removes predecessor confirmation.
	renewed, err := r.Renew(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	var stored *time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT publication_id,publication_confirmed_at FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]).Scan(&id, &stored); err != nil || id != nil || stored != nil {
		t.Fatal("renewal retained predecessor publication", err)
	}
	if err := r.ConfirmPublication(ctx, l, owned, cut, exported, published); err == nil {
		t.Fatal("renewal accepted old publication")
	}
	if err := r.CheckPublication(ctx, l, owned, cut, exported, published); err == nil {
		t.Fatal("renewal left old confirmation usable")
	}
	if got, err := verifier.Confirmation(ctx, owned, exported, published, confirmation); err == nil || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("renewal left exported custody usable")
	}
	newOwned, err := r.OwnedLease(ctx, renewed)
	if err != nil {
		t.Fatal(err)
	}
	newCut, err := r.PrepareCoveredClosure(ctx, renewed)
	if err != nil {
		t.Fatal(err)
	}
	newExported, err := r.OwnedClosure(ctx, renewed, newOwned, newCut)
	if err != nil {
		t.Fatal(err)
	}
	newPublication, err := native.AcknowledgePublication(ctx, newOwned, newExported)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmPublication(ctx, renewed, newOwned, newCut, newExported, newPublication); err != nil {
		t.Fatal("successor publication cannot confirm", err)
	}
	newConfirmation, err := exporter.OwnedConfirmation(ctx, renewed, newOwned, newCut, newExported, newPublication)
	if err != nil {
		t.Fatal("successor confirmation cannot export", err)
	}
	// Primary expiry, not process time, fences confirmation and takeover.
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET lease_expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckPublication(ctx, renewed, newOwned, newCut, newExported, newPublication); err == nil {
		t.Fatal("expired primary confirmation remained usable")
	}
	if got, err := verifier.Confirmation(ctx, newOwned, newExported, newPublication, newConfirmation); err == nil || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("expired retained confirmation remained usable")
	}
	takeover, err := r.Acquire(ctx, l.state.tenant, l.state.epoch)
	if err != nil {
		t.Fatal("expired confirmed epoch cannot be taken over", err)
	}
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT publication_id,publication_confirmed_at FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]).Scan(&id, &stored); err != nil || id != nil || stored != nil {
		t.Fatal("takeover inherited publication", err)
	}
	testVelocityPublicationAck(t, ctx, cfg, dsn, databaseName)
	// This isolated schema is deliberately downgraded only after confirmation
	// tests. Old lease/page APIs must work without optional publication columns.
	if _, err := cfg.Pool.Raw().Exec(ctx, `ALTER TABLE risk_store.velocity_epochs DROP COLUMN publication_id,DROP COLUMN publication_confirmed_at`); err != nil {
		t.Fatal(err)
	}
	legacyRenewal, err := r.Renew(ctx, takeover)
	if err != nil {
		t.Fatal("optional publication migration broke old-schema renewal", err)
	}
	if _, err := r.ReadPage(ctx, legacyRenewal, VelocityReplayCursor{}, 10); err != nil {
		t.Fatal("optional publication migration broke old-schema paging", err)
	}
	legacyOwned, err := r.OwnedLease(ctx, legacyRenewal)
	if err != nil {
		t.Fatal(err)
	}
	legacyCut, err := r.PrepareCoveredClosure(ctx, legacyRenewal)
	if err != nil {
		t.Fatal(err)
	}
	legacyExport, err := r.OwnedClosure(ctx, legacyRenewal, legacyOwned, legacyCut)
	if err != nil {
		t.Fatal(err)
	}
	legacyPublication, err := native.AcknowledgePublication(ctx, legacyOwned, legacyExport)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmPublication(ctx, legacyRenewal, legacyOwned, legacyCut, legacyExport, legacyPublication); err == nil {
		t.Fatal("confirmation without required migration succeeded")
	}
	if k, err := exporter.OwnedConfirmation(ctx, legacyRenewal, legacyOwned, legacyCut, legacyExport, legacyPublication); err == nil || k != (risk.VelocityConfirmation{}) {
		t.Fatal("missing migration exported confirmation")
	}
}

func testVelocityPublicationAck(t *testing.T, ctx context.Context, cfg VelocityJournalConfig, dsn, databaseName string) {
	t.Helper()
	primary := cfg.Pool
	pool, fault := newCommitAckPool(t, ctx, dsn, databaseName, nil)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(cleanup); err != nil {
			t.Error("publication acknowledgement pool cleanup")
		}
	}()
	cfg.Pool = pool
	journal, err := NewVelocityJournal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	j, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	r, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 20 * time.Second, JournalIssuer: j, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := primary.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command, err := coordinator.Prepare(risk.Context{Tenant: "publication-ack-tenant", Operation: "identity.profile.get", Attempt: "original"}, risk.Subject{User: "subject"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := journal.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, attempt, risk.CounterNotCommitted, nil); err != nil {
		t.Fatal(err)
	}
	l, err := r.Acquire(ctx, "publication-ack-tenant", [16]byte{102})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := r.OwnedLease(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.ReadPage(ctx, l, VelocityReplayCursor{}, 10)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("publication original history missing", err)
	}
	history, err := r.OwnedHistory(ctx, l, owned, page.Records()[0])
	if err != nil {
		t.Fatal(err)
	}
	ack, err := native.Acknowledge(ctx, owned, history)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RecordApplied(ctx, l, owned, ack); err != nil {
		t.Fatal(err)
	}
	if _, err := primary.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '1 hour 1 second' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	cut, err := r.PrepareCoveredClosure(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := r.OwnedClosure(ctx, l, owned, cut)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := native.AcknowledgePublication(ctx, owned, exported)
	if err != nil {
		t.Fatal(err)
	}
	// Invalidate primary applied state after native acknowledgement, before the
	// confirmation transaction. No pre-IO proof can substitute for rechecking.
	if _, err := primary.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_seal=set_byte(applied_seal,0,get_byte(applied_seal,0)#1) WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmPublication(ctx, l, owned, cut, exported, publication); err == nil {
		t.Fatal("changed primary applied proof confirmed publication")
	}
	if _, err := primary.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_seal=set_byte(applied_seal,0,get_byte(applied_seal,0)#1) WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	fault.velocityPublication.Store(&l.state.epoch)
	if err := r.ConfirmPublication(ctx, l, owned, cut, exported, publication); err == nil || fault.hits.Load() != 1 {
		t.Fatal("lost successful confirmation commit exposed success", err)
	}
	fault.velocityPublication.Store(nil)
	var id []byte
	var at time.Time
	read := func() {
		t.Helper()
		if err := primary.Raw().QueryRow(ctx, `SELECT publication_id,publication_confirmed_at FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]).Scan(&id, &at); err != nil {
			t.Fatal("independent primary confirmation read", err)
		}
	}
	read()
	b, err := reader.Closure(ctx, owned, exported)
	if err != nil || string(id) != string(b.ID[:]) || b.Position <= 0 {
		t.Fatal("lost-ack confirmation did not actually commit original applied cut", err)
	}
	originalAt := at
	if err := r.CheckPublication(ctx, l, owned, cut, exported, publication); err != nil {
		t.Fatal("committed confirmation cannot reconcile", err)
	}
	confirmation, err := r.OwnedConfirmation(ctx, l, owned, cut, exported, publication)
	if err != nil {
		t.Fatal("reconciled commit cannot export confirmation", err)
	}
	if got, err := verifier.Confirmation(ctx, owned, exported, publication, confirmation); err != nil || got != b {
		t.Fatal("reconciled confirmation lost original applied cut", err)
	}
	if _, err := primary.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_seal=set_byte(applied_seal,0,get_byte(applied_seal,0)#1) WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if got, err := verifier.Confirmation(ctx, owned, exported, publication, confirmation); err == nil || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("corrupt applied proof admitted retained confirmation")
	}
	if _, err := primary.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_seal=set_byte(applied_seal,0,get_byte(applied_seal,0)#1) WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmPublication(ctx, l, owned, cut, exported, publication); err != nil {
		t.Fatal("matching retry after commit-ack loss failed", err)
	}
	read()
	if !at.Equal(originalAt) || fault.hits.Load() != 1 {
		t.Fatal("ambiguous confirmation replay refreshed or redispatched")
	}
}
