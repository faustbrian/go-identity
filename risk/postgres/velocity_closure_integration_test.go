//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func testVelocityClosure(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig) {
	t.Helper()
	var now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(tenant, attempt string) risk.CounterCommand {
		command, err := c.Prepare(risk.Context{Tenant: tenant, Operation: "identity.profile.get", Attempt: attempt}, risk.Subject{User: "subject"}, risk.BeforeReturn)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	issuer, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	recovery, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 5 * time.Second, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	command := prepare("closure-tenant", "original")
	receipt, err := journal.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := recovery.Acquire(ctx, "closure-tenant", [16]byte{74})
	if err != nil {
		t.Fatal(err)
	}
	if closure, err := recovery.PrepareClosure(ctx, lease); err == nil || closure != (VelocityRecoveryClosure{}) {
		t.Fatal("pending history granted closure")
	}
	if err := journal.RecordResult(ctx, receipt, risk.CounterNotCommitted, nil); err != nil {
		t.Fatal(err)
	}
	page, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 100)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("closure history missing", err)
	}
	if closure, err := recovery.PrepareClosure(ctx, lease); err == nil || closure != (VelocityRecoveryClosure{}) {
		t.Fatal("scanned but unapplied history granted closure")
	}
	owned, err := recovery.OwnedLease(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	history, err := recovery.OwnedHistory(ctx, lease, owned, page.Records()[0])
	if err != nil {
		t.Fatal(err)
	}
	ack, err := native.Acknowledge(ctx, owned, history)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.RecordApplied(ctx, lease, owned, ack); err != nil {
		t.Fatal(err)
	}
	closure, err := recovery.PrepareClosure(ctx, lease)
	if err != nil {
		t.Fatal("fully applied history did not close", err)
	}
	if err := recovery.CheckClosure(ctx, closure); err != nil {
		t.Fatal("acknowledged closure not current", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:], closure.state.through.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	covered, err := recovery.PrepareCoveredClosure(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := recovery.OwnedClosure(ctx, lease, owned, covered)
	if err != nil {
		t.Fatal("applied covered cut not exported", err)
	}
	if got, err := reader.Closure(ctx, owned, exported); err != nil || got.Position != page.Records()[0].state.position || got.Position <= 0 || !got.JournalStartedAt.Equal(covered.state.started) || !got.ReplayThrough.Equal(closure.state.through) {
		t.Fatal("export dropped applied progress or original cut", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := recovery.CheckClosure(canceled, closure); !errors.Is(err, context.Canceled) {
		t.Fatal("closure cancellation not preserved", err)
	}
	foreign, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 5 * time.Second, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	if err := foreign.CheckClosure(ctx, closure); err == nil {
		t.Fatal("foreign recovery owner accepted closure")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_seal=set_byte(applied_seal,0,get_byte(applied_seal,0)#1) WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if err := recovery.CheckClosure(ctx, closure); err == nil {
		t.Fatal("corrupt applied custody accepted closure")
	}
	if got, err := reader.Closure(ctx, owned, exported); err == nil || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("corrupt applied seal retained exported cut", err)
	}
	if got, err := recovery.OwnedClosure(ctx, lease, owned, covered); err == nil || got != (risk.VelocityClosure{}) {
		t.Fatal("corrupt applied seal exported cut", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_seal=set_byte(applied_seal,0,get_byte(applied_seal,0)#1) WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	// All closure SQL locks have ended. A same-scope new writer is denied by
	// durable admission, while another scope remains independently writable.
	if attempt, err := journal.RecordAttempt(ctx, prepare("closure-tenant", "late")); err == nil || attempt != (VelocityAttempt{}) {
		t.Fatal("new writer escaped durable closure")
	}
	if _, err := journal.RecordAttempt(ctx, prepare("other-closure-tenant", "independent")); err != nil {
		t.Fatal("closure blocked another scope", err)
	}
	if err := journal.RecordResult(ctx, receipt, risk.CounterNotCommitted, nil); err != nil {
		t.Fatal("closure broke unchanged terminal replay", err)
	}
	again, err := recovery.PrepareClosure(ctx, lease)
	if err != nil || !again.state.through.Equal(closure.state.through) {
		t.Fatal("closure retry replaced its stable checkpoint", err)
	}
	var state string
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT state FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]).Scan(&state); err != nil || state != "replaying" {
		t.Fatal("closure published health", err)
	}
	renewed, err := recovery.Renew(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.CheckClosure(ctx, closure); err == nil {
		t.Fatal("superseded closure remained valid")
	}
	late, err := journal.RecordAttempt(ctx, prepare("closure-tenant", "late"))
	if err != nil {
		t.Fatal("renewal did not reopen evidence admission", err)
	}
	if closure, err := recovery.PrepareClosure(ctx, renewed); err == nil || closure != (VelocityRecoveryClosure{}) {
		t.Fatal("renewal ignored newly pending history")
	}
	if err := journal.RecordResult(ctx, late, risk.CounterUnknown, nil); err != nil {
		t.Fatal(err)
	}
	if closure, err := recovery.PrepareClosure(ctx, renewed); err == nil || closure != (VelocityRecoveryClosure{}) {
		t.Fatal("unknown history granted closure")
	}
	expiring, err := recovery.Acquire(ctx, "closure-expiry-tenant", [16]byte{76})
	if err != nil {
		t.Fatal(err)
	}
	expiringClosure, err := recovery.PrepareClosure(ctx, expiring)
	if err != nil {
		t.Fatal("empty closed cut unavailable", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET lease_expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, expiring.state.tenant, journal.state.namespace, expiring.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if err := recovery.CheckClosure(ctx, expiringClosure); err == nil {
		t.Fatal("expired closure accepted")
	}
	if _, err := journal.RecordAttempt(ctx, prepare("closure-expiry-tenant", "after-expiry")); err != nil {
		t.Fatal("expired closure permanently blocked evidence", err)
	}
	// Pause a real writer AFTER it owns its shared scope lock. PostgreSQL queues
	// later shared requests behind a waiting exclusive request, so introducing
	// the writer after closure was queued would not exercise overlap.
	raceLease, err := recovery.Acquire(ctx, "closure-race-tenant", [16]byte{75})
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := cfg.Pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer velocityRollback(blocker)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(9137401)`); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `CREATE FUNCTION risk_store.pause_closure_writer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(9137401); RETURN NEW; END $$; CREATE TRIGGER pause_closure_writer BEFORE INSERT ON risk_store.velocity_attempts FOR EACH ROW WHEN (NEW.tenant_id='closure-race-tenant') EXECUTE FUNCTION risk_store.pause_closure_writer()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := cfg.Pool.Raw().Exec(cleanup, `DROP TRIGGER pause_closure_writer ON risk_store.velocity_attempts; DROP FUNCTION risk_store.pause_closure_writer()`); err != nil {
			t.Error("closure latch cleanup")
		}
	}()
	written := make(chan error, 1)
	writerCommand := prepare("closure-race-tenant", "overlap")
	go func() { _, err := journal.RecordAttempt(ctx, writerCommand); written <- err }()
	writerJoined := false
	defer func() {
		velocityRollback(blocker)
		if !writerJoined {
			<-written
		}
	}()
	waitFor := func(query string) {
		t.Helper()
		for i := 0; i < 40; i++ {
			if _, err := blocker.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
				t.Fatal(err)
			}
			var waiting bool
			if err := blocker.QueryRow(ctx, query).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			if _, err := blocker.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
				t.Fatal(err)
			}
		}
		t.Fatal("closure latch did not reach required boundary")
	}
	waitFor(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'INSERT INTO %velocity_attempts%')`)
	type response struct {
		closure VelocityRecoveryClosure
		err     error
	}
	finished := make(chan response, 1)
	go func() { c, err := recovery.PrepareClosure(ctx, raceLease); finished <- response{c, err} }()
	joined := false
	defer func() {
		velocityRollback(blocker)
		if !joined {
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Error("closure worker cleanup")
			}
		}
	}()
	waitFor(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'SELECT pg_advisory_xact_lock(%')`)
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	writerErr := <-written
	writerJoined = true
	if writerErr != nil {
		t.Fatal("overlapping writer failed before closure", writerErr)
	}
	result := <-finished
	joined = true
	if result.err == nil || result.closure != (VelocityRecoveryClosure{}) {
		t.Fatal("closure omitted overlapping committed history")
	}
}
