//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/internal/velocity"
)

// Real primary transactions and the owned connection execute. Native effects
// are replaced only at the internal adapter boundary; this is not live Valkey.
func testVelocityJournalConnection(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig) {
	t.Helper()
	f := prepareEmptyVelocityActivation(t, ctx, journal, "connection-tenant", [16]byte{124}, 20*time.Second)
	health, err := f.activate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	factory, ok := any(f.r).(interface {
		OwnedJournal(context.Context, VelocityHealthy) (velocity.Journal, error)
	})
	if !ok {
		t.Fatal("primary owner lacks concrete journal connection")
	}
	owned, err := factory.OwnedJournal(ctx, health)
	if err != nil {
		t.Fatal(err)
	}
	var effects atomic.Int32
	mode := risk.CounterCommitted
	native, err := velocity.BindNative(journal.state.replay.Namespace(), func(c risk.CounterCommand) error { return c.ValidateConfiguration(cfg.Policy, cfg.Keys) }, func(context.Context, risk.CounterCommand) error { return nil }, func(effectCtx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		// A separate primary transaction sees acknowledged intent and all
		// aliases, and obtains an exclusive fence: no journal lock spans IO.
		digest, err := journal.state.replay.Attempt(c)
		if err != nil {
			return risk.CounterResult{}, err
		}
		var outcome string
		if err := cfg.Pool.Raw().QueryRow(effectCtx, `SELECT outcome FROM risk_store.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND attempt_digest=$3`, c.Bindings().Tenant, journal.state.namespace, digest[:]).Scan(&outcome); err != nil || outcome != "pending" {
			t.Error("native reached before acknowledged intent", err)
			return risk.CounterResult{}, risk.ErrInvalidCounterResult
		}
		var aliases, pendingSnapshots int
		if err := cfg.Pool.Raw().QueryRow(effectCtx, `SELECT count(*) FROM risk_store.velocity_aliases a JOIN risk_store.velocity_attempts v USING(sequence) WHERE v.tenant_id=$1 AND v.namespace_digest=$2 AND v.attempt_digest=$3`, c.Bindings().Tenant, journal.state.namespace, digest[:]).Scan(&aliases); err != nil {
			return risk.CounterResult{}, err
		}
		wantAliases := 0
		for _, target := range c.Bindings().Targets {
			wantAliases += len(target.Keys)
		}
		if err := cfg.Pool.Raw().QueryRow(effectCtx, `SELECT count(*) FROM risk_store.velocity_snapshots a JOIN risk_store.velocity_attempts v USING(sequence) WHERE v.tenant_id=$1 AND v.namespace_digest=$2 AND v.attempt_digest=$3`, c.Bindings().Tenant, journal.state.namespace, digest[:]).Scan(&pendingSnapshots); err != nil || aliases != wantAliases || pendingSnapshots != 0 {
			t.Error("native reached incomplete or fabricated primary intent", err)
			return risk.CounterResult{}, risk.ErrInvalidCounterResult
		}
		tx, err := cfg.Pool.Raw().Begin(effectCtx)
		if err != nil {
			return risk.CounterResult{}, err
		}
		defer velocityRollback(tx)
		if err := f.r.state.lock(effectCtx, tx, c.Bindings().Tenant); err != nil {
			t.Error("journal lock spans native IO", err)
			return risk.CounterResult{}, err
		}
		if err := tx.Rollback(effectCtx); err != nil {
			return risk.CounterResult{}, err
		}
		effects.Add(1)
		var at time.Time
		if err := cfg.Pool.Raw().QueryRow(effectCtx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
			return risk.CounterResult{}, err
		}
		var snapshots []risk.Counter
		if mode == risk.CounterCommitted {
			for _, target := range c.Bindings().Targets {
				snapshots = append(snapshots, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: at, WindowStartedAt: at, WindowExpiresAt: at.Add(c.Bindings().Window)})
			}
		}
		return risk.NewCounterResult(c, mode, snapshots)
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := velocity.NewStore(owned, native, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(attempt, tenant string) risk.CounterCommand {
		t.Helper()
		var at time.Time
		if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Clock: func() time.Time { return at }, Timeout: time.Second, Store: store})
		if err != nil {
			t.Fatal(err)
		}
		command, err := c.Prepare(risk.Context{Tenant: tenant, Operation: "identity.profile.get", Attempt: attempt}, risk.Subject{User: "user"}, risk.BeforeReturn)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	for _, outcome := range []risk.CounterOutcome{risk.CounterCommitted, risk.CounterNotCommitted, risk.CounterUnknown} {
		mode = outcome
		command := prepare("connection-"+string(rune('a'+outcome)), "connection-tenant")
		result, err := store.Mutate(ctx, command)
		if err != nil {
			t.Fatal("owned primary connection denied", err)
		}
		got, snapshot, err := result.Declaration(command)
		if err != nil || got != outcome {
			t.Fatal("original native outcome lost", err)
		}
		retained, err := journal.ReadResult(ctx, command)
		if err != nil {
			t.Fatal("native outcome was not durably retained", err)
		}
		old, saved, err := retained.Declaration(command)
		if err != nil || old != outcome || len(snapshot) != len(saved) {
			t.Fatal("primary changed original declaration", err)
		}
		for _, want := range snapshot {
			found := false
			for _, got := range saved {
				if got.Kind == want.Kind && got.Value == want.Value && got.ObservedAt.Equal(want.ObservedAt) && got.WindowStartedAt.Equal(want.WindowStartedAt) && got.WindowExpiresAt.Equal(want.WindowExpiresAt) {
					found = true
				}
			}
			if !found {
				t.Fatal("primary changed original snapshot")
			}
		}
		before := effects.Load()
		if _, err := store.Mutate(ctx, command); err != nil || effects.Load() != before {
			t.Fatal("terminal primary replay redispatched", err)
		}
	}
	mode = risk.CounterCommitted
	concurrent := prepare("connection-concurrent", "connection-tenant")
	beforeConcurrent := effects.Load()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = store.Mutate(ctx, concurrent) }()
	}
	wg.Wait()
	if effects.Load() != beforeConcurrent+1 {
		t.Fatal("concurrent logical attempt duplicated native effects")
	}
	if _, err := journal.ReadResult(ctx, concurrent); err != nil {
		t.Fatal("concurrent original result missing", err)
	}
	// A failed intent commit cannot reach native work through the connection.
	if _, err := cfg.Pool.Raw().Exec(ctx, `CREATE FUNCTION risk_store.reject_connection_intent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$; CREATE TRIGGER reject_connection_intent BEFORE INSERT ON risk_store.velocity_aliases FOR EACH ROW EXECUTE FUNCTION risk_store.reject_connection_intent()`); err != nil {
		t.Fatal(err)
	}
	beforeFailed := effects.Load()
	if _, err := store.Mutate(ctx, prepare("connection-insert-failure", "connection-tenant")); err == nil || effects.Load() != beforeFailed {
		t.Fatal("failed intent reached native effects")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `DROP TRIGGER reject_connection_intent ON risk_store.velocity_aliases; DROP FUNCTION risk_store.reject_connection_intent()`); err != nil {
		t.Fatal(err)
	}
	// After a known native commit, result rollback denies admission without
	// erasing the commit or turning the remaining pending intent into retry rights.
	if _, err := cfg.Pool.Raw().Exec(ctx, `CREATE FUNCTION risk_store.reject_connection_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$; CREATE TRIGGER reject_connection_result BEFORE INSERT ON risk_store.velocity_snapshots FOR EACH ROW EXECUTE FUNCTION risk_store.reject_connection_result()`); err != nil {
		t.Fatal(err)
	}
	failedResult := prepare("connection-result-failure", "connection-tenant")
	result, err := store.Mutate(ctx, failedResult)
	if err == nil || effects.Load() != beforeFailed+1 {
		t.Fatal("result failure lost dispatch truth", err)
	}
	if outcome, _, err := result.Declaration(failedResult); err != nil || outcome != risk.CounterCommitted {
		t.Fatal("result rollback erased native commit", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `DROP TRIGGER reject_connection_result ON risk_store.velocity_snapshots; DROP FUNCTION risk_store.reject_connection_result()`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Mutate(ctx, failedResult); err == nil || effects.Load() != beforeFailed+1 {
		t.Fatal("result rollback authorized resend")
	}
	pending := prepare("connection-pending", "connection-tenant")
	if _, err := journal.RecordAttempt(ctx, pending); err != nil {
		t.Fatal(err)
	}
	before := effects.Load()
	if _, err := store.Mutate(ctx, pending); err == nil || effects.Load() != before {
		t.Fatal("pending journal authorized native retry")
	}
	if _, err := store.Mutate(ctx, prepare("foreign", "foreign-tenant")); err == nil || effects.Load() != before {
		t.Fatal("healthy connection admitted foreign tenant")
	}
	for _, bad := range []VelocityHealthy{{}, {state: &velocityHealthy{}}} {
		if _, err := factory.OwnedJournal(ctx, bad); err == nil {
			t.Fatal("invalid health bound")
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := factory.OwnedJournal(canceled, health); !errors.Is(err, context.Canceled) {
		t.Fatal("factory cancellation lost", err)
	}
	if err := f.r.InvalidateHealthy(ctx, health); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Mutate(ctx, prepare("after-invalidation", "connection-tenant")); err == nil || effects.Load() != before {
		t.Fatal("connection cached invalidated primary health")
	}
}
