//go:build integration

package postgres

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

type velocityReadStore struct{ journal VelocityJournal }

func (s velocityReadStore) Mutate(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	return s.journal.ReadResult(ctx, c)
}

func testVelocityResults(t *testing.T, ctx context.Context, pool *database.Pool, j VelocityJournal, cfg VelocityJournalConfig, prepare func(string, risk.Subject, risk.Phase) risk.CounterCommand, dsn, databaseName string) {
	t.Helper()
	subject := risk.Subject{Network: "2001:db8::1", Device: "device", IdentifierDigest: strings.Repeat("a", 64)}
	snapshotFor := func(c risk.CounterCommand) []risk.Counter {
		var now time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		b := c.Bindings()
		var result []risk.Counter
		for i, target := range b.Targets {
			value := uint64(0)
			if i == 0 {
				value = math.MaxUint64
			}
			result = append(result, risk.Counter{Kind: string(target.Dimension), Value: value, ObservedAt: now, WindowStartedAt: now.Add(-time.Second), WindowExpiresAt: now.Add(b.Window - time.Second)})
		}
		return result
	}
	for _, phase := range []risk.Phase{risk.BeforeCredential, risk.BeforeReturn} {
		selected := subject
		if phase == risk.BeforeReturn {
			selected = risk.Subject{User: "user"}
		}
		attempt := "result-" + string(phase)
		c := prepare(attempt, selected, phase)
		a, err := j.RecordAttempt(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := snapshotFor(c)
		if err := j.RecordResult(ctx, a, risk.CounterCommitted, append(append([]risk.Counter(nil), snapshot...), risk.Counter{})); !errors.Is(err, risk.ErrInvalidCounterResult) {
			t.Fatal("oversized snapshot admitted", err)
		}
		for _, mutate := range []func([]risk.Counter){
			func(v []risk.Counter) { v[0].WindowExpiresAt = v[0].WindowExpiresAt.Add(-time.Microsecond) },
			func(v []risk.Counter) { v[0].ObservedAt = v[0].WindowExpiresAt },
			func(v []risk.Counter) { v[0].ObservedAt = v[0].WindowStartedAt.Add(-time.Microsecond) },
			func(v []risk.Counter) { v[0].ObservedAt = v[0].ObservedAt.Add(time.Nanosecond) },
		} {
			bad := append([]risk.Counter(nil), snapshot...)
			mutate(bad)
			if err := j.RecordResult(ctx, a, risk.CounterCommitted, bad); err == nil {
				t.Fatal("unsupported snapshot admitted")
			}
		}
		if err := j.RecordResult(ctx, a, risk.CounterCommitted, snapshot); err != nil {
			t.Fatal("committed declaration rejected", err)
		}
		if err := j.RecordResult(ctx, a, risk.CounterCommitted, snapshot); err != nil {
			t.Fatal("identical terminal replay rejected", err)
		}
		bad := append([]risk.Counter(nil), snapshot...)
		bad[0].Value--
		if err := j.RecordResult(ctx, a, risk.CounterCommitted, bad); err == nil {
			t.Fatal("terminal overwrite admitted")
		}
		for _, v := range snapshot {
			var value string
			var observed, started, expires time.Time
			if err := pool.Raw().QueryRow(ctx, `SELECT value::text,observed_at,started_at,expires_at FROM risk_store.velocity_snapshots WHERE sequence=$1 AND dimension=$2`, a.state.sequence, v.Kind).Scan(&value, &observed, &started, &expires); err != nil || value != strconv.FormatUint(v.Value, 10) || !observed.Equal(v.ObservedAt) || !started.Equal(v.WindowStartedAt) || !expires.Equal(v.WindowExpiresAt) {
				t.Fatal("original result changed", err)
			}
		}
		var now time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Clock: func() time.Time { return now }, Timeout: time.Second, Store: velocityReadStore{j}})
		if err != nil {
			t.Fatal(err)
		}
		replay, err := coordinator.Prepare(risk.Context{Tenant: "native-tenant", Operation: c.Bindings().Operation, Attempt: attempt}, selected, phase)
		if err != nil {
			t.Fatal(err)
		}
		evaluation, err := coordinator.Mutate(ctx, replay)
		if err != nil || evaluation.Outcome != risk.CounterCommitted || evaluation.Signal.State != risk.SignalThrottle || !evaluation.Signal.ObservedAt.Equal(snapshot[0].ObservedAt) || !evaluation.Signal.ExpiresAt.Equal(snapshot[0].WindowExpiresAt) {
			t.Fatal("public readback refreshed or changed result", err)
		}
		now = now.Add(c.Bindings().Window + time.Second)
		stale, err := coordinator.Prepare(risk.Context{Tenant: "native-tenant", Operation: c.Bindings().Operation, Attempt: attempt}, selected, phase)
		if err != nil {
			t.Fatal(err)
		}
		evaluation, err = coordinator.Mutate(ctx, stale)
		if err != nil || evaluation.Outcome != risk.CounterCommitted || evaluation.Signal.State != risk.SignalUnavailable {
			t.Fatal("historical result gained fresh authority", err)
		}
		// Corrupting an ordered retained alias cannot yield a positive readback.
		if _, err := pool.Raw().Exec(ctx, `DELETE FROM risk_store.velocity_aliases WHERE sequence=$1 AND dimension='tenant' AND key_rank=2`, a.state.sequence); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ReadResult(ctx, c); err == nil {
			t.Fatal("incomplete aliases accepted")
		}
	}
	for i, outcome := range []risk.CounterOutcome{risk.CounterNotCommitted, risk.CounterUnknown} {
		c := prepare("negative-"+strconv.Itoa(i), subject, risk.BeforeCredential)
		a, err := j.RecordAttempt(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.RecordResult(ctx, a, outcome, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ReadResult(ctx, c); err != nil {
			t.Fatal("negative outcome unreadable", err)
		}
		var now time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Clock: func() time.Time { return now }, Timeout: time.Second, Store: velocityReadStore{j}})
		if err != nil {
			t.Fatal(err)
		}
		replay, err := coordinator.Prepare(risk.Context{Tenant: "native-tenant", Operation: c.Bindings().Operation, Attempt: c.Bindings().Attempt}, subject, risk.BeforeCredential)
		if err != nil {
			t.Fatal(err)
		}
		evaluation, err := coordinator.Mutate(ctx, replay)
		if err != nil || evaluation.Outcome != outcome || evaluation.Signal.State != risk.SignalUnavailable {
			t.Fatal("negative outcome changed or gained authority", err)
		}
		if err := j.RecordResult(ctx, a, risk.CounterCommitted, snapshotFor(c)); err == nil {
			t.Fatal("negative/unknown became committed")
		}
		var n int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_snapshots WHERE sequence=$1`, a.state.sequence).Scan(&n); err != nil || n != 0 {
			t.Fatal("negative outcome contains snapshots", err)
		}
	}
	c := prepare("conflicting-results", subject, risk.BeforeCredential)
	a, err := j.RecordAttempt(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := snapshotFor(c)
	var failures [2]error
	var wg sync.WaitGroup
	for i := range failures {
		wg.Add(1)
		go func() {
			defer wg.Done()
			values := append([]risk.Counter(nil), snapshot...)
			values[0].Value = uint64(i)
			failures[i] = j.RecordResult(ctx, a, risk.CounterCommitted, values)
		}()
	}
	wg.Wait()
	if (failures[0] == nil) == (failures[1] == nil) {
		t.Fatal("conflicting declarations did not produce one winner")
	}
	foreign, _ := NewVelocityJournal(cfg)
	if err := foreign.RecordResult(ctx, a, risk.CounterUnknown, nil); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("foreign receipt owner admitted", err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION risk_store.reject_velocity_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.dimension='canonical_network' THEN RAISE EXCEPTION 'synthetic failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_velocity_snapshot BEFORE INSERT ON risk_store.velocity_snapshots FOR EACH ROW EXECUTE FUNCTION risk_store.reject_velocity_snapshot()`); err != nil {
		t.Fatal(err)
	}
	c = prepare("failed-result", subject, risk.BeforeCredential)
	a, err = j.RecordAttempt(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordResult(ctx, a, risk.CounterCommitted, snapshotFor(c)); err == nil {
		t.Fatal("partial completion allowed")
	}
	var state string
	var count int
	if err := pool.Raw().QueryRow(ctx, `SELECT outcome FROM risk_store.velocity_attempts WHERE sequence=$1`, a.state.sequence).Scan(&state); err != nil || state != "pending" {
		t.Fatal("failed result changed outcome", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_snapshots WHERE sequence=$1`, a.state.sequence).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial snapshots survived", err)
	}
	var unavailable identity.UnavailableError
	if _, err := j.ReadResult(ctx, c); !errors.As(err, &unavailable) {
		t.Fatal("pending result became readable", err)
	}
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_velocity_snapshot ON risk_store.velocity_snapshots; DROP FUNCTION risk_store.reject_velocity_snapshot()`); err != nil {
		t.Fatal(err)
	}
	// Drop only an actual PostgreSQL successful COMMIT acknowledgement. The
	// existing bounded socket fault never fabricates a database outcome.
	faultPool, fault := newCommitAckPool(t, ctx, dsn, databaseName, nil)
	faultConfig := cfg
	faultConfig.Pool = faultPool
	faultJournal, err := NewVelocityJournal(faultConfig)
	if err != nil {
		t.Fatal(err)
	}
	c = prepare("lost-result-ack", subject, risk.BeforeCredential)
	a, err = faultJournal.RecordAttempt(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	fault.velocitySequence.Store(a.state.sequence)
	if err := faultJournal.RecordResult(ctx, a, risk.CounterCommitted, snapshotFor(c)); !errors.As(err, &unavailable) || fault.hits.Load() != 1 {
		t.Fatal("lost commit ack asserted success/noncommit", err)
	}
	if _, err := j.ReadResult(ctx, c); err != nil {
		t.Fatal("primary could not resolve complete terminal history", err)
	}
	if _, err := j.RecordAttempt(ctx, c); err == nil {
		t.Fatal("ambiguous acknowledgement permitted redispatch")
	}
}
