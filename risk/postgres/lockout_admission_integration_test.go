//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// Seed authoritative restrictions only in the disposable database. Production
// start/end commands must use the original coordinator and are separate work;
// this fixture does not claim their authorization, audit or recovery behavior.
func testDurableLockoutAdmission(t *testing.T, ctx context.Context, pool *database.Pool,
	prepare func(*Repository, string, ...time.Time) (*identitypostgres.Coordinator, identity.CommandBinding, identity.Command, identitypostgres.CommandPlan),
	old, newer risk.CounterDigestKey) {
	t.Helper()
	history, err := (LockoutMigrationSource{Base: CounterMigrationSource{Base: ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}, Version: 22}, Version: 23}, Version: 24}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"active", "expired", "future-start", "older-policy", "foreign-tenant", "foreign-operation", "retained-key-rotation", "window-reset", "missing-schema"} {
		t.Run(mode, func(t *testing.T) {
			tenant := "lockout-" + mode
			cfg := protectedConfig(t, old)
			cfg.EnforceLockouts = true
			r, err := NewRepository(cfg)
			if err != nil {
				t.Fatal(err)
			}
			coord, b, command, plan := prepare(r, tenant)
			reservation, result, err := coord.ReserveCommand(ctx, b, command, plan)
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("reserve", err)
			}
			start := "clock_timestamp()-interval '1 second'"
			end := "clock_timestamp()+interval '1 hour'"
			if mode == "expired" {
				start = "clock_timestamp()-interval '2 hours'"
				end = "clock_timestamp()-interval '1 hour'"
			}
			if mode == "future-start" {
				start = "clock_timestamp()+interval '1 minute'"
			}
			if mode != "missing-schema" {
				// Install after preparation/reservation: old positive allowance is
				// insufficient. Even a clean counter snapshot cannot erase this row.
				_, err = pool.Raw().Exec(ctx, `INSERT INTO risk_store.counter_lockouts(tenant_id,operation,dimension,counter_id,version,policy_version,started_at,expires_at) SELECT tenant_id,operation,dimension,counter_id,1,3,`+start+`,`+end+` FROM risk_store.counter_windows WHERE tenant_id=$1 AND dimension='subject'`, tenant)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "foreign-tenant" {
				// Foreign restrictions stay durable; only their separate scope is
				// selected for the control command, never an unkeyed caller alias.
				other := tenant + "-control"
				coord, b, command, plan = prepare(r, other)
				reservation, _, err = coord.ReserveCommand(ctx, b, command, plan)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "foreign-operation" {
				// A separate operation with an identical stored root spelling
				// cannot contaminate the original operation. This hostile fixture
				// exercises composite SQL scope, not genuine key derivation.
				if _, err = pool.Raw().Exec(ctx, `INSERT INTO risk_store.counter_windows SELECT tenant_id,'identity.email.change',dimension,counter_id,value,window_us,started_at,expires_at FROM risk_store.counter_windows WHERE tenant_id=$1 AND dimension='subject'`, tenant); err != nil {
					t.Fatal(err)
				}
				if _, err = pool.Raw().Exec(ctx, `UPDATE risk_store.counter_lockouts SET operation='identity.email.change' WHERE tenant_id=$1`, tenant); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "older-policy" {
				if _, err = pool.Raw().Exec(ctx, `UPDATE risk_store.counter_lockouts SET policy_version=2 WHERE tenant_id=$1`, tenant); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "window-reset" {
				if _, err = pool.Raw().Exec(ctx, `UPDATE risk_store.counter_windows SET started_at=started_at-interval '15 minutes',expires_at=expires_at-interval '15 minutes' WHERE tenant_id=$1`, tenant); err != nil {
					t.Fatal(err)
				}
				coord, b, command, plan = prepare(r, tenant)
				reservation, _, err = coord.ReserveCommand(ctx, b, command, plan)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "retained-key-rotation" {
				cfg = protectedConfig(t, newer, old)
				cfg.EnforceLockouts = true
				r, err = NewRepository(cfg)
				if err != nil {
					t.Fatal(err)
				}
				coord, b, command, plan = prepare(r, tenant)
				reservation, _, err = coord.ReserveCommand(ctx, b, command, plan)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "missing-schema" {
				if _, err = pool.Raw().Exec(ctx, `ALTER TABLE risk_store.counter_lockouts RENAME TO hidden_lockouts`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE risk_store.hidden_lockouts RENAME TO counter_lockouts`); e != nil {
						t.Error(e)
					}
				}()
			}
			w, err := coord.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coord.Abort(w, identity.UnavailableError{})
			result, err = coord.ApplyFeature(ctx, w, command)
			allowed := mode == "expired" || mode == "foreign-tenant" || mode == "foreign-operation"
			if allowed {
				if err != nil {
					t.Fatal("inactive/foreign restriction denied", err)
				}
				result, err = coord.Commit(w, result)
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("control commit", err)
				}
			} else {
				if err == nil {
					t.Fatal("active or unavailable durable lockout allowed domain mutation")
				}
				if mode != "missing-schema" {
					var denied identity.ForbiddenError
					if !errors.As(err, &denied) {
						t.Fatal("lockout leaked classification", err)
					}
				}
				result, _ = coord.Abort(w, err)
				if result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("lockout denial lost rollback", result.Outcome)
				}
			}
			var effects, charges int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.native_counter_effect WHERE command_id=$1),(SELECT count(*) FROM risk_store.counter_charges WHERE tenant_id=$2)`, string(b.CommandID), string(b.TenantID)).Scan(&effects, &charges); err != nil || charges < 1 || effects != boolCount(allowed) {
				t.Fatal("protected effects/charges", err, effects, charges)
			}
		})
	}
	t.Run("restriction-writes-cannot-cross-admission", func(t *testing.T) {
		for _, existing := range []bool{false, true} {
			tenant := "lockout-write-insert"
			if existing {
				tenant = "lockout-write-update"
			}
			cfg := protectedConfig(t, old)
			cfg.EnforceLockouts = true
			r, err := NewRepository(cfg)
			if err != nil {
				t.Fatal(err)
			}
			coord, b, command, plan := prepare(r, tenant)
			reservation, _, err := coord.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			insert := `INSERT INTO risk_store.counter_lockouts(tenant_id,operation,dimension,counter_id,version,policy_version,started_at,expires_at) SELECT tenant_id,operation,dimension,counter_id,1,3,clock_timestamp()-interval '1 second',clock_timestamp()+interval '1 hour' FROM risk_store.counter_windows WHERE tenant_id=$1 AND dimension='subject'`
			if existing {
				if _, err = pool.Raw().Exec(ctx, `INSERT INTO risk_store.counter_lockouts(tenant_id,operation,dimension,counter_id,version,policy_version,started_at,expires_at) SELECT tenant_id,operation,dimension,counter_id,1,3,clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour' FROM risk_store.counter_windows WHERE tenant_id=$1 AND dimension='subject'`, tenant); err != nil {
					t.Fatal(err)
				}
			}
			w, err := coord.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coord.Abort(w, identity.UnavailableError{})
			result, err := coord.ApplyFeature(ctx, w, command)
			if err != nil {
				t.Fatal(err)
			}
			statement := insert
			if existing {
				statement = `UPDATE risk_store.counter_lockouts SET version=version+1,started_at=clock_timestamp()-interval '1 second',expires_at=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1`
			}
			// Separate connection, bounded synchronous statement: absence is
			// fenced by the counter FK; retained rows by the admission SHARE lock.
			blocked, stop := context.WithTimeout(ctx, 100*time.Millisecond)
			_, writeErr := pool.Raw().Exec(blocked, statement, tenant)
			stop()
			if !errors.Is(writeErr, context.DeadlineExceeded) {
				t.Fatal("restriction changed under admitted transaction", writeErr)
			}
			result, err = coord.Commit(w, result)
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original admitted commit", err)
			}
			var count int
			if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.counter_lockouts WHERE tenant_id=$1 AND expires_at>clock_timestamp()`, tenant).Scan(&count); err != nil || count != 0 {
				t.Fatal("cancelled write leaked restriction", err, count)
			}
			if _, err = pool.Raw().Exec(ctx, statement, tenant); err != nil {
				t.Fatal("write after commit", err)
			}
			coord, b, command, plan = prepare(r, tenant)
			reservation, _, err = coord.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			w, err = coord.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coord.Abort(w, identity.UnavailableError{})
			_, err = coord.ApplyFeature(ctx, w, command)
			var denied identity.ForbiddenError
			if !errors.As(err, &denied) {
				t.Fatal("next command missed committed restriction", err)
			}
			aborted, abortErr := coord.Abort(w, err)
			if aborted.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(abortErr, &denied) {
				t.Fatal("abort denied command", abortErr, aborted.Outcome)
			}
		}
	})
	t.Run("populated-state-upgrade", func(t *testing.T) {
		testLockoutStatePopulatedUpgrade(t, ctx, pool)
	})
	t.Run("native-transitions", func(t *testing.T) {
		testNativeLockoutTransitions(t, ctx, pool, prepare)
	})
}

func boolCount(b bool) int {
	if b {
		return 1
	}
	return 0
}
