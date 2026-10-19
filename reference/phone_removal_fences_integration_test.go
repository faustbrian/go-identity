//go:build integration

package reference_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/reference"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type phoneRemovalFenceTrace struct{ hit atomic.Bool }

func newPhoneRemovalFencePool(t *testing.T, ctx context.Context, original *database.Pool) (*database.Pool, *phoneRemovalFenceTrace) {
	t.Helper()
	trace := &phoneRemovalFenceTrace{}
	pool, err := database.Connect(ctx, database.Config{DSN: original.Raw().Config().ConnConfig.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
			if n != nil && n.Message == "identity-test-phone-removal-fence" {
				trace.hit.Store(true)
			}
		}
		return nil
	}})
	if err != nil {
		t.Fatal("phone removal trace pool", err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(ctx); err != nil {
			t.Error("phone removal trace cleanup", err)
		}
	})
	return pool, trace
}

func TestReferencePostgresPhoneRemovalFinalFences(t *testing.T) {
	for _, mode := range []string{"mfa", "credential", "account", "session", "recovery", "late-write", "risk-outage"} {
		t.Run(mode, func(t *testing.T) {
			// Each original protected attempt has its own real account/budget.
			// Do not refill counters to squeeze unrelated denials into one user.
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneOTP: "browser", phoneRemoval: "fence-" + mode}, true)
		})
	}
}

// Negative injections run only in this test's disposable database. They can
// withdraw authority or fail a write, never manufacture successful authority.
// The last cascade-consumer insert is after the actual directory/proof/notice
// writes; final admission must detect withdrawals and roll all those effects
// back. No production trigger or migration is added by this test.
func provePhoneRemovalFinalFence(t *testing.T, ctx context.Context, f liveStores, owner *reference.PhoneRemovalService, original phone.RemoveRequest, snapshot func() [10]uint64, before [10]uint64, cookies []*http.Cookie, readSession func([]*http.Cookie) bool, counterSchema, selected string) {
	t.Helper()
	if selected == "risk-outage" {
		spec, err := original.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		spec.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("phone-removal-risk-outage"))
		if err != nil {
			t.Fatal(err)
		}
		request, err := phone.NewRemoveRequest(spec)
		if err != nil {
			t.Fatal(err)
		}
		schema := pgx.Identifier{counterSchema}.Sanitize()
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE `+schema+`.counter_lockouts RENAME TO unavailable_phone_lockouts`); err != nil {
			t.Fatal(err)
		}
		result, denied := owner.Remove(ctx, request)
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE `+schema+`.unavailable_phone_lockouts RENAME TO counter_lockouts`); err != nil {
			t.Fatal("phone risk outage cleanup", err)
		}
		if denied == nil || result.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || !readSession(cookies) {
			t.Fatal("unavailable protected risk authority allowed removal", denied)
		}
		return
	}
	subject := `(SELECT user_id FROM identity.status_cascades WHERE tenant_id=NEW.tenant_id AND cascade_id=NEW.cascade_id)`
	for _, test := range []struct{ name, withdraw string }{
		{"mfa", `UPDATE identity_mfa.factor_authorities SET active_factors=1 WHERE tenant_id=NEW.tenant_id AND user_id=` + subject + `;`},
		{"credential", `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=NEW.tenant_id AND user_id=` + subject + ` AND kind=1;`},
		{"account", `UPDATE identity.users SET status='suspended' WHERE tenant_id=NEW.tenant_id AND user_id=` + subject + `;`},
		{"session", `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=NEW.tenant_id AND user_id=` + subject + `;`},
		{"recovery", `UPDATE identity.identifiers SET is_primary=false,verified=false,verification_state=1,verified_at=NULL WHERE tenant_id=NEW.tenant_id AND user_id=` + subject + ` AND kind='email';`},
		{"late-write", `RAISE EXCEPTION 'synthetic phone removal write failure';`},
	} {
		if test.name != selected {
			continue
		}
		t.Run(test.name, func(t *testing.T) {
			spec, err := original.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			spec.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("phone-removal-final-" + test.name))
			if err != nil {
				t.Fatal(err)
			}
			request, err := phone.NewRemoveRequest(spec)
			if err != nil {
				t.Fatal(err)
			}
			// All identifiers and SQL fragments above are fixed test inputs. This
			// invoker trigger has no dynamic SQL or access beyond the owned DB.
			_, err = f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.withdraw_phone_removal_authority() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.ordinal=9 THEN RAISE NOTICE 'identity-test-phone-removal-fence'; `+test.withdraw+` END IF; RETURN NEW; END $$;
CREATE TRIGGER withdraw_phone_removal_authority BEFORE INSERT ON identity.status_consumers FOR EACH ROW EXECUTE FUNCTION public.withdraw_phone_removal_authority()`)
			if err != nil {
				t.Fatal("phone final-fence injection", err)
			}
			result, denied := owner.Remove(ctx, request)
			if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER withdraw_phone_removal_authority ON identity.status_consumers; DROP FUNCTION public.withdraw_phone_removal_authority()`); err != nil {
				t.Fatal("phone final-fence cleanup", err)
			}
			if f.phoneRemovalTrace == nil || !f.phoneRemovalTrace.hit.Load() {
				t.Fatal("phone final-fence injection was never reached")
			}
			if denied == nil || result.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || !readSession(cookies) {
				t.Fatal("late authority withdrawal or write failure committed phone removal", test.name, result.Outcome, denied)
			}
			if test.name == "mfa" {
				provePhoneRemovalAuditAction(t, ctx, f, result)
			}
			var active bool
			var factors uint64
			if err := f.pool.Raw().QueryRow(ctx, `SELECT bool_and(c.enabled),a.active_factors FROM identity.credential_references c JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id) WHERE c.tenant_id=$1 AND c.user_id=$2 AND c.kind=1 GROUP BY a.active_factors`, string(spec.TenantID), string(spec.UserID)).Scan(&active, &factors); err != nil || !active || factors != 0 {
				t.Fatal("negative injection escaped rollback", test.name, err)
			}
		})
	}
}
