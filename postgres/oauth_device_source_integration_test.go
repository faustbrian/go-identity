//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Real owner-level Work/SQL proof using the existing isolated database and
// migrations, not fabricated authenticated sessions or a complete device flow.
func TestOAuthDeviceGrantSourcePostgres(t *testing.T) {
	ctx, pool, _ := anonymousKernelDatabase(t)
	migration, err := authority.AuthoritySchemaMigration(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, migration.Up); err != nil {
		t.Fatal(err)
	}
	testOAuthDeviceGrantSource(t, ctx, pool)
}

func testOAuthDeviceGrantSource(t *testing.T, ctx context.Context, pool *database.Pool) {
	_, _, c, a := deviceSourceWork(t, "apply")
	a.Version = 1
	for _, statement := range []string{
		`INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES($1,$2,'active',1,11,13,17)`,
		`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password-source',1,'identity/password',7,true)`,
	} {
		if _, err := pool.Raw().Exec(ctx, statement, string(c.Credential.TenantID), string(c.Credential.UserID)); err != nil {
			t.Fatal("source credential fixture", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.device_source_effect(attempt text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	setup, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorizationFixture(setup)
	if _, err := authority.InitializeAuthority(ctx, setup, a.Scope, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := setup.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, stage, change string
		allowed             bool
	}{
		{"prepare", "prepare", "", true},
		{"apply", "apply", "", true},
		{"final", "final", "", true},
		{"blocked", "apply", `UPDATE identity.users SET status='suspended' WHERE user_id='human-source'`, false},
		{"user epoch", "apply", `UPDATE identity.users SET authority_version=12 WHERE user_id='human-source'`, false},
		{"identifier epoch", "apply", `UPDATE identity.users SET identifier_version=14 WHERE user_id='human-source'`, false},
		{"credential epoch", "apply", `UPDATE identity.users SET credential_version=18 WHERE user_id='human-source'`, false},
		{"credential version", "apply", `UPDATE identity.credential_references SET version=8 WHERE user_id='human-source'`, false},
		{"credential disabled", "apply", `UPDATE identity.credential_references SET enabled=false WHERE user_id='human-source'`, false},
		{"credential expired", "final", `UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE user_id='human-source'`, false},
		{"authorization epoch", "final", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackAuthorizationFixture(tx)
			w, owner, c, expected := deviceSourceWork(t, tc.stage)
			expected.Version = 1
			w.state.ctx, w.state.tx = ctx, tx
			original := w.state.binding
			if tc.change != "" {
				if _, err := tx.Exec(ctx, tc.change); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "authorization epoch" {
				if _, err := authority.AdvanceAuthority(ctx, tx, expected.Scope, 1, time.Second); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := w.Exec(ctx, `INSERT INTO public.device_source_effect(attempt) VALUES($1)`, tc.name); err != nil {
				t.Fatal(err)
			}
			at, err := w.RequireOAuthDeviceGrantSource(ctx, owner, c, expected)
			if tc.allowed {
				if err != nil || at.IsZero() || w.state.binding != original || w.usable() != nil {
					t.Fatal("exact source not fenced without client relabeling", err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				var denied identity.ForbiddenError
				if !errors.As(err, &denied) || !at.IsZero() || w.usable() == nil || w.state.binding != original {
					t.Fatal("withdrawn source left usable Work", err)
				}
				if _, err := w.Exec(ctx, `INSERT INTO public.device_source_effect(attempt) VALUES('ignored-denial')`); err == nil {
					t.Fatal("ignored source denial permitted later work")
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			}
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.device_source_effect WHERE attempt=$1`, tc.name).Scan(&count); err != nil || (count == 1) != tc.allowed {
				t.Fatal("source check lost committed/rollback distinction", err)
			}
		})
	}
	t.Run("credential expires during authorization lock wait", func(t *testing.T) {
		bounded, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		if _, err := pool.Raw().Exec(bounded, `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '2 seconds' WHERE user_id='human-source'`); err != nil {
			t.Fatal(err)
		}
		blocker, err := pool.Raw().Begin(bounded)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackAuthorizationFixture(blocker)
		if _, err := blocker.Exec(bounded, `SELECT subject_id FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace=$2 AND subject_id=$3 FOR UPDATE`, string(a.Scope.TenantID), a.Scope.PolicyNamespace, string(a.Scope.SubjectID)); err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Raw().Begin(bounded)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackAuthorizationFixture(tx)
		var pid int
		if err := tx.QueryRow(bounded, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		w, owner, c, expected := deviceSourceWork(t, "final")
		expected.Version = 1
		w.state.ctx, w.state.tx = bounded, tx
		done := make(chan struct{})
		var at time.Time
		var admissionErr error
		go func() {
			defer close(done)
			at, admissionErr = w.RequireOAuthDeviceGrantSource(bounded, owner, c, expected)
		}()
		// The worker exclusively owns Work/tx until done. Join before rollback,
		// including failures, so this timing test cannot leave a live goroutine.
		defer func() { cancel(); <-done }()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var blocked bool
			if err := pool.Raw().QueryRow(bounded, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			select {
			case <-done:
				t.Fatal("source admission did not reach authorization lock", admissionErr)
			case <-bounded.Done():
				t.Fatal("authorization lock wait not observed")
			case <-ticker.C:
			}
		}
		// Use the primary's own clock: release the observed authorization lock
		// only after the already-read credential has actually expired.
		if _, err := pool.Raw().Exec(bounded, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM (expires_at-clock_timestamp())))+0.02) FROM identity.credential_references WHERE user_id='human-source'`); err != nil {
			t.Fatal(err)
		}
		if err := blocker.Commit(bounded); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-bounded.Done():
			t.Fatal("source admission did not finish")
		}
		var denied identity.ForbiddenError
		if !errors.As(admissionErr, &denied) || !at.IsZero() || w.usable() == nil {
			t.Fatal("authorization wait extended expired credential authority", admissionErr)
		}
	})
}
