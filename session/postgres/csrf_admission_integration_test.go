//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Every protected effect and its admission use the same real transaction;
// verification uses a separate connection after that owner commits or aborts.
func testCSRFFencedMutation(t *testing.T, ctx context.Context, pool *database.Pool, original session.Session) {
	t.Helper()
	base, _ := original.Bindings()
	base.Version = 3
	vector, _ := base.Authority.Bindings()
	vector.Session.Version = base.Version
	base.Authority, _ = session.NewAuthoritySnapshot(vector)
	now := time.Now().UTC()
	base.IssuedAt, base.LastActivityAt = now, now
	base.Authentication.Proof.IssuedAt, base.Authentication.Proof.ExpiresAt = now.Add(-time.Minute), now.Add(time.Minute)
	legacy, err := session.NewSession(base)
	if err != nil {
		t.Fatal(err)
	}
	record, token, key := csrfAdmissionFixture(t, legacy)
	payload, expiry, _ := encodeRecord(record)
	oldPayload, oldExpiry, _ := encodeRecord(original)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.csrf_effects(id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := pool.Raw().Exec(cleanup, `UPDATE session_store.families SET state='active' WHERE tenant_id='tenant-a'`); err != nil {
			t.Error(err)
		}
		if _, err := pool.Raw().Exec(cleanup, `UPDATE session_store.sessions SET state='active',version=$1::numeric,record=$2::jsonb,expires_at=$3 WHERE tenant_id='tenant-a' AND session_id='session-a'`, "18446744073709551615", oldPayload, oldExpiry); err != nil {
			t.Error(err)
		}
		if _, err := pool.Raw().Exec(cleanup, `DROP TABLE public.csrf_effects`); err != nil {
			t.Error(err)
		}
	})
	reset := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.families SET state='active' WHERE tenant_id='tenant-a'`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='active',version=3,record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, payload, expiry); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{Schema: "session_store", MaximumDuration: time.Second}
	assertEffect := func(t *testing.T, id string, expected int) {
		t.Helper()
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.csrf_effects WHERE id=$1`, id).Scan(&count); err != nil || count != expected {
			t.Fatal("unexpected committed protected effect", id, count, err)
		}
	}
	wrongToken, _ := session.NewCSRFToken()
	wrongMaterial, _ := session.NewCSRFKey(7, bytes.Repeat([]byte{2}, 32))
	wrongVersion, _ := session.NewCSRFKey(8, bytes.Repeat([]byte{1}, 32))
	for _, candidate := range []struct {
		name  string
		token session.CSRFToken
		key   session.CSRFKey
	}{
		{"wrong-token", wrongToken, key}, {"wrong-material", token, wrongMaterial},
		{"wrong-version", token, wrongVersion}, {"absent-token", session.CSRFToken{}, key},
		{"absent-key", token, session.CSRFKey{}}, {"correct", token, key},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			reset(t)
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			// Stage before admission to prove denial rolls back existing work too.
			if _, err := tx.Exec(ctx, `INSERT INTO public.csrf_effects VALUES($1)`, candidate.name); err != nil {
				t.Fatal(err)
			}
			err = RequireCSRF(ctx, tx, cfg, record, candidate.token, candidate.key)
			if candidate.name == "correct" {
				if err != nil {
					t.Fatal("current primary token denied", err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				assertEffect(t, candidate.name, 1)
			} else {
				var denied identity.ForbiddenError
				if !errors.As(err, &denied) {
					t.Fatal("wrong token/key not uniformly denied", err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				assertEffect(t, candidate.name, 0)
			}
		})
	}
	for _, table := range []string{"sessions", "families"} {
		t.Run(table+"-blocked-budget", func(t *testing.T) {
			reset(t)
			invalidator, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer invalidator.Rollback(ctx)
			if _, err := invalidator.Exec(ctx, `UPDATE session_store.`+table+` SET state='revoked' WHERE tenant_id='tenant-a'`); err != nil {
				t.Fatal(err)
			}
			budget := cfg
			budget.MaximumDuration = 150 * time.Millisecond
			run := startCSRFProtectedWrite(t, ctx, pool, budget, record, token, key, table+"-timeout")
			waitCSRFBlocked(t, ctx, invalidator, run.pid)
			var deadline identity.DeadlineExceededError
			if err := run.wait(ctx); !errors.As(err, &deadline) {
				t.Fatal("blocked check did not honor finite budget", err)
			}
			if err := invalidator.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			assertEffect(t, table+"-timeout", 0)
			fresh := startCSRFProtectedWrite(t, ctx, pool, cfg, record, token, key, table+"-timeout-released")
			if err := fresh.wait(ctx); err != nil {
				t.Fatal("timeout retained a fence", err)
			}
			assertEffect(t, table+"-timeout-released", 1)
		})
		t.Run(table+"-invalidation-wins", func(t *testing.T) {
			reset(t)
			invalidator, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer invalidator.Rollback(ctx)
			if _, err := invalidator.Exec(ctx, `UPDATE session_store.`+table+` SET state='revoked' WHERE tenant_id='tenant-a'`); err != nil {
				t.Fatal(err)
			}
			run := startCSRFProtectedWrite(t, ctx, pool, cfg, record, token, key, table+"-lost")
			waitCSRFBlocked(t, ctx, invalidator, run.pid)
			if err := invalidator.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var denied identity.ForbiddenError
			if err := run.wait(ctx); !errors.As(err, &denied) {
				t.Fatal("committed invalidation was bypassed", err)
			}
			assertEffect(t, table+"-lost", 0)
		})
		t.Run(table+"-protected-work-wins", func(t *testing.T) {
			reset(t)
			protected, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer protected.Rollback(ctx)
			if err := RequireCSRF(ctx, protected, cfg, record, token, key); err != nil {
				t.Fatal(err)
			}
			if _, err := protected.Exec(ctx, `INSERT INTO public.csrf_effects VALUES($1)`, table+"-first"); err != nil {
				t.Fatal(err)
			}
			invalidator, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer invalidator.Rollback(ctx)
			if _, err := invalidator.Exec(ctx, `SET LOCAL lock_timeout='75ms'`); err != nil {
				t.Fatal(err)
			}
			_, err = invalidator.Exec(ctx, `UPDATE session_store.`+table+` SET state='revoked' WHERE tenant_id='tenant-a'`)
			var lock *pgconn.PgError
			if !errors.As(err, &lock) || lock.Code != "55P03" {
				invalidator.Rollback(ctx)
				t.Fatal("invalidation did not wait for protected transaction", err)
			}
			if err := invalidator.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err := protected.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.`+table+` SET state='revoked' WHERE tenant_id='tenant-a'`); err != nil {
				t.Fatal(err)
			}
			assertEffect(t, table+"-first", 1)
			after := startCSRFProtectedWrite(t, ctx, pool, cfg, record, token, key, table+"-after")
			var denied identity.ForbiddenError
			if err := after.wait(ctx); !errors.As(err, &denied) {
				t.Fatal("post-invalidation token admitted", err)
			}
			assertEffect(t, table+"-after", 0)
		})
	}
	for _, change := range []string{"missing", "tokenless", "replacement", "new-version", "expired"} {
		t.Run(change+"-primary-state", func(t *testing.T) {
			reset(t)
			expected := record
			switch change {
			case "missing":
				// Use a valid token binding for an absent session below.
			case "tokenless", "replacement", "new-version", "expired":
				changed := legacy
				spec := base
				if change == "replacement" {
					changed = withCSRFState(t, record, 9)
				}
				if change == "new-version" {
					spec.Version++
					v, _ := spec.Authority.Bindings()
					v.Session.Version = spec.Version
					spec.Authority, err = session.NewAuthoritySnapshot(v)
					if err != nil {
						t.Fatal(err)
					}
					changed, err = session.NewSession(spec)
					if err != nil {
						t.Fatal(err)
					}
				}
				if change == "expired" {
					spec.IssuedAt, spec.LastActivityAt = now.Add(-2*time.Hour), now.Add(-2*time.Hour)
					spec.Authentication.Proof.IssuedAt, spec.Authentication.Proof.ExpiresAt = spec.IssuedAt.Add(-time.Minute), spec.IssuedAt.Add(time.Minute)
					changed, err = session.NewSessionWithCSRF(spec, record.CSRFState())
					if err != nil {
						t.Fatal(err)
					}
					expected = changed
				}
				encoded, deadline, err := encodeRecord(changed)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := changed.Bindings()
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET version=$1,record=$2::jsonb,expires_at=$3 WHERE tenant_id='tenant-a' AND session_id='session-a'`, b.Version, encoded, deadline); err != nil {
					t.Fatal(err)
				}
			}
			if change == "missing" {
				spec := base
				spec.SessionID = "absent-session"
				v, _ := spec.Authority.Bindings()
				v.Session.ScopeKey = "session:tenant-a:absent-session"
				spec.Authority, err = session.NewAuthoritySnapshot(v)
				if err != nil {
					t.Fatal(err)
				}
				state, err := token.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
				if err != nil {
					t.Fatal(err)
				}
				expected, err = session.NewSessionWithCSRF(spec, state)
				if err != nil {
					t.Fatal(err)
				}
			}
			run := startCSRFProtectedWrite(t, ctx, pool, cfg, expected, token, key, change+"-primary")
			var denied identity.ForbiddenError
			if err := run.wait(ctx); !errors.As(err, &denied) {
				t.Fatal("changed primary state admitted", err)
			}
			assertEffect(t, change+"-primary", 0)
		})
	}
}

type csrfProtectedRun struct {
	pid    int
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

func (r *csrfProtectedRun) wait(ctx context.Context) error {
	select {
	case <-r.done:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func startCSRFProtectedWrite(t *testing.T, ctx context.Context, pool *database.Pool, cfg Config, record session.Session, token session.CSRFToken, key session.CSRFKey, id string) *csrfProtectedRun {
	t.Helper()
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := &csrfProtectedRun{done: make(chan struct{})}
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&r.pid); err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	call, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	go func() {
		defer close(r.done)
		r.err = RequireCSRF(call, tx, cfg, record, token, key)
		if r.err == nil {
			_, r.err = tx.Exec(call, `INSERT INTO public.csrf_effects VALUES($1)`, id)
		}
		if r.err == nil {
			r.err = tx.Commit(call)
		}
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) && r.err == nil {
			r.err = err
		}
	}()
	t.Cleanup(func() {
		r.cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		select {
		case <-r.done:
		case <-cleanup.Done():
			t.Error("protected mutation goroutine did not terminate")
		}
	})
	return r
}

func waitCSRFBlocked(t *testing.T, ctx context.Context, observer pgx.Tx, pid int) {
	t.Helper()
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := observer.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ticker.C:
		case <-bounded.Done():
			t.Fatal("protected admission never reached the invalidation lock")
		}
	}
}
