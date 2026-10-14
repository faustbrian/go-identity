//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// Bounded plan: the native owner must deny changed records, revocation and
// expiry, and keep both share locks until the original transaction closes.
// This tests its borrowed primary SQL, not complete bearer authentication.
func testSessionAdmission(t *testing.T, ctx context.Context, pool *database.Pool, original session.Session) {
	t.Helper()
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	spec, _ := original.Bindings()
	now := time.Now().UTC()
	spec.IssuedAt, spec.LastActivityAt = now, now
	spec.Authentication.Proof.IssuedAt = now.Add(-time.Minute)
	spec.Authentication.Proof.ExpiresAt = now.Add(time.Minute)
	expected, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	payload, expiry, err := encodeRecord(expected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, payload, expiry); err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	if err := RequireSession(ctx, tx, config, expected); err != nil {
		t.Fatal("active exact record denied", err)
	}
	for _, mutate := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.TenantID = "tenant-b"; s.Authentication.Proof.Tenant = "tenant-b" },
		func(s *session.SessionSpec) { s.UserID = "other"; s.Authentication.Proof.Subject = "other" },
		func(s *session.SessionSpec) { s.Audience = "other"; s.Authentication.Proof.Audience = "other" },
		func(s *session.SessionSpec) { s.Authentication.CredentialVersion-- },
		func(s *session.SessionSpec) { s.Authentication.Proof.ID = "zyxwvutsrqponmlkjihgfe" },
		func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.Authorization.Version--
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
		func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.Passkey = session.OptionalAuthorityBinding{}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
	} {
		changed := spec
		mutate(&changed)
		other, e := session.NewSession(changed)
		if e != nil {
			t.Fatal("invalid test input", e)
		}
		var denied identity.ForbiddenError
		if e = RequireSession(ctx, tx, config, other); !errors.As(e, &denied) {
			t.Fatal("changed record admitted", e)
		}
	}
	// Future, regressed and exhausted current epochs are never adopted into
	// the immutable session. The full uint64 maximum matches only itself.
	if _, err = tx.Exec(ctx, `UPDATE session_store.families SET version=version-1 WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	var stale identity.ForbiddenError
	if e := RequireSession(ctx, tx, config, expected); !errors.As(e, &stale) {
		t.Fatal("stale family admitted", e)
	}
	if _, err = tx.Exec(ctx, `UPDATE session_store.families SET version=version+1 WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"sessions", "families"} {
		if _, err = tx.Exec(ctx, `UPDATE session_store.`+table+` SET state='revoked' WHERE tenant_id='tenant-a'`); err != nil {
			t.Fatal(err)
		}
		var denied identity.ForbiddenError
		if e := RequireSession(ctx, tx, config, expected); !errors.As(e, &denied) {
			t.Fatal("revoked admitted", table, e)
		}
		if _, err = tx.Exec(ctx, `UPDATE session_store.`+table+` SET state='active' WHERE tenant_id='tenant-a'`); err != nil {
			t.Fatal(err)
		}
	}
	// Once rolled back, the active original record is readable by another
	// transaction. Check share locking independently of our preceding writes.
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	check, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Rollback(ctx)
	// Create deterministic idle expiry relative to this run, independently of
	// the historical fixture's calendar date.
	expiredSpec := spec
	expiredSpec.IssuedAt, expiredSpec.LastActivityAt = now.Add(-2*time.Hour), now.Add(-2*time.Hour)
	expiredSpec.Authentication.Proof.IssuedAt = now.Add(-2*time.Hour - time.Minute)
	expiredSpec.Authentication.Proof.ExpiresAt = now.Add(-2*time.Hour + time.Minute)
	expired, e := session.NewSession(expiredSpec)
	if e != nil {
		t.Fatal(e)
	}
	expiredPayload, expiredExpiry, _ := encodeRecord(expired)
	if _, e = check.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, expiredPayload, expiredExpiry); e != nil {
		t.Fatal(e)
	}
	var denied identity.ForbiddenError
	if e := RequireSession(ctx, check, config, expired); !errors.As(e, &denied) {
		t.Fatal("expired fixture admitted", e)
	}
	if err = check.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// Install the live fixture durably inside this task-owned database for lock
	// checks, then restore its exact original projection before returning.
	oldPayload, oldExpiry, _ := encodeRecord(original)
	if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, payload, expiry); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, e := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, oldPayload, oldExpiry); e != nil {
			t.Error(e)
		}
	}()
	lock, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(ctx)
	if err = RequireSession(ctx, lock, config, expected); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"sessions", "families"} {
		// An autocommit statement can complete server-side after the client
		// times out and the blocking lock is released. Own the writer's
		// transaction so this lock probe can never persist revocation.
		writer, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		blocked, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		_, e = writer.Exec(blocked, `UPDATE session_store.`+table+` SET state='revoked' WHERE tenant_id='tenant-a'`)
		cancel()
		connection := writer.Conn()
		if cleanup := writer.Rollback(ctx); cleanup != nil && !connection.IsClosed() {
			t.Fatal("lock probe transaction cleanup")
		}
		if e == nil || !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal("share lock absent", table, e)
		}
	}
	if err = lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"sessions", "families"} {
		after, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, e = after.Exec(ctx, `UPDATE session_store.`+table+` SET state='revoked' WHERE tenant_id='tenant-a'`)
		after.Rollback(ctx)
		if e != nil {
			t.Fatal("lock retained after closure", e)
		}
	}
	var nilTx pgx.Tx
	if err = RequireSession(ctx, nilTx, config, expected); err == nil {
		t.Fatal("nil transaction admitted")
	}
}
