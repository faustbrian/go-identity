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
)

// The shared real migration harness supplies populated legacy rows. This
// transaction rolls back every projection change, retaining those original rows.
func testCSRFPrimaryRecord(t *testing.T, ctx context.Context, pool *database.Pool, original session.Session) {
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	base, _ := original.Bindings()
	now := time.Now().UTC()
	base.IssuedAt, base.LastActivityAt = now, now
	base.Authentication.Proof.IssuedAt, base.Authentication.Proof.ExpiresAt = now.Add(-time.Minute), now.Add(time.Minute)
	legacy, err := session.NewSession(base)
	if err != nil {
		t.Fatal(err)
	}
	expected := withCSRFState(t, legacy, 9)
	payload, expiry, err := encodeRecord(expected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, payload, expiry); err != nil {
		t.Fatal("native CSRF record cannot persist", err)
	}
	cfg := Config{Schema: "session_store", MaximumDuration: time.Second}
	if err := RequireSession(ctx, tx, cfg, expected); err != nil {
		t.Fatal("exact current primary CSRF record denied", err)
	}
	for _, stale := range []session.Session{legacy, withCSRFState(t, legacy, 10)} {
		var denied identity.ForbiddenError
		if err := RequireSession(ctx, tx, cfg, stale); !errors.As(err, &denied) {
			t.Fatal("stripped/substituted state admitted", err)
		}
	}
}
