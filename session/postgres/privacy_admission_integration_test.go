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

// Real primary reads and session-owned locking/expiry. Full generation-bound
// privacy execution still requires native proof, all cuts and terminal effects.
func testPrivacySessionProjection(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	record, command, profile := privacySessionFixture(t)
	spec, _ := record.Bindings()
	now := time.Now().UTC()
	spec.IssuedAt, spec.LastActivityAt = now, now
	spec.Authentication.Proof.IssuedAt = now.Add(-time.Minute)
	spec.Authentication.Proof.ExpiresAt = now.Add(time.Minute)
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	payload, expiry, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE session_store.families SET version=$1::numeric WHERE tenant_id='tenant-a'`, spec.FamilyVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE session_store.sessions SET version=$1::numeric,family_version=$2::numeric,record=$3::jsonb,expires_at=$4 WHERE tenant_id='tenant-a'`, spec.Version, spec.FamilyVersion, payload, expiry); err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	repo, err := NewRepositoryWithPrivacyExportAdmission(pool, config, profile)
	if err != nil || repo.privacyAdmission == nil {
		t.Fatal("opt-in constructor", err)
	}
	profile.Audience = "changed"
	if repo.privacyAdmission.Audience != "service-a" {
		t.Fatal("profile alias")
	}
	got, err := readPrivacySession(ctx, tx, config, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := privacySessionBindings(*repo.privacyAdmission, got, command); err != nil {
		t.Fatal(err)
	}
	if err := RequireSession(ctx, tx, config, got); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*identity.PrivacyExportRequestCommand){
		func(c *identity.PrivacyExportRequestCommand) { c.Binding.TenantID = "tenant-b" },
		func(c *identity.PrivacyExportRequestCommand) { c.Binding.UserID = "other" },
		func(c *identity.PrivacyExportRequestCommand) { c.SessionID = "missing" },
		func(c *identity.PrivacyExportRequestCommand) { c.SessionVersion++ },
	} {
		other := command
		change(&other)
		var denied identity.ForbiddenError
		if _, err := readPrivacySession(ctx, tx, config, other); !errors.As(err, &denied) {
			t.Fatal("foreign/stale primary accepted", err)
		}
	}
	for _, query := range []string{
		`UPDATE session_store.sessions SET state='revoked' WHERE tenant_id='tenant-a'`,
		`UPDATE session_store.families SET state='revoked' WHERE tenant_id='tenant-a'`,
	} {
		if _, err := tx.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
		var denied identity.ForbiddenError
		if err := RequireSession(ctx, tx, config, got); !errors.As(err, &denied) {
			t.Fatal("primary revocation accepted", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE session_store.sessions SET state='active' WHERE tenant_id='tenant-a'; UPDATE session_store.families SET state='active' WHERE tenant_id='tenant-a'`); err != nil {
			t.Fatal(err)
		}
	}
	spec.IssuedAt, spec.LastActivityAt = now.Add(-24*time.Hour), now.Add(-24*time.Hour)
	spec.Authentication.Proof.IssuedAt = now.Add(-24*time.Hour - time.Minute)
	spec.Authentication.Proof.ExpiresAt = now.Add(-24*time.Hour + time.Minute)
	expired, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	payload, expiry, err = encodeRecord(expired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a'`, payload, expiry); err != nil {
		t.Fatal(err)
	}
	expired, err = readPrivacySession(ctx, tx, config, command)
	if err != nil {
		t.Fatal(err)
	}
	var denied identity.ForbiddenError
	if err := RequireSession(ctx, tx, config, expired); !errors.As(err, &denied) {
		t.Fatal("primary expiry accepted", err)
	}
	old, err := NewRepository(pool, config)
	if err != nil || old.privacyAdmission != nil {
		t.Fatal("historical construction enabled admission", err)
	}
}
