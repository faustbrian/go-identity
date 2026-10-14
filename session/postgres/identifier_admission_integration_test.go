//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// Exercise real borrowed primary session projection/locking and constructor.
// The generation-bound CheckIdentifier invocation and kernel owner checks are
// covered by their own contracts; public protected execution remains pending.
func testIdentifierSessionProjection(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	record, cmd, profile := identifierSessionFixture(t)
	spec, _ := record.Bindings()
	now := time.Now().UTC()
	spec.IssuedAt, spec.LastActivityAt = now, now
	spec.Authentication.Proof.IssuedAt = now.Add(-time.Minute)
	spec.Authentication.Proof.ExpiresAt = now.Add(time.Minute)
	var err error
	record, err = session.NewSession(spec)
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
	if _, err = tx.Exec(ctx, `UPDATE session_store.families SET version=$1::numeric WHERE tenant_id='tenant-a'`, spec.FamilyVersion); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE session_store.sessions SET version=$1::numeric,family_version=$2::numeric,record=$3::jsonb,expires_at=$4 WHERE tenant_id='tenant-a'`, spec.Version, spec.FamilyVersion, payload, expiry); err != nil {
		t.Fatal(err)
	}
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	repo, err := NewRepositoryWithIdentifierAdmission(pool, c, profile)
	if err != nil || repo.identifierAdmission == nil {
		t.Fatal("native constructor", err)
	}
	profile.Audience = "changed"
	if repo.identifierAdmission.Audience != "service-a" {
		t.Fatal("caller mutated profile")
	}
	got, err := readIdentifierSession(ctx, tx, c, cmd)
	if err != nil {
		t.Fatal("original session projection", err)
	}
	if err = RequireSession(ctx, tx, c, got); err != nil {
		t.Fatal("complete physical row comparison", err)
	}
	_, credential, _, err := identifierSessionBindings(*repo.identifierAdmission, got, cmd, 7, true)
	if err != nil || credential.IdentifierAuthorityVersion != 7 {
		t.Fatal("owned final epoch mapping", err)
	}
	original, _ := got.Bindings()
	a, _ := original.Authority.Bindings()
	if a.Identifier.Version != 6 || original.Authentication != spec.Authentication {
		t.Fatal("snapshot or metadata rewritten")
	}
	for _, change := range []func(*identity.IdentifierCommand){func(c *identity.IdentifierCommand) { c.Binding.TenantID = "tenant-b" }, func(c *identity.IdentifierCommand) { c.Binding.UserID = "other" }, func(c *identity.IdentifierCommand) { c.SessionID = "missing" }, func(c *identity.IdentifierCommand) { c.SessionVersion++ }} {
		other := cmd
		change(&other)
		var denied identity.ForbiddenError
		if _, e := readIdentifierSession(ctx, tx, c, other); !errors.As(e, &denied) {
			t.Fatal("foreign or stale session projection", e)
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	var denied identity.ForbiddenError
	if _, err = readIdentifierSession(ctx, tx, c, cmd); !errors.As(err, &denied) {
		t.Fatal("revoked projection", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE session_store.sessions SET state='active',record=jsonb_set(record,'{Authority,Passkey}','null') WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if _, err = readIdentifierSession(ctx, tx, c, cmd); !errors.As(err, &unavailable) {
		t.Fatal("corrupt record", err)
	}
	old, err := NewRepository(pool, c)
	if err != nil || old.identifierAdmission != nil {
		t.Fatal("historical opt-in changed", err)
	}
	if old.CheckIdentifier(ctx, kernel.IdentifierAdmissionWork{}) == nil {
		t.Fatal("zero invocation accepted")
	}
}
