//go:build integration

package postgres

import (
	"context"
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testCredentialAuthority(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	q := identity.CredentialAuthorityQuery{TenantID: "credential", UserID: "user", CredentialID: "ref"}
	_, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,identifier_version,authority_version,credential_version)
 VALUES('credential','user','active',7,17,19,11),('credential-other','user','banned',23,29,31,37),('credential','other','active',41,43,47,53);
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 VALUES('credential','user','ref',1,'identity/password',13,true),('credential-other','user','ref',1,'identity/password',59,true),('credential','other','ref',1,'identity/password',61,true)`)
	if err != nil {
		t.Fatal("credential fixtures failed", err)
	}
	read := func(query identity.CredentialAuthorityQuery, aggregate, authority, reference uint64, status identity.Status, enabled bool) identity.CredentialAuthorityRecord {
		t.Helper()
		got, e := repo.GetCredentialAuthority(ctx, query)
		if e != nil || got.User.Version != aggregate || got.AuthorityVersion != authority || got.Credential.Version != reference || got.User.Status != status || got.Enabled != enabled || got.Credential.ID != query.CredentialID || got.Credential.UserID != query.UserID || got.Credential.TenantID != query.TenantID {
			t.Fatal("exact independent primary credential snapshot failed", e)
		}
		return got
	}
	got := read(q, 7, 11, 13, identity.StatusActive, true)
	if err := identity.CheckCredentialAuthority(got, got.Credential, 11, time.Now()); err != nil {
		t.Fatal("core cannot consume primary record", err)
	}
	foreign := q
	foreign.TenantID = "credential-other"
	got = read(foreign, 23, 37, 59, identity.StatusBanned, true)
	if identity.CheckCredentialAuthority(got, got.Credential, 37, time.Now()) == nil {
		t.Fatal("blocked primary user granted eligibility")
	}
	foreign = q
	foreign.UserID = "other"
	read(foreign, 41, 53, 61, identity.StatusActive, true)
	for _, absent := range []identity.CredentialAuthorityQuery{{TenantID: "missing", UserID: q.UserID, CredentialID: q.CredentialID}, {TenantID: q.TenantID, UserID: "missing", CredentialID: q.CredentialID}, {TenantID: q.TenantID, UserID: q.UserID, CredentialID: "missing"}} {
		got, e := repo.GetCredentialAuthority(ctx, absent)
		if !errors.Is(e, identity.ErrUserAbsent) || got != (identity.CredentialAuthorityRecord{}) {
			t.Fatal("foreign/absent reference granted partial record", e)
		}
	}
	expiry := time.Date(2020, 1, 1, 0, 0, 0, 123000, time.UTC)
	if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false,expires_at=$1 WHERE tenant_id='credential' AND user_id='user'`, expiry); e != nil {
		t.Fatal(e)
	}
	got = read(q, 7, 11, 13, identity.StatusActive, false)
	if !got.ExpiresAt.Equal(expiry) || identity.CheckCredentialAuthority(got, got.Credential, 11, time.Now()) == nil {
		t.Fatal("expired disabled reference was restored")
	}
	for _, value := range []uint64{1<<53 + 1, 1 << 63, math.MaxUint64} {
		v := strconv.FormatUint(value, 10)
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET credential_version=$1::numeric WHERE tenant_id='credential' AND user_id='user'`, v); e != nil {
			t.Fatal(e)
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET version=$1::numeric WHERE tenant_id='credential' AND user_id='user'`, v); e != nil {
			t.Fatal(e)
		}
		read(q, 7, value, value, identity.StatusActive, false)
	}
	// Every writer commits both dimensions together. The reader must never
	// combine the user epoch from one commit with a reference from another.
	writePair := func(epoch int) error {
		tx, e := pool.Raw().Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, `UPDATE identity.users SET credential_version=$1::numeric WHERE tenant_id='credential' AND user_id='user'`, strconv.Itoa(epoch)); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE identity.credential_references SET version=$1::numeric WHERE tenant_id='credential' AND user_id='user'`, strconv.Itoa(epoch+100)); e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	if e := writePair(101); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		for i := 102; i < 118; i++ {
			if e := writePair(i); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	consistent := true
	for i := 0; i < 32; i++ {
		got, e := repo.GetCredentialAuthority(ctx, q)
		if e != nil || got.Credential.Version != got.AuthorityVersion+100 || got.User.Version != 7 {
			consistent = false
		}
	}
	if e := <-done; e != nil {
		t.Fatal("concurrent writer failed", e)
	}
	if !consistent {
		t.Fatal("primary read combined separate committed snapshots")
	}
	// Older creation SQL continues to initialize only this independent dimension;
	// no row is synthesized when it has not created a credential reference.
	if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('credential','old-writer','active',1)`); e != nil {
		t.Fatal(e)
	}
	var epoch string
	if e := pool.Raw().QueryRow(ctx, `SELECT credential_version::text FROM identity.users WHERE tenant_id='credential' AND user_id='old-writer'`).Scan(&epoch); e != nil || epoch != "1" {
		t.Fatal("old creation default changed", e)
	}
	old := q
	old.UserID = "old-writer"
	if got, e := repo.GetCredentialAuthority(ctx, old); !errors.Is(e, identity.ErrUserAbsent) || got != (identity.CredentialAuthorityRecord{}) {
		t.Fatal("epoch default fabricated a credential", e)
	}
	for _, sql := range []string{
		`UPDATE identity.credential_references SET owner='passkey' WHERE tenant_id='credential'`,
		`UPDATE identity.credential_references SET kind=257 WHERE tenant_id='credential'`,
		`UPDATE identity.credential_references SET version=0 WHERE tenant_id='credential'`,
		`UPDATE identity.credential_references SET version=1.5 WHERE tenant_id='credential'`,
		`UPDATE identity.credential_references SET version=18446744073709551616 WHERE tenant_id='credential'`,
		`UPDATE identity.users SET credential_version=0 WHERE tenant_id='credential'`,
		`UPDATE identity.credential_references SET expires_at='infinity' WHERE tenant_id='credential'`,
		`UPDATE identity.credential_references SET expires_at='0001-01-01 00:00:00+00' WHERE tenant_id='credential'`,
		`UPDATE identity.credential_references SET expires_at='10000-01-01 00:00:00+00' WHERE tenant_id='credential'`,
		`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('credential','missing','ref',1,'identity/password',1,true)`,
	} {
		if _, e := pool.Raw().Exec(ctx, sql); e == nil {
			t.Fatal("database admitted corrupt reference/epoch")
		}
	}
	for _, kind := range []struct {
		kind  int
		owner string
	}{{1, "identity/password"}, {2, "passkey"}, {2, "webauthn"}, {3, "identity/oauth"}, {3, "sso"}, {4, "identity/apikey"}} {
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET kind=$1,owner=$2 WHERE tenant_id='credential' AND user_id='other'`, kind.kind, kind.owner); e != nil {
			t.Fatal(e)
		}
		query := q
		query.UserID = "other"
		got, e := repo.GetCredentialAuthority(ctx, query)
		if e != nil || got.Credential.Kind != identity.CredentialKind(kind.kind) || got.Credential.Owner != kind.owner {
			t.Fatal("supported owner pair changed", e)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, e := repo.GetCredentialAuthority(canceled, q); !errors.Is(e, context.Canceled) || got != (identity.CredentialAuthorityRecord{}) {
		t.Fatal("cancelled read returned authority", e)
	}
	if got, e := repo.GetCredentialAuthority(nil, q); e == nil || got != (identity.CredentialAuthorityRecord{}) {
		t.Fatal("nil context accepted")
	}
	bad := q
	bad.CredentialID = "invalid credential"
	if got, e := repo.GetCredentialAuthority(ctx, bad); e == nil || got != (identity.CredentialAuthorityRecord{}) {
		t.Fatal("invalid exact ID accepted")
	}
	lock, e := pool.Raw().Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback(ctx)
	if _, e := lock.Exec(ctx, `LOCK TABLE identity.credential_references IN ACCESS EXCLUSIVE MODE`); e != nil {
		t.Fatal(e)
	}
	deadline, cancelDeadline := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelDeadline()
	if got, e := repo.GetCredentialAuthority(deadline, q); !errors.Is(e, context.DeadlineExceeded) || got != (identity.CredentialAuthorityRecord{}) {
		t.Fatal("blocked primary read ignored earlier deadline", e)
	}
}
