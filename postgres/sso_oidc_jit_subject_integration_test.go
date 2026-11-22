//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type ssoOIDCSubjectAvailabilityReader interface {
	SSOOIDCSubjectAvailable(context.Context, ProviderSigninAccountQuery) (bool, error)
}

func requireSSOOIDCSubjectAvailabilityReader(t *testing.T, r *Repository) ssoOIDCSubjectAvailabilityReader {
	t.Helper()
	reader, ok := any(r).(ssoOIDCSubjectAvailabilityReader)
	if !ok {
		t.Fatal("native SSO OIDC subject availability contract is missing")
	}
	return reader
}

func ssoOIDCJITSubjectQuery(subject string) ProviderSigninAccountQuery {
	return ProviderSigninAccountQuery{TenantID: "tenant-a", Provider: "sso.oidc.v1." + strings.Repeat("a", 64), Issuer: "https://issuer.example", Subject: subject}
}

func TestSSOOIDCSubjectAvailabilityNative(t *testing.T) {
	ctx, pool, repository := newAccountAuthorityStore(t)
	reader := requireSSOOIDCSubjectAvailabilityReader(t, repository)
	history, err := (SSOOIDCSubjectAvailabilityMigrationSource{Base: ssoOIDCSubjectMigrationBase(), Version: 13}).Load(ctx)
	if err != nil {
		t.Fatal("availability migration fixture")
	}
	if _, err := pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("native concurrent availability index")
	}
	exec := func(t *testing.T, sql string, args ...any) {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, sql, args...); err != nil {
			t.Fatal("subject availability fixture failed")
		}
	}
	insert := func(t *testing.T, id string, q ProviderSigninAccountQuery, linked bool) {
		t.Helper()
		exec(t, `INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 VALUES($1,'owner',$2,$3::text,$4::text,$5::text,sha256(convert_to(
 octet_length($3::text)::text||':'||$3::text||octet_length($4::text)::text||':'||$4::text||octet_length($5::text)::text||':'||$5::text,'UTF8')),1,1,$6)`, string(q.TenantID), id, q.Provider, q.Issuer, q.Subject, linked)
	}
	check := func(t *testing.T, q ProviderSigninAccountQuery, want bool) {
		t.Helper()
		available, err := reader.SSOOIDCSubjectAvailable(ctx, q)
		if err != nil || available != want {
			t.Fatal("subject availability did not preserve exact occupied scope")
		}
	}

	t.Run("absent", func(t *testing.T) { check(t, ssoOIDCJITSubjectQuery("absent"), true) })
	for _, state := range []string{"live", "retired", "disabled", "missing-association", "banned-owner"} {
		t.Run(state, func(t *testing.T) {
			q := ssoOIDCJITSubjectQuery(state)
			insert(t, state, q, state != "retired")
			if state == "disabled" {
				exec(t, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a','owner','disabled',3,'sso',1,false);
 INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant-a','owner','disabled','disabled')`)
			}
			if state == "banned-owner" {
				exec(t, `UPDATE identity.users SET status='banned' WHERE tenant_id='tenant-a' AND user_id='owner'`)
			}
			check(t, q, false)
		})
	}
	t.Run("repeated-retired-history", func(t *testing.T) {
		q := ssoOIDCJITSubjectQuery("repeated-history")
		insert(t, "retired-first", q, false)
		insert(t, "retired-second", q, false)
		check(t, q, false)
	})
	t.Run("tenant-and-namespace-isolation", func(t *testing.T) {
		q := ssoOIDCJITSubjectQuery("isolated")
		foreign := q
		foreign.TenantID = "tenant-b"
		insert(t, "foreign-tenant", foreign, true)
		otherNamespace := q
		otherNamespace.Provider = "sso.oidc.v1." + strings.Repeat("b", 64)
		insert(t, "foreign-namespace", otherNamespace, false)
		check(t, q, true)
		check(t, foreign, false)
		check(t, otherNamespace, false)
	})
	t.Run("opaque-subject", func(t *testing.T) {
		q := ssoOIDCJITSubjectQuery(" subject-ä ")
		insert(t, "opaque", q, false)
		check(t, q, false)
		q.Subject = strings.TrimSpace(q.Subject)
		check(t, q, true)
	})
	// The production CHECK prevents forged digests. Removing it only in this
	// disposable database proves collision/corruption never becomes absence.
	exec(t, `ALTER TABLE identity.accounts DROP CONSTRAINT identity_account_subject_key`)
	for _, linked := range []bool{true, false} {
		name := "retired-collision"
		if linked {
			name = "live-collision"
		}
		t.Run(name, func(t *testing.T) {
			q := ssoOIDCJITSubjectQuery(name)
			stored := q
			stored.Subject = "different-" + name
			insert(t, name, stored, linked)
			exec(t, `UPDATE identity.accounts SET subject_key=sha256(convert_to(
 octet_length($2::text)::text||':'||$2::text||octet_length($3::text)::text||':'||$3::text||octet_length($4::text)::text||':'||$4::text,'UTF8'))
 WHERE tenant_id='tenant-a' AND account_id=$1`, name, q.Provider, q.Issuer, q.Subject)
			check(t, q, false)
		})
	}
}

func TestSSOOIDCSubjectAvailabilityNativePopulatedMigration(t *testing.T) {
	ctx, pool, repository := newAccountAuthorityStore(t)
	// Retired duplicate social tuples are legal before and after this native
	// SSO access-path addition. It must not impose a new link constraint.
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT 'tenant-a','owner',id,'github','https://issuer.example','social-subject',
 sha256(convert_to('6:github22:https://issuer.example14:social-subject','UTF8')),3,5,linked
 FROM (VALUES ('old-first',false),('old-second',false),('current',true)) AS fixture(id,linked)`); err != nil {
		t.Fatal("populated account fixture")
	}
	source := SSOOIDCSubjectAvailabilityMigrationSource{Base: ssoOIDCSubjectMigrationBase(), Version: 13}
	history, err := source.Load(ctx)
	if err != nil {
		t.Fatal("availability migration fixture")
	}
	if _, err := pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("populated concurrent availability index")
	}
	var valid, ready, unique bool
	var predicate string
	if err := pool.Raw().QueryRow(ctx, `SELECT indisvalid,indisready,indisunique,pg_get_expr(indpred,indrelid)
 FROM pg_index WHERE indexrelid='identity.identity_accounts_retired_subject'::regclass`).Scan(&valid, &ready, &unique, &predicate); err != nil || !valid || !ready || unique || predicate != "(NOT linked)" {
		t.Fatal("retired subject index is not a valid non-unique partial native index")
	}
	var live, retired int
	var preserved bool
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FILTER (WHERE linked),count(*) FILTER (WHERE NOT linked),
 bool_and(provider='github' AND issuer='https://issuer.example' AND subject='social-subject' AND version=3 AND social_link_version=5)
 FROM identity.accounts WHERE tenant_id='tenant-a'`).Scan(&live, &retired, &preserved); err != nil || live != 1 || retired != 2 || !preserved {
		t.Fatal("concurrent index changed populated social account history")
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT tenant_id,user_id,'new-retired',provider,issuer,subject,subject_key,version,social_link_version,false FROM identity.accounts
 WHERE tenant_id='tenant-a' AND account_id='current'`); err != nil {
		t.Fatal("native access path prohibited legal social unlink history")
	}
	if available, err := repository.SSOOIDCSubjectAvailable(ctx, ssoOIDCJITSubjectQuery("absent")); err != nil || !available {
		t.Fatal("social history occupied an unrelated native namespace")
	}
}

func TestSSOOIDCSubjectAvailabilityNativeFailuresDeny(t *testing.T) {
	ctx, pool, repository := newAccountAuthorityStore(t)
	reader := requireSSOOIDCSubjectAvailabilityReader(t, repository)
	q := ssoOIDCJITSubjectQuery("absent")
	for _, provider := range []string{"", "github", "sso.oidc.v1." + strings.Repeat("A", 64), "sso.oidc.v1." + strings.Repeat("a", 63), "sso.oidc.v1." + strings.Repeat("a", 65), "sso.oidc.v1." + strings.Repeat("g", 64)} {
		invalid := q
		invalid.Provider = provider
		var input identity.InvalidInputError
		if available, err := reader.SSOOIDCSubjectAvailable(ctx, invalid); available || !errors.As(err, &input) {
			t.Fatal("invalid SSO namespace returned availability")
		}
	}
	for _, invalid := range []ProviderSigninAccountQuery{{}, {TenantID: q.TenantID, Provider: q.Provider, Issuer: q.Issuer}, {TenantID: q.TenantID, Provider: q.Provider, Issuer: "http://issuer.example", Subject: q.Subject}} {
		var input identity.InvalidInputError
		if available, err := reader.SSOOIDCSubjectAvailable(ctx, invalid); available || !errors.As(err, &input) {
			t.Fatal("invalid subject query returned availability")
		}
	}
	if available, err := reader.SSOOIDCSubjectAvailable(nil, q); available || err == nil {
		t.Fatal("nil context returned availability")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if available, err := reader.SSOOIDCSubjectAvailable(cancelled, q); available || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read returned availability")
	}
	bounded, err := NewRepository(pool, Config{MaximumDuration: 20 * time.Millisecond})
	if err != nil {
		t.Fatal("bounded repository fixture")
	}
	blocker, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("lock fixture")
	}
	defer blocker.Rollback(ctx)
	if _, err := blocker.Exec(ctx, `LOCK TABLE identity.accounts IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal("lock fixture")
	}
	if available, err := requireSSOOIDCSubjectAvailabilityReader(t, bounded).SSOOIDCSubjectAvailable(ctx, q); available || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("timed out read returned availability")
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal("lock release fixture")
	}
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity.accounts RENAME TO unavailable_accounts`); err != nil {
		t.Fatal("unavailable fixture")
	}
	var unavailable identity.UnavailableError
	if available, err := reader.SSOOIDCSubjectAvailable(ctx, q); available || !errors.As(err, &unavailable) {
		t.Fatal("storage failure returned availability")
	}
}
