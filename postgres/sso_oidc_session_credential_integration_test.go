//go:build integration

package postgres

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Storage fixtures prove current eligibility, not enterprise authentication or
// a complete session revoke-one journey; those remain with the session owner.
func TestSSOOIDCSessionCredentialRequiresActualCurrentAssociation(t *testing.T) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	w, owner, expected := ssoOIDCSessionCredentialFixture()
	b := w.state.binding
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol, string(b.TenantID), string(b.UserID), string(expected.Credential.ID)); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES($1,$2,'active',101,11,13,17);
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,3,'sso',3,true)`)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT $1,$2,'enterprise-account','enterprise','https://issuer.example','subject',sha256(convert_to('10:enterprise22:https://issuer.example7:subject','UTF8')),1,1,true;
 INSERT INTO identity.account_credentials(tenant_id,user_id,account_id,credential_id)VALUES($1,$2,'enterprise-account',$3)`, pgx.QueryExecModeSimpleProtocol, string(b.TenantID), string(b.UserID), string(expected.Credential.ID)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, change string
		allowed      bool
	}{
		{"exact original", "", true},
		{"aggregate version is not authority", `UPDATE identity.users SET version=102 WHERE tenant_id=$1 AND user_id=$2 AND $3<>''`, true},
		{"missing association", `DELETE FROM identity.account_credentials WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, false},
		{"unlinked account", `UPDATE identity.accounts SET linked=false WHERE tenant_id=$1 AND user_id=$2 AND $3<>''`, false},
		{"disabled", `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, false},
		{"expired", `UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, false},
		{"stale reference", `UPDATE identity.credential_references SET version=4 WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, false},
		{"cross owner", `UPDATE identity.credential_references SET owner='identity/oauth' WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, false},
		{"missing reference", `DELETE FROM identity.account_credentials WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3; DELETE FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, false},
		{"inactive user", `UPDATE identity.users SET status='banned' WHERE tenant_id=$1 AND user_id=$2 AND $3<>''`, false},
		{"stale user epoch", `UPDATE identity.users SET authority_version=12 WHERE tenant_id=$1 AND user_id=$2 AND $3<>''`, false},
		{"stale identifier epoch", `UPDATE identity.users SET identifier_version=14 WHERE tenant_id=$1 AND user_id=$2 AND $3<>''`, false},
		{"stale credential epoch", `UPDATE identity.users SET credential_version=18 WHERE tenant_id=$1 AND user_id=$2 AND $3<>''`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(`UPDATE identity.users SET status='active',version=101,authority_version=11,identifier_version=13,credential_version=17 WHERE tenant_id=$1 AND user_id=$2;
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,3,'sso',3,true) ON CONFLICT DO NOTHING;
 UPDATE identity.credential_references SET enabled=true,owner='sso',version=3,expires_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3;
 UPDATE identity.accounts SET linked=true WHERE tenant_id=$1 AND user_id=$2;
 INSERT INTO identity.account_credentials(tenant_id,user_id,account_id,credential_id) VALUES($1,$2,'enterprise-account',$3) ON CONFLICT DO NOTHING`)
			if tc.change != "" {
				exec(tc.change)
			}
			readErr := repo.CheckLinkedSSOOIDCProviderCredential(ctx, expected)
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			work, _, _ := ssoOIDCSessionCredentialFixture()
			work.state.ctx, work.state.tx, work.state.featureInvocation = ctx, tx, owner
			workErr := work.RequireLinkedSSOOIDCProviderCredential(ctx, owner, expected)
			if tc.allowed {
				if readErr != nil || workErr != nil {
					t.Fatal("current SSO authority denied", readErr, workErr)
				}
				for _, sql := range []string{
					`SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id=$2 AND $3<>'' FOR UPDATE NOWAIT`,
					`SELECT credential_id FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 FOR UPDATE NOWAIT`,
					`SELECT account_id FROM identity.accounts WHERE tenant_id=$1 AND user_id=$2 AND $3<>'' FOR UPDATE NOWAIT`,
					`SELECT credential_id FROM identity.account_credentials WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 FOR UPDATE NOWAIT`,
				} {
					probe, e := pool.Raw().Begin(ctx)
					if e != nil {
						t.Fatal(e)
					}
					_, e = probe.Exec(ctx, sql, string(b.TenantID), string(b.UserID), string(expected.Credential.ID))
					_ = probe.Rollback(ctx)
					var locked *pgconn.PgError
					if !errors.As(e, &locked) || locked.Code != "55P03" {
						t.Fatal("SSO association authority lock not retained", e)
					}
				}
				// A final invocation may recheck the original reference, including a
				// source credential unrelated to the target session record ID.
				work.state.featureApplying = false
				if err := work.RequireLinkedSSOOIDCProviderCredential(ctx, owner, expected); err != nil {
					t.Fatal("final eligibility denied", err)
				}
				if _, err := tx.Exec(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(b.TenantID), string(b.UserID), string(expected.Credential.ID)); err != nil {
					t.Fatal(err)
				}
				var denied identity.ForbiddenError
				if err := work.RequireLinkedSSOOIDCProviderCredential(ctx, owner, expected); !errors.As(err, &denied) || work.state.failed == nil {
					t.Fatal("final check ignored newly expired original", err)
				}
			} else {
				var denied identity.ForbiddenError
				if !errors.As(readErr, &denied) || !errors.As(workErr, &denied) || !errors.As(work.usable(), &denied) {
					t.Fatal("stale SSO authority admitted or denial ignored", readErr, workErr)
				}
			}
		})
	}
}
