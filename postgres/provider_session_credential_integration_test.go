//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestProviderSessionCredentialRequiresActualCurrentAssociation(t *testing.T) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('provider-session','user','active',1);
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('provider-session','user','provider',3,'identity/oauth',1,true);
 WITH metadata AS(SELECT 'oidc'::text AS provider,'https://issuer.example'::text AS issuer,'subject'::text AS subject)
 INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT 'provider-session','user','account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM metadata;
 INSERT INTO identity.account_credentials(tenant_id,user_id,account_id,credential_id)VALUES('provider-session','user','account','provider')`); err != nil {
		t.Fatal(err)
	}
	expected := CredentialAdmission{Credential: identity.CredentialRef{TenantID: "provider-session", UserID: "user", ID: "provider", Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 1}, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}
	if err := repo.CheckLinkedProviderCredential(ctx, expected); err != nil {
		t.Fatal("current linked provider denied", err)
	}
	for name, sql := range map[string]string{
		"missing association": `DELETE FROM identity.account_credentials WHERE tenant_id='provider-session'`,
		"unlinked account":    `UPDATE identity.accounts SET linked=false WHERE tenant_id='provider-session'`,
		"disabled credential": `UPDATE identity.credential_references SET enabled=false WHERE tenant_id='provider-session'`,
		"expired credential":  `UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id='provider-session'`,
		"blocked user":        `UPDATE identity.users SET status='banned' WHERE tenant_id='provider-session'`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='provider-session';UPDATE identity.accounts SET linked=true WHERE tenant_id='provider-session';UPDATE identity.credential_references SET enabled=true,expires_at=NULL WHERE tenant_id='provider-session';INSERT INTO identity.account_credentials(tenant_id,user_id,account_id,credential_id) VALUES('provider-session','user','account','provider') ON CONFLICT DO NOTHING`); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, sql); err != nil {
				t.Fatal(err)
			}
			var denied identity.ForbiddenError
			if err := repo.CheckLinkedProviderCredential(ctx, expected); !errors.As(err, &denied) {
				t.Fatal("stale/unlinked authority admitted", err)
			}
		})
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := repo.CheckLinkedProviderCredential(cancelled, expected); err == nil {
		t.Fatal("cancelled association read succeeded")
	}
}
