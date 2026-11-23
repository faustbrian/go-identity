//go:build integration

package postgres

import (
	"errors"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// Primary admission borrows the existing identity lock order. The known-owner
// fixture observes that narrow fence, not protocol proof or session issuance.
func TestSSOOIDCSigninAccountPrimaryFence(t *testing.T) {
	testSSOSigninAccountPrimaryFence(t, "oidc", []string{"apply", "final", "blocked", "disabled", "expired", "unlinked", "missing-association", "stale-account", "stale-link", "stale-credential", "stale-user", "stale-identifier", "stale-credential-epoch"})
}

func TestSSOOAuth2SigninAccountPrimaryFence(t *testing.T) {
	testSSOSigninAccountPrimaryFence(t, "oauth2", []string{"apply", "final", "blocked", "unlinked", "stale-credential"})
}

func TestSSOSAMLCallbackAccountPrimaryFence(t *testing.T) {
	testSSOSigninAccountPrimaryFence(t, "saml", []string{"apply", "final", "blocked", "unlinked", "missing-association", "stale-credential"})
}

func testSSOSigninAccountPrimaryFence(t *testing.T, protocol string, modes []string) {
	t.Helper()
	ctx, pool, repository := newAccountAuthorityStore(t)
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, sql); err != nil {
			t.Fatal("enterprise account fixture", err)
		}
	}
	exec(`INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('tenant','selected-user','active',101,13,17,19);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant','selected-user','provider-ref',3,'sso',11,true)`)
	want := ssoOIDCSigninAccountFixture()
	read := repository.GetSSOOIDCSigninAccount
	if protocol == "saml" {
		want.Account.Provider, want.Account.Issuer = "sso.saml.v1."+strings.Repeat("a", 64), "urn:example:trusted-saml-idp"
		read = repository.GetSSOSAMLSigninAccount
	}
	q := ProviderSigninAccountQuery{TenantID: want.Account.TenantID, Provider: want.Account.Provider, Issuer: want.Account.Issuer, Subject: want.Account.Subject}
	if _, err := pool.Raw().Exec(ctx, `WITH metadata AS (SELECT $1::text AS provider,$2::text AS issuer,$3::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT 'tenant','selected-user','account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),5,7,true FROM metadata`, q.Provider, q.Issuer, q.Subject); err != nil {
		t.Fatal("write exact provider account tuple", err)
	}
	exec(`INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant','selected-user','provider-ref','account')`)
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			exec(`UPDATE identity.users SET status='active',authority_version=13,identifier_version=17,credential_version=19 WHERE tenant_id='tenant';
UPDATE identity.credential_references SET enabled=true,version=11,expires_at=NULL WHERE tenant_id='tenant';
UPDATE identity.accounts SET linked=true,version=5,social_link_version=7 WHERE tenant_id='tenant';
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant','selected-user','provider-ref','account') ON CONFLICT DO NOTHING`)
			expected, err := read(ctx, q)
			if err != nil || expected != want {
				t.Fatal("enterprise account lookup lost original authority", err)
			}
			switch mode {
			case "blocked":
				exec(`UPDATE identity.users SET status='banned' WHERE tenant_id='tenant'`)
			case "disabled":
				exec(`UPDATE identity.credential_references SET enabled=false WHERE tenant_id='tenant'`)
			case "expired":
				exec(`UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id='tenant'`)
			case "unlinked":
				exec(`UPDATE identity.accounts SET linked=false WHERE tenant_id='tenant'`)
			case "missing-association":
				exec(`DELETE FROM identity.account_credentials WHERE tenant_id='tenant'`)
			case "stale-account":
				exec(`UPDATE identity.accounts SET version=6 WHERE tenant_id='tenant'`)
			case "stale-link":
				exec(`UPDATE identity.accounts SET social_link_version=8 WHERE tenant_id='tenant'`)
			case "stale-credential":
				exec(`UPDATE identity.credential_references SET version=12 WHERE tenant_id='tenant'`)
			case "stale-user":
				exec(`UPDATE identity.users SET authority_version=14 WHERE tenant_id='tenant'`)
			case "stale-identifier":
				exec(`UPDATE identity.users SET identifier_version=18 WHERE tenant_id='tenant'`)
			case "stale-credential-epoch":
				exec(`UPDATE identity.users SET credential_version=20 WHERE tenant_id='tenant'`)
			}
			makeCommand, makePlan := ssoOIDCSigninAccountCommand, ssoOIDCSigninPlanFixture
			var owner FeatureExecutionContributor = &ssoOIDCSigninAccountParticipant{}
			require := Work.RequireSSOOIDCSigninProviderAccount
			switch protocol {
			case "oauth2":
				makeCommand, makePlan = ssoOAuth2SigninAccountCommand, ssoOAuth2SigninPlanFixture
				owner, require = &ssoOAuth2SigninAccountParticipant{}, Work.RequireSSOOAuth2SigninProviderAccount
			case "saml":
				makeCommand, makePlan = samlSigninAccountCommand, samlSigninPlanFixture
				owner, require = &samlSigninAccountParticipant{}, Work.RequireSSOSAMLSigninProviderAccount
			}
			s, command := makeCommand(t, expected)
			_, plan := makePlan(t)
			frozen := &admittedKernelPlan{binding: s.Binding, feature: plan.Feature, lifecycle: plan.Lifecycle, fingerprint: [32]byte{7}}
			reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 3}}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			w := Work{state: &workState{tx: tx, ctx: ctx, binding: s.Binding, generation: 3, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true, featureApplyCommand: &command, execution: &domainExecution{reservation: reservation}}}
			if mode == "final" {
				w.state.featureApplying, w.state.featureApplyCommand, w.state.featureCommitCommand = false, nil, &command
			}
			now, err := require(w, ctx, owner, command)
			if w.state.binding != s.Binding {
				t.Fatal("enterprise account selection retargeted original flow")
			}
			if mode != "apply" && mode != "final" {
				var denied identity.ForbiddenError
				if !errors.As(err, &denied) || !now.IsZero() || w.state.failed == nil {
					t.Fatal("stale enterprise account admitted", err)
				}
				return
			}
			if err != nil || now.IsZero() {
				t.Fatal("current enterprise account denied", err)
			}
			for _, table := range []string{"users", "credential_references", "accounts", "account_credentials"} {
				other, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_, err = other.Exec(ctx, `SELECT user_id FROM identity.`+table+` WHERE tenant_id='tenant' FOR UPDATE NOWAIT`)
				_ = other.Rollback(ctx)
				var locked *pgconn.PgError
				if !errors.As(err, &locked) || locked.Code != "55P03" {
					t.Fatal("enterprise authority lock escaped Work", table, err)
				}
			}
			if protocol != "oidc" {
				reconstructed := ssoOIDCAccountPreAuthCommand(t, s)
				if _, err := require(w, ctx, owner, reconstructed); err == nil || w.state.failed == nil {
					t.Fatal("reconstructed callback command acquired the original invocation")
				}
			}
		})
	}
	for _, owner := range []string{"identity/oauth", "sso"} {
		exec(`UPDATE identity.users SET status='active',authority_version=13,identifier_version=17,credential_version=19 WHERE tenant_id='tenant';
UPDATE identity.credential_references SET enabled=true,version=11,expires_at=NULL WHERE tenant_id='tenant';
UPDATE identity.accounts SET linked=true,version=5,social_link_version=7 WHERE tenant_id='tenant'`)
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET owner=$1 WHERE tenant_id='tenant'`, owner); err != nil {
			t.Fatal(err)
		}
		out, ssoErr := read(ctx, q)
		_, socialErr := repository.GetProviderSigninAccount(ctx, q)
		if owner == "identity/oauth" && (ssoErr == nil || out != (ProviderAccountAdmission{}) || socialErr != nil) {
			t.Fatal("enterprise read broadened social credential acceptance")
		}
		if owner == "sso" && (ssoErr != nil || socialErr == nil) {
			t.Fatal("social read broadened enterprise credential acceptance")
		}
	}
}
