//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// This exercises real identity-owned locks through an original anonymous Work,
// not provider verification, coordinator issuance or the complete signin flow.
func TestOAuthSigninAccountAdmissionPrimaryFence(t *testing.T) {
	ctx, pool, repository := newAccountAuthorityStore(t)
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, sql); err != nil {
			t.Fatal("account fixture", err)
		}
	}
	exec(`INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('tenant','selected-user','active',101,13,17,19);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant','selected-user','provider-ref',3,'identity/oauth',11,true);
WITH metadata AS (SELECT 'oidc-local'::text AS provider,'https://issuer.example'::text AS issuer,'subject'::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT 'tenant','selected-user','account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),5,7,true FROM metadata;
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant','selected-user','provider-ref','account')`)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	query := ProviderSigninAccountQuery{TenantID: "tenant", Provider: "oidc-local", Issuer: "https://issuer.example", Subject: "subject"}
	if observed, err := repository.GetProviderSigninAccount(cancelled, query); !errors.Is(err, context.Canceled) || observed != (ProviderAccountAdmission{}) {
		t.Fatal("provider read cancellation lost", err)
	}
	for _, mode := range []string{"current", "current-final", "blocked", "disabled", "expired", "expired-final", "unlinked", "missing-association", "stale-link", "stale-credential", "stale-user-epoch", "changed-subject"} {
		t.Run(mode, func(t *testing.T) {
			exec(`UPDATE identity.users SET status='active',authority_version=13 WHERE tenant_id='tenant';
UPDATE identity.credential_references SET enabled=true,version=11,expires_at=NULL WHERE tenant_id='tenant';
UPDATE identity.accounts SET linked=true,social_link_version=7 WHERE tenant_id='tenant';
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant','selected-user','provider-ref','account') ON CONFLICT DO NOTHING`)
			query := ProviderSigninAccountQuery{TenantID: "tenant", Provider: "oidc-local", Issuer: "https://issuer.example", Subject: "subject"}
			expected, err := repository.GetProviderSigninAccount(ctx, query)
			if err != nil || expected != signinAccountFixture() {
				t.Fatal("actual original provider account snapshot", err)
			}
			switch mode {
			case "blocked":
				exec(`UPDATE identity.users SET status='banned' WHERE tenant_id='tenant'`)
			case "disabled":
				exec(`UPDATE identity.credential_references SET enabled=false WHERE tenant_id='tenant'`)
			case "expired", "expired-final":
				exec(`UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id='tenant'`)
			case "unlinked":
				exec(`UPDATE identity.accounts SET linked=false WHERE tenant_id='tenant'`)
			case "missing-association":
				exec(`DELETE FROM identity.account_credentials WHERE tenant_id='tenant'`)
			case "stale-link":
				exec(`UPDATE identity.accounts SET social_link_version=8 WHERE tenant_id='tenant'`)
			case "stale-credential":
				exec(`UPDATE identity.credential_references SET version=12 WHERE tenant_id='tenant'`)
			case "stale-user-epoch":
				exec(`UPDATE identity.users SET authority_version=14 WHERE tenant_id='tenant'`)
			case "changed-subject":
				expected.Account.Subject = "other-subject"
			}
			switch mode {
			case "blocked", "disabled", "expired", "expired-final", "unlinked", "missing-association":
				observed, readErr := repository.GetProviderSigninAccount(ctx, query)
				var denied identity.ForbiddenError
				if !errors.As(readErr, &denied) || observed != (ProviderAccountAdmission{}) {
					t.Fatal("ineligible provider subject selected a user", readErr)
				}
			}
			s, command := signinAccountCommand(t, expected)
			owner := &oauthSigninAccountParticipant{}
			feature := &FeatureRegistration{Contributor: owner.Descriptor(), Operation: s.Operation}
			life := &LifecyclePlan{EventType: "oauth.signin.v1"}
			frozen := &admittedKernelPlan{binding: s.Binding, feature: feature, lifecycle: life, fingerprint: [32]byte{7}}
			reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 3}}
			bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			tx, err := pool.Raw().Begin(bounded)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			w := Work{state: &workState{tx: tx, ctx: bounded, binding: s.Binding, generation: 3, feature: feature, lifecycle: &workLifecycle{plan: *life}, featureInvocation: owner, featureApplying: true, featureApplyCommand: &command, execution: &domainExecution{reservation: reservation}}}
			if mode == "current-final" || mode == "expired-final" {
				w.state.featureApplying, w.state.featureApplyCommand, w.state.featureCommitCommand = false, nil, &command
			}
			before, _ := w.state.ctx.Deadline()
			now, err := w.RequireOAuthSigninProviderAccount(bounded, owner, command)
			after, _ := w.state.ctx.Deadline()
			if before != after || w.state.binding != s.Binding {
				t.Fatal("provider selection retargeted original flow or renewed lifetime")
			}
			if mode != "current" && mode != "current-final" {
				var denied identity.ForbiddenError
				if !errors.As(err, &denied) || !now.IsZero() || w.state.failed == nil {
					t.Fatal("stale provider authority admitted", err)
				}
				if _, err := w.Exec(bounded, `SELECT 1`); err == nil {
					t.Fatal("ignored denial did not poison subsequent work")
				}
				return
			}
			if err != nil || now.IsZero() {
				t.Fatal("current linked provider account denied", err)
			}
			for _, table := range []string{"users", "credential_references", "accounts", "account_credentials"} {
				other, err := pool.Raw().Begin(bounded)
				if err != nil {
					t.Fatal(err)
				}
				_, err = other.Exec(bounded, `SELECT user_id FROM identity.`+table+` WHERE tenant_id='tenant' FOR UPDATE NOWAIT`)
				_ = other.Rollback(bounded)
				var locked *pgconn.PgError
				if !errors.As(err, &locked) || locked.Code != "55P03" {
					t.Fatal("provider authority lock escaped Work", table, err)
				}
			}
		})
	}
	for _, mode := range []string{"foreign-tenant", "foreign-provider", "foreign-issuer", "foreign-subject", "whitespace-subject", "absent-association", "ambiguous-credential"} {
		t.Run("read/"+mode, func(t *testing.T) {
			exec(`UPDATE identity.users SET status='active',authority_version=13 WHERE tenant_id='tenant';
UPDATE identity.credential_references SET enabled=true,version=11,expires_at=NULL WHERE tenant_id='tenant';
UPDATE identity.accounts SET linked=true,social_link_version=7 WHERE tenant_id='tenant';
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant','selected-user','provider-ref','account') ON CONFLICT DO NOTHING`)
			query := ProviderSigninAccountQuery{TenantID: "tenant", Provider: "oidc-local", Issuer: "https://issuer.example", Subject: "subject"}
			switch mode {
			case "foreign-tenant":
				query.TenantID = "other"
			case "foreign-provider":
				query.Provider = "other"
			case "foreign-issuer":
				query.Issuer = "https://other.example"
			case "foreign-subject":
				query.Subject = "Subject"
			case "whitespace-subject":
				query.Subject = " subject "
			case "absent-association":
				exec(`DELETE FROM identity.account_credentials WHERE tenant_id='tenant'`)
			case "ambiguous-credential":
				exec(`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant','selected-user','other-provider-ref',3,'identity/oauth',1,true);
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant','selected-user','other-provider-ref','account')`)
			}
			if observed, err := repository.GetProviderSigninAccount(ctx, query); err == nil || observed != (ProviderAccountAdmission{}) {
				t.Fatal("foreign or ambiguous provider account yielded a selected user")
			}
		})
	}
}
