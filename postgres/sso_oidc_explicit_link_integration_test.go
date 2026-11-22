//go:build integration

package postgres

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestSSOOIDCExplicitLinkChangesOnlyTheExistingMember(t *testing.T) {
	ctx, pool, repository := newAccountAuthorityStore(t)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
VALUES('tenant-a','owner','local-credential',1,'identity/password',1,true)`); err != nil {
		t.Fatal("existing local credential fixture", err)
	}
	token := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	for _, mode := range []string{"no-state", "wrong-actor", "stale-credential", "retired-subject", "late-revocation", "rollback", "commit"} {
		t.Run(mode, func(t *testing.T) {
			intent := enterpriseExplicitLinkIntent()
			intent.Change.Account.UserID, intent.Change.Method.Credential.UserID = "owner", "owner"
			intent.ActorCredential.Credential.UserID, intent.ActorCredential.Credential.Version = "owner", 1
			intent.ActorCredential.UserAuthorityVersion, intent.ActorCredential.IdentifierAuthorityVersion, intent.ActorCredential.CredentialAuthorityVersion = 1, 1, 1
			intent.Change.ExpectedUserVersion, intent.Change.ExpectedCredentialVersion = 1, 1
			intent.Change.Account.Subject = "linked-subject-" + mode
			intent.ValidUntil = time.Now().UTC().Truncate(time.Microsecond).Add(15 * time.Second)
			if mode == "stale-credential" {
				intent.ActorCredential.Credential.Version++
			}
			b, plan := enterpriseExplicitLinkPlan(t)
			b.ActorID, b.UserID = "owner", "owner"
			if mode == "wrong-actor" {
				b.ActorID = "other"
			}
			plan.Capability.ExpiresAt = intent.ValidUntil.Add(time.Second)
			field, err := SSOOIDCExplicitLinkField(intent)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: plan.Feature.Operation, Fields: []identity.FeatureField{field}}, token)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "retired-subject" {
				a := intent.Change.Account
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
VALUES('tenant-a','other','previous-link',$1::text,$2::text,$3::text,sha256(convert_to(octet_length($1::text)::text||':'||$1::text||octet_length($2::text)::text||':'||$2::text||octet_length($3::text)::text||':'||$3::text,'UTF8')),1,1,false)`, a.Provider, a.Issuer, a.Subject); err != nil {
					t.Fatal("retired link fixture", err)
				}
			}
			owner := &ssoOIDCSigninAccountParticipant{}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			w := Work{state: &workState{tx: tx, ctx: ctx, binding: b, generation: 1, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle},
				featureInvocation: owner, featureApplying: true, featureApplyCommand: &command, oauthSigninStage: oauthSigninStateConsumed,
				execution: &domainExecution{reservation: &reservationState{journal: journalReservation{generation: 1}, plan: &admittedKernelPlan{
					binding: b, feature: plan.Feature, capability: plan.Capability, fingerprint: [32]byte{8},
					contributors: []registeredContributor{{descriptor: repository.Descriptor(), contributor: repository}},
				}}}}}
			if err := configureKernelWork(ctx, w); err != nil {
				t.Fatal(err)
			}
			if mode == "no-state" {
				w.state.oauthSigninStage = oauthSigninStateAbsent
			}
			linked, err := repository.ApplySSOOIDCExplicitLink(ctx, w, owner, command, intent)
			switch mode {
			case "late-revocation", "rollback", "commit":
				if err != nil || linked.Account != intent.Change.Account || linked.Credential.Credential != intent.Change.Method.Credential || linked.Credential.CredentialAuthorityVersion != 2 {
					t.Fatal("provisional enterprise account or authority differs from original intent", err)
				}
				w.state.oauthSigninStage = oauthSigninStateFinalized
				if mode == "late-revocation" {
					if _, err := w.Exec(ctx, `UPDATE identity.credential_references SET enabled=false
WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='local-credential'`); err != nil {
						t.Fatal("reach the post-link commit check with invalidated actor authority", err)
					}
					if err := w.checkSSOOIDCExplicitLinkFinal(); !errors.As(err, new(identity.ForbiddenError)) || w.usable() == nil {
						t.Fatal("final check admitted a link after its original actor credential was invalidated", err)
					}
				} else if err := w.checkSSOOIDCExplicitLinkFinal(); err != nil {
					t.Fatal("final check did not accept the actual linked successor", err)
				}
				if mode == "commit" {
					if err := tx.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				} else if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			default:
				if err == nil || w.usable() == nil {
					t.Fatal("unadmitted enterprise link did not stop Work")
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			}
			q := ProviderSigninAccountQuery{TenantID: "tenant-a", Provider: intent.Change.Account.Provider, Issuer: intent.Change.Account.Issuer, Subject: intent.Change.Account.Subject}
			actual, lookupErr := repository.GetSSOOIDCSigninAccount(ctx, q)
			if mode == "commit" {
				if lookupErr != nil || actual != linked || actual.Account.UserID != "owner" {
					t.Fatal("subsequent enterprise sign-in cannot resolve the original member", lookupErr)
				}
			} else if !errors.As(lookupErr, new(identity.ForbiddenError)) {
				t.Fatal("uncommitted link became visible", lookupErr)
			}
			var users, localCredentials int
			var aggregate, epoch string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id='tenant-a'),
 (SELECT count(*) FROM identity.credential_references WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='local-credential' AND enabled),
 version::text,credential_version::text FROM identity.users WHERE tenant_id='tenant-a' AND user_id='owner'`).Scan(&users, &localCredentials, &aggregate, &epoch); err != nil {
				t.Fatal(err)
			}
			version := "1"
			if mode == "commit" {
				version = "2"
			}
			if users != 2 || localCredentials != 1 || aggregate != version || epoch != version {
				t.Fatal("link changed user conservation, local credential or independent authority epochs")
			}
		})
	}
}
