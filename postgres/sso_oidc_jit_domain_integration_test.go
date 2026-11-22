//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestSSOOIDCJITIdentitySharesOriginalWork(t *testing.T) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	for _, schema := range []string{identifierRetirementSQL, identifierNormalizationSQL} {
		if _, err := pool.Raw().Exec(ctx, schema); err != nil {
			t.Fatal("identifier history", err)
		}
	}
	key := [32]byte{11}
	domain, err := NewSSOOIDCJITDomain(repo, SSOOIDCJITDomainConfig{
		ComparisonProfile: "canonical-email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: key},
	})
	if err != nil {
		t.Fatal("JIT composition", err)
	}
	for _, mode := range []string{"commit", "rollback", "own-command-only", "duplicate", "reused-email", "retired-email", "retired-subject", "expired", "past-original-grant", "no-consumption", "missing-intent", "changed-intent"} {
		t.Run(mode, func(t *testing.T) {
			intent := ssoOIDCJITIntentFixture()
			intent.Account.Account.TenantID = "tenant-a"
			intent.Account.Credential.Credential.TenantID = "tenant-a"
			intent.Account.Account.Subject = "subject-" + mode
			intent.Account.Account.ID = identity.AccountID("account-" + mode)
			intent.Account.Credential.Credential.ID = identity.CredentialID("credential-" + mode)
			intent.Account.Account.UserID = identity.UserID("user-" + mode)
			intent.Account.Credential.Credential.UserID = intent.Account.Account.UserID
			intent.Email.ID = identity.IdentifierID("email-" + mode)
			intent.Email.UserID = intent.Account.Account.UserID
			intent.Email.CanonicalValue = mode + "@enterprise.example"
			intent.Email.DisplayValue = intent.Email.CanonicalValue
			intent.Email.NormalizationProfile = "canonical-email"
			intent.Email.NormalizationVersion = 1
			now := time.Now().UTC().Truncate(time.Microsecond)
			intent.ValidUntil = now.Add(15 * time.Second)
			if mode == "expired" {
				intent.ValidUntil = now.Add(-time.Second)
			}
			spec, _ := ssoOIDCSigninAccountCommand(t, intent.Account)
			field, err := SSOOIDCJITIntentField(intent)
			if err != nil {
				t.Fatal("freeze enterprise intent", err)
			}
			if mode != "missing-intent" {
				spec.Fields = append(spec.Fields, field)
			}
			command := ssoOIDCAccountPreAuthCommand(t, spec)
			_, plan := ssoOIDCSigninPlanFixture(t)
			plan.Capability.ExpiresAt = now.Add(30 * time.Second)
			if mode == "past-original-grant" {
				plan.Capability.ExpiresAt = now.Add(10 * time.Second)
			}
			seed := func(sql string, args ...any) {
				t.Helper()
				if _, err := pool.Raw().Exec(ctx, sql, args...); err != nil {
					t.Fatal("existing owner fixture", err)
				}
			}
			switch mode {
			case "reused-email":
				seed(`INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,verified,is_primary,version,verification_state,verification_version)
VALUES('tenant-a','owner','existing-jit-email','email',$1::text,$1::text,false,false,1,1,1)`, intent.Email.CanonicalValue)
			case "retired-email":
				digest := identifierReuseDigest(key, "tenant-a", identity.IdentifierEmail, intent.Email.CanonicalValue)
				seed(`INSERT INTO identity.identifier_retirements(tenant_id,user_id,identifier_id,kind,record_version,verification_version,removed,command_id,key_version,value_digest,retired_at,reuse_until)
VALUES('tenant-a','owner','retired-jit-email','email',1,1,true,'BAQEBAQEBAQEBAQEBAQEBA',1,$1,$2,$3)`, digest[:], now, now.Add(time.Hour))
			case "retired-subject":
				a := intent.Account.Account
				seed(`INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
VALUES('tenant-a','owner','retired-jit-account',$1::text,$2::text,$3::text,sha256(convert_to(octet_length($1::text)::text||':'||$1::text||octet_length($2::text)::text||':'||$2::text||octet_length($3::text)::text||':'||$3::text,'UTF8')),1,1,false)`, a.Provider, a.Issuer, a.Subject)
			case "changed-intent":
				intent.JITPolicyVersion++
			}
			owner := &ssoOIDCSigninAccountParticipant{}
			frozen := &admittedKernelPlan{binding: spec.Binding, feature: plan.Feature, lifecycle: plan.Lifecycle,
				capability: plan.Capability, fingerprint: [32]byte{7}, contributors: []registeredContributor{{descriptor: repo.Descriptor(), contributor: repo}}}
			reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 3}}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			w := Work{state: &workState{tx: tx, ctx: ctx, binding: spec.Binding, generation: 3, feature: plan.Feature,
				lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true,
				featureApplyCommand: &command, execution: &domainExecution{reservation: reservation}, oauthSigninStage: oauthSigninStateConsumed}}
			if err := configureKernelWork(ctx, w); err != nil {
				t.Fatal("original tenant fence", err)
			}
			if mode == "no-consumption" {
				w.state.oauthSigninStage = oauthSigninStateAbsent
			}
			user, err := domain.Apply(ctx, w, owner, command, intent)
			switch mode {
			case "commit", "rollback", "own-command-only", "duplicate":
				if err != nil || user != (identity.User{TenantID: "tenant-a", ID: intent.Email.UserID, Version: 1, Status: identity.StatusActive}) || w.state.binding != spec.Binding {
					t.Fatal("creation failed or retargeted original command", err)
				}
				proof, err := w.SSOOIDCJITUser(ctx, owner, command)
				if err != nil || proof != user {
					t.Fatal("same-command creation proof", err)
				}
			case "reused-email", "retired-email", "retired-subject":
				var conflict identity.ConflictError
				if !errors.As(err, &conflict) || user != (identity.User{}) || w.state.failed == nil {
					t.Fatal("existing or retired owner was not rejected", err)
				}
			default:
				if err == nil || user != (identity.User{}) || w.state.failed == nil {
					t.Fatal("invalid original callback created a user", err)
				}
			}
			if mode == "own-command-only" {
				copy := ssoOIDCAccountPreAuthCommand(t, spec)
				if got, err := w.SSOOIDCJITUser(ctx, owner, copy); err == nil || got != (identity.User{}) || w.state.failed == nil {
					t.Fatal("reconstructed command borrowed original proof")
				}
			}
			if mode == "duplicate" {
				if _, err := domain.Apply(ctx, w, owner, command, intent); err == nil || w.state.failed == nil {
					t.Fatal("duplicate creation did not poison Work")
				}
			}
			if mode == "commit" {
				w.state.featureApplying, w.state.featureApplyCommand, w.state.featureCommitCommand = false, nil, &command
				w.state.oauthSigninStage = oauthSigninStateFinalized
				if got, err := w.SSOOIDCJITUser(ctx, owner, command); err != nil || got != user {
					t.Fatal("final check lost same-command creation proof", err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal("native transaction commit", err)
				}
			} else if err := tx.Rollback(ctx); err != nil {
				t.Fatal("native transaction rollback", err)
			}
			assertSSOOIDCJITIdentityRows(t, repo, ctx, intent, mode == "commit")
		})
	}
}

func assertSSOOIDCJITIdentityRows(t *testing.T, repo *Repository, ctx context.Context, intent SSOOIDCJITIntent, want bool) {
	t.Helper()
	a, i := intent.Account.Account, intent.Email
	id := string(intent.Account.Credential.Credential.ID)
	var user, email, credential, account, association bool
	err := repo.pool.Raw().QueryRow(ctx, `SELECT
EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2),
EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2),
EXISTS(SELECT 1 FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),
EXISTS(SELECT 1 FROM identity.accounts WHERE tenant_id=$1 AND user_id=$2),
EXISTS(SELECT 1 FROM identity.account_credentials WHERE tenant_id=$1 AND user_id=$2)`, string(a.TenantID), string(a.UserID)).Scan(&user, &email, &credential, &account, &association)
	if err != nil || user != want || email != want || credential != want || account != want || association != want {
		t.Fatalf("partial JIT identity: user=%t email=%t credential=%t account=%t association=%t, want=%t: %v", user, email, credential, account, association, want, err)
	}
	if !want {
		return
	}
	var exactEmail, exactReference bool
	err = repo.pool.Raw().QueryRow(ctx, `SELECT
EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND kind='email'
AND canonical_value=$4 AND display_value=$4 AND verified AND NOT is_primary AND version=1 AND verification_state=2
AND verification_version=1 AND verified_at IS NOT NULL AND normalization_profile=$5 AND normalization_version=1),
EXISTS(SELECT 1 FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$6 AND enabled AND expires_at IS NULL)`,
		string(a.TenantID), string(a.UserID), string(i.ID), i.CanonicalValue, i.NormalizationProfile, id).Scan(&exactEmail, &exactReference)
	if err != nil || !exactEmail || !exactReference {
		t.Fatal("verified mailbox or enabled credential did not retain exact initial state", err)
	}
	got, err := repo.GetSSOOIDCSigninAccount(ctx, ProviderSigninAccountQuery{TenantID: a.TenantID, Provider: a.Provider, Issuer: a.Issuer, Subject: a.Subject})
	if err != nil || got != intent.Account {
		t.Fatal("committed account cannot be used by the existing linked-signin owner", err)
	}
}
