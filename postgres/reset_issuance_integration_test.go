//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This exercises real primary fencing, anonymous command preservation and
// atomic issuer/audit/lifecycle persistence. The SQL issuer is a kernel test
// seam, not the production issuer or complete reset/factor/delivery workflow.
type resetSelectionNative struct {
	resetIssuancePhase
	recipient  RecipientRecord
	credential CredentialAdmission
	issuer     *issuanceSQLPhase
	grant      capability.Grant
	skipFence  bool
}

type resetSelectionAudit struct{ recoveryAuditPhase }

func (p *resetSelectionAudit) PersistAudits(ctx context.Context, w Work) error {
	if err := p.recoveryAuditPhase.PersistAudits(ctx, w); err != nil {
		return err
	}
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_reset_selection_audit(command_id,succeeded) VALUES($1,$2)`, string(w.state.binding.CommandID), record.Record.Outcome() == audit.OutcomeSucceeded); err != nil {
			return err
		}
	}
	return nil
}

func (p *resetSelectionNative) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	s, ok := c.Feature()
	if !ok || !passwordResetRequestOperation(s.Operation) || plan.CapabilityIssuance == nil || !validResetRecipientIssuance(s.Binding, plan) {
		return invalidPlan()
	}
	return nil
}

func (p *resetSelectionNative) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if !p.skipFence {
		if _, err := w.RequireRecipientCredential(ctx, p, p.recipient, p.credential); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if after, _, _, err := w.FeatureScope(p); err != nil || after != b || b.UserID != "" {
		return identity.FeatureReceipt{}, invalidWork()
	}
	if err := w.StageCapabilityIssuanceFor(p.issuer, 0, p.grant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.Feature()
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}

func (*resetSelectionNative) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func testResetRecipientIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	var installed bool
	if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity.credential_references') IS NOT NULL`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		if _, err := pool.Raw().Exec(ctx, statusSchemaSQL+credentialSchemaSQL); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_reset_selection_audit(command_id text PRIMARY KEY,succeeded boolean NOT NULL);
CREATE TABLE IF NOT EXISTS public.identity_test_issuance(command_id text UNIQUE NOT NULL,capability_id text PRIMARY KEY,proof_fingerprint bytea NOT NULL,replay_digest bytea NOT NULL,generation numeric NOT NULL);
INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('reset-selection','existing-user','active',101,2,3,4);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('reset-selection','existing-user','email','email','reset-selection@example.test',true,true,7,2,1,clock_timestamp());
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('reset-selection','existing-user','password',1,'identity/password',5,true)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-fence", "stale-credential", "stale-identifier", "blocked-user", "wrong-subject", "wrong-origin", "wrong-identifier", "issuer-failure", "lifecycle-failure"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='reset-selection'; UPDATE identity.credential_references SET version=5 WHERE tenant_id='reset-selection'; UPDATE identity.identifiers SET version=7 WHERE tenant_id='reset-selection'`); err != nil {
				t.Fatal(err)
			}
			r, err := repo.ResolveRecipient(ctx, RecipientQuery{TenantID: "reset-selection", Kind: identity.IdentifierEmail, CanonicalValue: "reset-selection@example.test", Eligibility: RecipientVerified})
			if err != nil || r.Suppressed {
				t.Fatal("recipient snapshot unavailable", err)
			}
			b, _, plan := resetIssuanceFixture(t)
			b.TenantID = "reset-selection"
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b.AnonymousFlowID = string(b.CommandID)
			issuer := &issuanceSQLPhase{}
			if mode == "issuer-failure" {
				issuer.mode = "error"
			}
			phase := &resetSelectionNative{resetIssuancePhase: resetIssuancePhase{operation: plan.Feature.Operation}, recipient: r, credential: CredentialAdmission{Credential: identity.CredentialRef{ID: "password", TenantID: b.TenantID, UserID: r.User.ID, Owner: "identity/password", Kind: identity.CredentialPassword, Version: 5}, UserAuthorityVersion: 2, IdentifierAuthorityVersion: 3, CredentialAuthorityVersion: 4}, issuer: issuer, skipFence: mode == "missing-fence"}
			auditing, lifecycle := &resetSelectionAudit{}, &recoveryLifecyclePhase{}
			lifecycle.fail = mode == "lifecycle-failure"
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle, phase, issuer})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			payload := capability.Payload{Version: 1, ID: string(b.CommandID), Issuer: "https://reset.test", Audiences: []string{"identity"}, Subject: string(r.User.ID), Tenant: string(b.TenantID), Resource: "identity.password/password", Operation: "identity.password.reset-complete", CorrelationID: string(b.CommandID), IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1, Caveats: map[string]string{"password.identifier": "email", "password.identifier-version": "7", "password.credential-version": "5", "password.credential-authority-version": "4", "password.user-authority-version": "2"}}
			switch mode {
			case "wrong-subject":
				payload.Subject = "other-user"
			case "wrong-origin":
				payload.CorrelationID = "other-command"
			case "wrong-identifier":
				payload.Caveats["password.identifier"] = "other-email"
			case "stale-credential":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET version=6 WHERE tenant_id='reset-selection'`)
			case "stale-identifier":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=8 WHERE tenant_id='reset-selection'`)
			case "blocked-user":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id='reset-selection'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			key := []byte("0123456789abcdef0123456789abcdef")
			signer, err := capability.NewHMACSHA256Signer("reset-selection", key)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := capability.NewHMACSHA256Verifier(key)
			if err != nil {
				t.Fatal(err)
			}
			token, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal("synthetic signing", err)
			}
			phase.grant, err = capability.Verify(ctx, token, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
				return capability.ResolvedKey{Verifier: verifier}, nil
			}), capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
			if err != nil {
				t.Fatal("synthetic verification", err)
			}
			plan.CapabilityIssuance.Grants[0].CapabilityID = payload.ID
			plan.CapabilityIssuance.Grants[0].ExpiresAt = payload.ExpiresAt
			plan.CapabilityIssuance.Grants[0].ProofFingerprint = phase.grant.EnvelopeDigest()
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: phase.operation, Fields: []identity.FeatureField{{Name: "request", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-selected-reset"}}}})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = registry.Descriptors()
			seed, err := securityMutationAudit(ctx, b, 0, 0, now, "committed", plan.Audits[0].EventType, plan.SubjectType, b.AnonymousFlowID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, phase.operation, plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal("reset selection preparation", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal("reset selection reservation", err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal("reset selection begin", err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			result, executionErr := coordinator.ApplyFeature(ctx, work, command)
			if executionErr == nil {
				result, executionErr = coordinator.Commit(work, result)
			} else {
				_, _ = coordinator.Abort(work, executionErr)
			}
			want := 0
			if mode == "commit" {
				if executionErr != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("reset selection commit", executionErr)
				}
				want = 1
				if issuer.binding.Command != b || issuer.binding.Plan.ResetRecipientUserID != r.User.ID || issuer.binding.Command.UserID != "" {
					t.Fatal("issuer changed original anonymous command")
				}
				_, replay, err := coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || issuer.invocations != 1 {
					t.Fatal("reset replay reissued", err)
				}
			} else if executionErr == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("denied reset selection committed")
			}
			var issued, audited, outboxed, recorded int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_issuance WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_reset_selection_audit WHERE command_id=$1 AND succeeded),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_reset_selection_audit WHERE command_id=$1)`, string(b.CommandID)).Scan(&issued, &audited, &outboxed, &recorded); err != nil || issued != want || audited != want || outboxed != want || recorded != 1 {
				t.Fatalf("reset atomic effects %d/%d/%d and audit records %d: %v", issued, audited, outboxed, recorded, err)
			}
		})
	}
}
