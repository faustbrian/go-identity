//go:build integration

package postgres

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// The SQL issuer is the existing kernel test seam. This does not certify the
// production signer, encrypted delivery, factor policy or complete login.
type magicLinkSelectionNative struct {
	magicLinkIssuancePhase
	recipient RecipientRecord
	issuer    *issuanceSQLPhase
	grant     capability.Grant
	skipFence bool
}

func (p *magicLinkSelectionNative) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	s, ok := c.Feature()
	if !ok || !magicLinkRequestOperation(s.Operation) || plan.CapabilityIssuance == nil || !validMagicLinkRecipientIssuance(s.Binding, plan) {
		return invalidPlan()
	}
	return nil
}

func (p *magicLinkSelectionNative) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if !p.skipFence {
		if err := w.RequireMagicLinkRecipient(ctx, p, p.recipient); err != nil {
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

func testMagicLinkRecipientIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
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
CREATE TABLE IF NOT EXISTS public.identity_test_reset_selection_audit(command_id text PRIMARY KEY,succeeded boolean NOT NULL);
CREATE TABLE IF NOT EXISTS public.identity_test_issuance(command_id text UNIQUE NOT NULL,capability_id text PRIMARY KEY,proof_fingerprint bytea NOT NULL,replay_digest bytea NOT NULL,generation numeric NOT NULL);
INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('magic-selection','existing-user','active',101,2,3,4);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('magic-selection','existing-user','email','email','magic-selection@example.test',true,true,7,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-fence", "stale-identifier", "stale-verification", "stale-user-authority", "stale-credential-authority", "blocked-user", "wrong-subject", "wrong-origin", "wrong-canonical-email", "issuer-failure", "lifecycle-failure"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active',authority_version=2,credential_version=4 WHERE tenant_id='magic-selection'; UPDATE identity.identifiers SET version=7,verification_version=1 WHERE tenant_id='magic-selection'`); err != nil {
				t.Fatal(err)
			}
			r, err := repo.ResolveRecipient(ctx, RecipientQuery{TenantID: "magic-selection", Kind: identity.IdentifierEmail, CanonicalValue: "magic-selection@example.test", Eligibility: RecipientVerified})
			if err != nil || r.Suppressed {
				t.Fatal("recipient unavailable", err)
			}
			b, _, plan := magicLinkIssuanceFixture(t)
			b.TenantID = r.Query.TenantID
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b.AnonymousFlowID = string(b.CommandID)
			issuer := &issuanceSQLPhase{}
			if mode == "issuer-failure" {
				issuer.mode = "error"
			}
			phase := &magicLinkSelectionNative{magicLinkIssuancePhase: magicLinkIssuancePhase{resetIssuancePhase{operation: plan.Feature.Operation}}, recipient: r, issuer: issuer, skipFence: mode == "missing-fence"}
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
			payload := capability.Payload{Version: 1, ID: string(b.CommandID), Issuer: "https://magic.test", Audiences: []string{"identity"}, Subject: string(r.User.ID), Tenant: string(b.TenantID), Resource: "identity.magiclink/" + string(r.Identifier.ID), Operation: "identity.magic-link.consume", CorrelationID: string(b.CommandID), IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1, Caveats: map[string]string{"magiclink.identifier": string(r.Identifier.ID), "magiclink.identifier-version": strconv.FormatUint(r.Identifier.Version, 10), "magiclink.verification-version": strconv.FormatUint(r.Verification.Version, 10), "magiclink.identifier-authority-version": strconv.FormatUint(r.IdentifierAuthorityVersion, 10), "magiclink.user-authority-version": strconv.FormatUint(r.UserAuthorityVersion, 10), "magiclink.credential-authority-version": strconv.FormatUint(r.CredentialAuthorityVersion, 10), "magiclink.canonical-email": r.Query.CanonicalValue}}
			switch mode {
			case "wrong-subject":
				payload.Subject = "foreign"
			case "wrong-origin":
				payload.CorrelationID = "foreign"
			case "wrong-canonical-email":
				payload.Caveats["magiclink.canonical-email"] = "foreign@example.test"
			case "stale-identifier":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=8 WHERE tenant_id='magic-selection'`)
			case "stale-verification":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verification_version=2 WHERE tenant_id='magic-selection'`)
			case "stale-user-authority":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=3 WHERE tenant_id='magic-selection'`)
			case "stale-credential-authority":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET credential_version=5 WHERE tenant_id='magic-selection'`)
			case "blocked-user":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id='magic-selection'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			key := []byte("0123456789abcdef0123456789abcdef")
			signer, err := capability.NewHMACSHA256Signer("magic-selection", key)
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
			plan.CapabilityIssuance.Grants[0].CapabilityID, plan.CapabilityIssuance.Grants[0].ExpiresAt, plan.CapabilityIssuance.Grants[0].ProofFingerprint = payload.ID, payload.ExpiresAt, phase.grant.EnvelopeDigest()
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: phase.operation, Fields: []identity.FeatureField{{Name: "request", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-selected-magiclink"}}}})
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
				t.Fatal("magic-link preparation", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal("magic-link reservation", err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal("magic-link begin", err)
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
					t.Fatal("magic-link commit", executionErr)
				}
				want = 1
				if issuer.binding.Command != b || issuer.binding.Plan.MagicLinkRecipientUserID != r.User.ID || issuer.binding.Command.UserID != "" {
					t.Fatal("issuer changed anonymous command")
				}
				_, replay, err := coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || issuer.invocations != 1 {
					t.Fatal("replay reissued", err)
				}
			} else if executionErr == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("denied magic-link selection committed")
			}
			var issued, audited, outboxed int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_issuance WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_reset_selection_audit WHERE command_id=$1 AND succeeded),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(b.CommandID)).Scan(&issued, &audited, &outboxed); err != nil || issued != want || audited != want || outboxed != want {
				t.Fatalf("atomic magic-link effects %d/%d/%d: %v", issued, audited, outboxed, err)
			}
		})
	}
}
