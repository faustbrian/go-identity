//go:build integration

package postgres

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This native SQL seam proves coordinator consumption/continuation/issuance
// atomicity. It is not the real MFA factor store, primary verifier, capability
// producer or a public login journey. Child grants use actual signing/Verify.
type magicLinkMFAAtomicPhase struct {
	magicLinkConsumptionPhase
	challenge MFAContinuationPlan
	issuer    *issuanceSQLPhase
	grant     capability.Grant
}

func (p *magicLinkMFAAtomicPhase) ValidateMagicLinkMFAChallenge(c identity.Command, m MFAContinuationPlan) error {
	if c != p.expected || m != p.challenge {
		return invalidPlan()
	}
	return nil
}
func (p *magicLinkMFAAtomicPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	m, err := w.MagicLinkMFAChallenge(p)
	if err != nil || m != p.challenge {
		return identity.FeatureReceipt{}, invalidWork()
	}
	if _, err := w.MagicLinkMFAChallenge(&magicLinkMFAAtomicPhase{}); err == nil {
		return identity.FeatureReceipt{}, invalidWork()
	}
	p.retained = w
	if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_magic_mfa(command_id,continuation_id,scope_digest) VALUES($1,$2,$3)`, string(w.state.binding.CommandID), string(m.ID), m.ScopeDigest[:]); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := w.StageCapabilityIssuanceFor(p.issuer, 0, p.grant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.failApply {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: magicLinkConsumeOperation()}, nil
}
func (p *magicLinkMFAAtomicPhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if c != p.expected {
		return invalidWork()
	}
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	if _, err := w.MagicLinkMFAChallenge(p); err == nil {
		return invalidWork()
	}
	if p.failCommit {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (*magicLinkMFAAtomicPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_magic_mfa")
}

func testMagicLinkMFAChallenge(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_magic_mfa(command_id text PRIMARY KEY,continuation_id text UNIQUE NOT NULL,scope_digest bytea NOT NULL);
CREATE TABLE IF NOT EXISTS public.identity_test_issuance(command_id text UNIQUE NOT NULL,capability_id text PRIMARY KEY,proof_fingerprint bytea NOT NULL,replay_digest bytea NOT NULL,generation numeric NOT NULL);
CREATE TABLE IF NOT EXISTS identity.capability_recovery_fixture(tenant_id text NOT NULL,purpose text NOT NULL,capability_id text PRIMARY KEY,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"original-no-child", "commit", "apply-denied", "commit-denied", "issuer-failure", "outbox-failure", "finalize-failure", "signed-scope-substitution", "signed-foreign-subject", "signed-foreign-tenant", "signed-foreign-resource", "signed-foreign-profile", "signed-issue-time", "signed-extra-caveat"} {
		t.Run(mode, func(t *testing.T) {
			b, p := magicLinkMFAPlanFixture(t)
			var err error
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			p.MFAContinuation.ID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			p.Capability.CapabilityID = "magic-mfa-parent-" + mode
			p.Capability.ExpiresAt = now.Add(10 * time.Minute)
			p.MFAContinuation.IssuedAt, p.MFAContinuation.ExpiresAt = now, now.Add(5*time.Minute)
			payload := capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"identity"}, Subject: string(p.MFAContinuation.UserID), Resource: "mfa/continuations/" + string(p.MFAContinuation.ID), Operation: "identity.mfa.complete", IssuedAt: now, NotBefore: now, ExpiresAt: p.MFAContinuation.ExpiresAt, ID: string(p.MFAContinuation.ID), Tenant: string(b.TenantID), MaxUses: 1, Caveats: map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": hex.EncodeToString(p.MFAContinuation.ScopeDigest[:])}}
			switch mode {
			case "signed-scope-substitution":
				payload.Caveats["mfa.scope"] = hex.EncodeToString(make([]byte, 32))
			case "signed-foreign-subject":
				payload.Subject = "other-subject"
			case "signed-foreign-tenant":
				payload.Tenant = "other-tenant"
			case "signed-foreign-resource":
				payload.Resource = "session/continuations/" + payload.ID
			case "signed-foreign-profile":
				payload.Caveats["mfa.profile"] = "identity-session-v1"
			case "signed-issue-time":
				payload.IssuedAt = payload.IssuedAt.Add(-time.Second)
			case "signed-extra-caveat":
				payload.Caveats["other.scope"] = "unbound"
			}
			key := make([]byte, 32)
			for i := range key {
				key[i] = 9
			}
			signer, err := capability.NewHMACSHA256Signer("mfa-test-key", key)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := capability.NewHMACSHA256Verifier(key)
			if err != nil {
				t.Fatal(err)
			}
			token, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			grant, err := capability.Verify(ctx, token, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
				return capability.ResolvedKey{Verifier: verifier}, nil
			}), capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
			if err != nil {
				t.Fatal(err)
			}
			p.CapabilityIssuance.Grants[0].CapabilityID, p.CapabilityIssuance.Grants[0].ExpiresAt, p.CapabilityIssuance.Grants[0].ProofFingerprint = payload.ID, payload.ExpiresAt, grant.EnvelopeDigest()
			issuer := &issuanceSQLPhase{}
			if mode == "issuer-failure" {
				issuer.mode = "error"
			}
			native := &magicLinkMFAAtomicPhase{magicLinkConsumptionPhase: magicLinkConsumptionPhase{proof: *p.Capability, failApply: mode == "apply-denied", failCommit: mode == "commit-denied"}, challenge: *p.MFAContinuation, issuer: issuer, grant: grant}
			registry, err := NewContributorRegistry([]Contributor{repo, &recoveryAuditPhase{}, &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}, native, &emailVerificationCounterPhase{}, &emailVerificationCapabilityPhase{failFinalize: mode == "finalize-failure"}, issuer})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: magicLinkConsumeOperation(), Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}}}})
			native.expected = command
			p.Contributors = registry.Descriptors()
			if mode == "original-no-child" {
				p.CapabilityIssuance = nil
				p.Contributors = p.Contributors[:len(p.Contributors)-1]
			}
			seed, err := securityMutationAudit(ctx, b, 0, 0, now, "committed", p.Audits[0].EventType, p.SubjectType, b.AnonymousFlowID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, magicLinkConsumeOperation(), p.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			p, err = coordinator.PrepareCommandPlan(b, command, p)
			if err != nil {
				t.Fatal("challenge declaration", err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.capability_recovery_fixture VALUES($1,$2,$3,$4,'issued',NULL,NULL,NULL)`, string(b.TenantID), string(p.Capability.Purpose), p.Capability.CapabilityID, p.Capability.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			r, _, err := coordinator.ReserveCommand(ctx, b, command, p)
			if err != nil {
				t.Fatal("challenge reservation", err)
			}
			w, err := coordinator.Begin(ctx, r)
			if mode == "original-no-child" {
				if err == nil {
					coordinator.Abort(w, identity.UnavailableError{})
					t.Fatal("preparation without a child entered domain work")
				}
				if r.state.started.Load() {
					t.Fatal("incomplete declaration consumed domain start")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			result, err := coordinator.ApplyFeature(ctx, w, command)
			if err == nil {
				result, err = coordinator.Commit(w, result)
			}
			if mode == "commit" {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("challenge did not commit", err)
				}
			} else if err == nil {
				t.Fatal("denied challenge committed")
			}
			coordinator.Abort(w, identity.UnavailableError{})
			var continuations, children, events int
			var parent string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_magic_mfa WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_issuance WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1),(SELECT state FROM identity.capability_recovery_fixture WHERE capability_id=$2)`, string(b.CommandID), p.Capability.CapabilityID).Scan(&continuations, &children, &events, &parent); err != nil {
				t.Fatal(err)
			}
			if mode == "commit" {
				if continuations != 1 || children != 1 || events != 1 || parent != "finalized" {
					t.Fatal("split challenge transaction")
				}
			} else if continuations != 0 || children != 0 || events != 0 || parent == "consuming" || parent == "finalized" {
				t.Fatal("denial retained protected challenge effects")
			}
			if _, err := native.retained.MagicLinkMFAChallenge(native); err == nil {
				t.Fatal("returned invocation retained challenge custody")
			}
			if mode == "commit" {
				q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
				recovered, recoverErr := coordinator.recoverCommandReceipt(ctx, q)
				if recoverErr != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("durable challenge receipt could not be recovered", recoverErr)
				}
				if replay, receipt, err := coordinator.ReserveCommand(ctx, b, command, p); err != nil || replay.state != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("committed replay obtained another domain transaction", err)
				}
				other := b
				other.CommandID, err = identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				spec, _ := command.Feature()
				spec.Binding = other
				competing := featureCodecCommand(t, spec)
				native.expected = competing
				otherPlan := p
				otherPlan.Audits = append([]AuditPlan(nil), p.Audits...)
				seed, err := securityMutationAudit(ctx, other, 0, 0, now, "committed", p.Audits[0].EventType, p.SubjectType, other.AnonymousFlowID, "protected", true)
				if err != nil {
					t.Fatal(err)
				}
				otherPlan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(other, magicLinkConsumeOperation(), p.SubjectType, seed)
				if err != nil {
					t.Fatal(err)
				}
				otherPlan, err = coordinator.PrepareCommandPlan(other, competing, otherPlan)
				if err != nil {
					t.Fatal(err)
				}
				if replay, _, err := coordinator.ReserveCommand(ctx, other, competing, otherPlan); err == nil || replay.state != nil {
					t.Fatal("same primary proof admitted another challenge")
				}
				native.expected = command
				var childrenAfter, continuationsAfter int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_issuance WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_magic_mfa WHERE command_id=$1)`, string(b.CommandID)).Scan(&childrenAfter, &continuationsAfter); err != nil || childrenAfter != 1 || continuationsAfter != 1 {
					t.Fatal("replay or competitor changed original challenge effects", err)
				}
			}
		})
	}
}
