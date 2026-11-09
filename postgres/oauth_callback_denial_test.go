package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func oauthDenialPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := emailVerificationPlanFixture(t)
	op := oauthCallbackDenialOperation()
	b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
	b.ActorKind, b.ActorID, b.RecordID = authorization.SubjectUser, identity.ActorID(b.UserID), "original-rp-transaction"
	p.Feature.Operation, p.Feature.Contributor = op, oauthCallbackDenialDescriptor()
	p.Contributors[3] = p.Feature.Contributor
	p.Contributors = append(p.Contributors[:4], p.Contributors[5])
	p.CommandCounters, p.SubjectType = nil, "oauth_transaction"
	p.Capability.Purpose = "identity.oauth.callback"
	p.Lifecycle = &LifecyclePlan{EventType: "oauth.rp_transaction.denied.v1", BeforeVersion: 1, AfterVersion: 2}
	p.Audits[0].EventType, p.Audits[0].RetentionClass = "identity.oauth.handle_callback", "standard"
	return b, p
}

func TestOAuthCallbackDenialPreservesOriginalConsumptionAndClosedHistory(t *testing.T) {
	b, p := oauthDenialPlanFixture(t)
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal("terminal provider-error profile unavailable", err)
	}
	restored, err := decodeFeaturePlan(b, fp, wire)
	if err != nil || restored.Capability == nil || *restored.Capability != *p.Capability || restored.Digest != sha256.Sum256(wire) || restored.Feature == nil || *restored.Feature != *p.Feature {
		t.Fatal("denial lost the original state or terminal operation", err)
	}
	for n := range wire {
		if _, err := decodeFeaturePlan(b, fp, wire[:n]); err == nil {
			t.Fatalf("truncated terminal callback admitted at %d", n)
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(wire), 0), cborMap(map[string][]byte{"base": cborBytes(wire), "profile": cborText("identity-oauth-callback-denial-v1"), "version": cborUint(1), "capability": encodeCapabilityPlan(p.Capability), "contributor": cborMap(map[string][]byte{})})} {
		if _, err := decodeFeaturePlan(b, fp, bad); err == nil {
			t.Fatal("noncanonical or recursive callback history admitted")
		}
	}
	other := b
	other.TenantID = "foreign"
	if _, err := decodeFeaturePlan(other, fp, wire); err == nil {
		t.Fatal("foreign callback history admitted")
	}
	base := p
	base.Capability, base.Contributors = nil, p.Contributors[:4]
	if _, err := encodeFeaturePlan(b, fp, base); err == nil {
		t.Fatal("proof-free denial exposed as execution profile")
	}
}

func TestOAuthCallbackDenialCannotBecomeIdentityOrIssuance(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"missing proof":    func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability = nil },
		"foreign purpose":  func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.Purpose = "identity.account.link-token" },
		"multiple uses":    func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.MaxUses = 2 },
		"unknown proof":    func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.ProofFingerprint = [32]byte{} },
		"other user actor": func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorID = "other" },
		"anonymous":        func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID, b.AnonymousFlowID = "", "flow" },
		"subject":          func(_ *identity.CommandBinding, p *CommandPlan) { p.SubjectType = "user" },
		"new issuance":     func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		"new delivery":     func(_ *identity.CommandBinding, p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"false lifecycle":  func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" },
		"new transaction": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = 0, 1
		},
		"false audit": func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].EventType = "identity.session.issue" },
		"foreign owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "other"
			p.Contributors[3] = p.Feature.Contributor
		},
		"future schema": func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Operation.SchemaVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := oauthDenialPlanFixture(t)
			change(&b, &p)
			if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
				t.Fatal("foreign denial declaration admitted")
			}
		})
	}
}

func TestOAuthCallbackDenialAuditRecordsDenialAndRealErasure(t *testing.T) {
	b, p := oauthDenialPlanFixture(t)
	plan := &admittedKernelPlan{binding: b, feature: p.Feature, lifecycle: p.Lifecycle, audits: p.Audits, subjectType: p.SubjectType}
	records, err := featureMutationAudits(context.Background(), plan, time.Unix(1700000000, 0).UTC(), "committed")
	if err != nil || len(records) != 1 {
		t.Fatal("denial audit unavailable", err)
	}
	r := records[0]
	if r.Action() != "identity.oauth.handle_callback" || r.Attributes()["retention.class"] != "standard" || r.Outcome() != audit.OutcomeDenied || r.ReasonCode() != "provider_denied" || !r.Changes().Redacted() || r.Attributes()["aggregate.before_version"] != "1" || r.Attributes()["aggregate.after_version"] != "2" {
		t.Fatal("provider refusal reported as authentication success or no erasure")
	}
	if _, err := securityMutationAudit(context.Background(), b, 1, 2, time.Unix(1700000000, 0).UTC(), "provider-denied", b.OperationID, "oauth_transaction", b.RecordID, "protected", false); err == nil {
		t.Fatal("generic mutation borrowed terminal provider-error audit semantics")
	}
}

func TestOAuthCallbackDenialLifecycleIsErasureNotSigninSuccess(t *testing.T) {
	w, _, _ := auditFixture(t)
	b, p := oauthDenialPlanFixture(t)
	w.state.binding, w.state.feature, w.state.subjectType = b, p.Feature, p.SubjectType
	now := time.Now().UTC().Truncate(time.Microsecond)
	plan := &admittedKernelPlan{binding: b, feature: p.Feature, lifecycle: p.Lifecycle, audits: p.Audits, subjectType: p.SubjectType}
	records, err := featureMutationAudits(w.state.ctx, plan, now, "committed")
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, p.Feature.Operation, p.SubjectType, records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := bindAuditPlans(w, p.Audits); err != nil {
		t.Fatal(err)
	}
	if err := w.StageAudit(0, records[0]); err != nil {
		t.Fatal(err)
	}
	if err := bindLifecyclePlan(w, p.Lifecycle); err != nil {
		t.Fatal(err)
	}
	if err := w.StageLifecycle(0, now); err != nil {
		t.Fatal(err)
	}
	events, err := w.StagedLifecycle()
	if err != nil || len(events) != 1 || events[0].EventType != "oauth.rp_transaction.denied.v1" || events[0].BeforeVersion != 1 || events[0].AfterVersion != 2 {
		t.Fatal("truthful denial audit prevented the actual atomic erasure lifecycle", err)
	}
}

func FuzzOAuthCallbackDenialHistory(f *testing.F) {
	b := recordBinding("identity.oauth.callback", "identity.oauth.callback.denied-v1", "original-rp")
	b.ActorKind, b.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
	feature := FeatureRegistration{Contributor: oauthCallbackDenialDescriptor(), Operation: oauthCallbackDenialOperation()}
	p := CommandPlan{
		Feature: &feature, SubjectType: "oauth_transaction",
		Contributors: []ContributorDescriptor{
			{Owner: "identity/postgres", ContractID: "identity.directory", Version: 1},
			{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1},
			{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, feature.Contributor,
			{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1},
		},
		Audits:     []AuditPlan{{EventType: "identity.oauth.handle_callback", SchemaVersion: 1, BindingDigest: [32]byte{1}, RetentionClass: "standard", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}},
		Lifecycle:  &LifecyclePlan{EventType: "oauth.rp_transaction.denied.v1", BeforeVersion: 1, AfterVersion: 2},
		Capability: &CapabilityPlan{CapabilityID: "state", Purpose: "identity.oauth.callback", ReplayDigest: [32]byte{2}, ReplayKeyVersion: 1, ProofFingerprint: [32]byte{3}, ExpiresAt: time.Unix(1700000000, 0).UTC(), MaxUses: 1},
	}
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(nil))
	f.Add(wire[:len(wire)/2])
	f.Add(bytes.Repeat([]byte{0xa5}, 65537))
	f.Fuzz(func(t *testing.T, input []byte) {
		out, err := decodeFeaturePlan(b, fp, input)
		if err != nil {
			if out.Feature != nil || out.Capability != nil || out.Digest != ([32]byte{}) {
				t.Fatal("invalid history leaked a partial declaration")
			}
			return
		}
		canonical, err := encodeFeaturePlan(b, fp, out)
		if err != nil || !bytes.Equal(input, canonical) || out.Digest != sha256.Sum256(input) {
			t.Fatal("accepted history changed original consumption intent")
		}
	})
}
