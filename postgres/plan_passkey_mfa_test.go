package postgres

import (
	"bytes"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func passkeyMFAPlanFixture(t testing.TB) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b := codecBinding()
	b.UserID = "factor-user"
	b.RecordID = string(b.CommandID)
	b.OperationID, b.SchemaID = "identity.passkey.signin-verify", "identity.passkey.signin-verify.native-v1"
	b.ActorID, b.ActorKind = identity.ActorID(b.UserID), authorization.SubjectUser
	expires := time.Unix(1800000000, 0).UTC()
	owner := ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
	p := CommandPlan{
		Feature:            &FeatureRegistration{Contributor: owner, Operation: identity.FeatureOperation{Owner: "passkey", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}},
		Contributors:       []ContributorDescriptor{(&Repository{}).Descriptor(), {Owner: "audit/postgres", ContractID: "audit.records", Version: 1}, {Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, owner},
		SubjectType:        "authentication_attempt",
		Lifecycle:          &LifecyclePlan{EventType: "mfa.challenge.created.v1", AfterVersion: 1},
		Audits:             []AuditPlan{{EventType: "authentication.succeeded", SchemaVersion: 1, BindingDigest: [32]byte{1}, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}},
		MFAContinuation:    &MFAContinuationPlan{ID: "AQEBAQEBAQEBAQEBAQEBAQ", UserID: b.UserID, ScopeDigest: [32]byte{7}, PolicyVersion: 2, FactorVersion: 3, IssuedAt: expires.Add(-time.Minute), ExpiresAt: expires},
		CapabilityIssuance: issuanceTestPlan(),
	}
	p.CapabilityIssuance.MFAContinuationUserID = b.UserID
	p.CapabilityIssuance.Grants[0].CapabilityID = string(p.MFAContinuation.ID)
	p.CapabilityIssuance.Grants[0].Purpose = "identity.mfa.complete"
	p.CapabilityIssuance.Grants[0].ExpiresAt = expires
	p.Contributors = append(p.Contributors, p.CapabilityIssuance.Contributor)
	return b, p
}

func TestPasskeyMFAPlanRetainsOriginalChallengeWithoutSession(t *testing.T) {
	b, p := passkeyMFAPlanFixture(t)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal("verified passkey primary cannot declare independent-factor challenge", err)
	}
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || got.MFAContinuation == nil || *got.MFAContinuation != *p.MFAContinuation || got.Capability != nil || got.CapabilityIssuance == nil || got.CapabilityIssuance.Grants[0] != p.CapabilityIssuance.Grants[0] || got.Lifecycle.EventType != "mfa.challenge.created.v1" {
		t.Fatal("passkey origin, continuation or challenge-only lifecycle lost", err)
	}
	again, err := encodeFeaturePlan(b, [32]byte{1}, got)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("passkey challenge is not canonical", err)
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated passkey challenge accepted")
		}
	}
	for _, source := range []func(*testing.T) (identity.CommandBinding, CommandPlan){passwordMFAPlanFixture, verificationMFAPlanFixture} {
		foreign, _ := source(t)
		if _, err := decodeFeaturePlan(foreign, [32]byte{1}, wire); err == nil {
			t.Fatal("passkey challenge relabeled as another primary")
		}
	}
}

func TestPasskeyMFAPlanRejectsForeignOrSessionProducingScope(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"missing subject":              func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "" },
		"anonymous override":           func(b *identity.CommandBinding, _ *CommandPlan) { b.AnonymousFlowID = "foreign-flow" },
		"foreign actor":                func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorID = "foreign-actor" },
		"service attribution":          func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectServiceAccount },
		"foreign record":               func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "AgICAgICAgICAgICAgICAg" },
		"foreign selected user":        func(_ *identity.CommandBinding, p *CommandPlan) { p.MFAContinuation.UserID = "foreign-user" },
		"premature session":            func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" },
		"synthetic primary capability": func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"foreign child": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.MFAContinuationUserID = "foreign-user"
		},
		"zero policy":   func(_ *identity.CommandBinding, p *CommandPlan) { p.MFAContinuation.PolicyVersion = 0 },
		"zero factor":   func(_ *identity.CommandBinding, p *CommandPlan) { p.MFAContinuation.FactorVersion = 0 },
		"foreign owner": func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Contributor.Owner = "foreign/postgres" },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := passkeyMFAPlanFixture(t)
			change(&b, &p)
			if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
				t.Fatal("foreign or session-producing challenge admitted")
			}
		})
	}
}

func TestPasskeyMFAPlanFreezesGeneratedOriginalScope(t *testing.T) {
	b, final := passkeyMFAPlanFixture(t)
	original := final
	original.CapabilityIssuance = nil
	original.Contributors = append([]ContributorDescriptor(nil), final.Contributors[:len(final.Contributors)-1]...)
	original.MFAContinuation = &MFAContinuationPlan{UserID: b.UserID, PolicyVersion: final.MFAContinuation.PolicyVersion, FactorVersion: final.MFAContinuation.FactorVersion}
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("journal-owned child generation cannot finish passkey preparation")
	}
	changed := final
	changed.MFAContinuation = cloneMFAContinuationPlan(final.MFAContinuation)
	changed.MFAContinuation.FactorVersion++
	if preparationFinalDeclaration(b, original, changed) {
		t.Fatal("generated challenge borrowed a newer factor epoch")
	}
}

func FuzzPasskeyMFAPlan(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa5})
	b, p := passkeyMFAPlanFixture(f)
	// A valid seed reaches the actual new closed envelope, not just rejection.
	if wire, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
		f.Add(wire)
	} else {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65536 {
			return
		}
		b, _ := passkeyMFAPlanFixture(t)
		got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err == nil {
			canonical, err := encodeFeaturePlan(b, [32]byte{1}, got)
			if err != nil || !bytes.Equal(canonical, wire) {
				t.Fatal("accepted noncanonical passkey challenge", err)
			}
		}
	})
}
