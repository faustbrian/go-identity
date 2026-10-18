package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func passwordMFAPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := magicLinkMFAPlanFixture(t)
	oldOwner := p.Feature.Contributor
	b.OperationID, b.SchemaID = "identity.password.signin", "password-signin"
	p.Feature.Operation = identity.FeatureOperation{Owner: "identity/password", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	p.Feature.Contributor = ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
	for i, d := range p.Contributors {
		if d == oldOwner {
			p.Contributors[i] = p.Feature.Contributor
		}
	}
	// A password primary is a real comparison, not a consumed capability.
	p.Capability = nil
	p.Contributors = append(p.Contributors[:len(p.Contributors)-2:len(p.Contributors)-2], p.CapabilityIssuance.Contributor)
	p.CommandCounters = nil
	kept := make([]ContributorDescriptor, 0, len(p.Contributors))
	for _, d := range p.Contributors {
		if d != (ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}) {
			kept = append(kept, d)
		}
	}
	p.Contributors = kept
	return b, p
}

func TestPasswordMFAFinalPreparationCannotReplaceOriginalScope(t *testing.T) {
	b, final := passwordMFAPlanFixture(t)
	original := final
	original.CapabilityIssuance = nil
	original.Contributors = append([]ContributorDescriptor(nil), final.Contributors[:len(final.Contributors)-1]...)
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("password child cannot finish original preparation")
	}
	for _, change := range []func(*MFAContinuationPlan){
		func(m *MFAContinuationPlan) { m.UserID = "other" },
		func(m *MFAContinuationPlan) { m.PolicyVersion++ },
		func(m *MFAContinuationPlan) { m.FactorVersion++ },
		func(m *MFAContinuationPlan) { m.ScopeDigest[0]++ },
		func(m *MFAContinuationPlan) { m.ExpiresAt = m.ExpiresAt.Add(time.Second) },
	} {
		changed := final
		changed.MFAContinuation = cloneMFAContinuationPlan(final.MFAContinuation)
		change(changed.MFAContinuation)
		if preparationFinalDeclaration(b, original, changed) {
			t.Fatal("password challenge replaced original scope")
		}
	}
	initial := original
	initial.MFAContinuation = &MFAContinuationPlan{UserID: original.MFAContinuation.UserID, PolicyVersion: original.MFAContinuation.PolicyVersion, FactorVersion: original.MFAContinuation.FactorVersion}
	if !preparationFinalDeclaration(b, initial, final) {
		t.Fatal("password child cannot bind original journal-owned generation")
	}
}

func TestPasswordMFAPlanRejectsMissingScopeAndForeignProfiles(t *testing.T) {
	for name, change := range map[string]func(*CommandPlan){
		"missing challenge":            func(p *CommandPlan) { p.MFAContinuation = nil },
		"synthetic primary capability": func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"session event":                func(p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" },
		"changed child recipient":      func(p *CommandPlan) { p.CapabilityIssuance.MFAContinuationUserID = "other" },
		"recovery recipient union":     func(p *CommandPlan) { p.CapabilityIssuance.ResetRecipientUserID = p.MFAContinuation.UserID },
		"foreign owner":                func(p *CommandPlan) { p.Feature.Contributor.Owner = "other" },
		"missing factor":               func(p *CommandPlan) { p.MFAContinuation.FactorVersion = 0 },
		"excessive expiry":             func(p *CommandPlan) { p.MFAContinuation.ExpiresAt = p.MFAContinuation.IssuedAt.Add(6 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := passwordMFAPlanFixture(t)
			change(&p)
			if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
				t.Fatal("invalid password challenge admitted")
			}
		})
	}
}

func TestPasswordMFAPlanRetainsChallengeWithoutInventingPrimaryCapability(t *testing.T) {
	b, p := passwordMFAPlanFixture(t)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal("password primary cannot declare challenge-only issuance", err)
	}
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || got.Capability != nil || got.MFAContinuation == nil || *got.MFAContinuation != *p.MFAContinuation || got.CapabilityIssuance == nil || got.CapabilityIssuance.Grants[0] != p.CapabilityIssuance.Grants[0] {
		t.Fatal("password challenge changed during recovery", err)
	}
	again, err := encodeFeaturePlan(b, [32]byte{1}, got)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("password challenge history is not canonical", err)
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated password challenge accepted", i)
		}
	}
}

func TestUsernameMFAChallengeRetainsOriginalAction(t *testing.T) {
	b, p := passwordMFAPlanFixture(t)
	b.OperationID, b.SchemaID = "identity.username.signin", "username-signin"
	p.Feature.Operation.Owner = "identity/username"
	p.Feature.Operation.OperationID, p.Feature.Operation.SchemaID = b.OperationID, b.SchemaID
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal("username password comparison cannot prepare its original MFA challenge", err)
	}
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || got.Feature == nil || got.Feature.Operation != p.Feature.Operation || got.MFAContinuation == nil || *got.MFAContinuation != *p.MFAContinuation {
		t.Fatal("username MFA challenge cannot recover its exact original operation", err)
	}
	if !bytes.Contains(wire, []byte("identity-username-mfa-challenge-v1")) {
		t.Fatal("username challenge reused a different origin's stored profile")
	}
	foreign := b
	foreign.OperationID, foreign.SchemaID = "identity.password.signin", "password-signin"
	if _, err := decodeFeaturePlan(foreign, [32]byte{1}, wire); err == nil {
		t.Fatal("username challenge was reinterpreted as email-password signin")
	}
	for _, origin := range []string{"password", "magic-link", "email-verification"} {
		changed := bytes.ReplaceAll(wire, []byte("identity-username-mfa-challenge-v1"), []byte("identity-"+origin+"-mfa-challenge-v1"))
		if _, err := decodeFeaturePlan(b, [32]byte{1}, changed); err == nil {
			t.Fatal("changed origin profile was accepted", origin)
		}
	}
}

func FuzzUsernameMFAOriginalChallenge(f *testing.F) {
	f.Add(uint32(0), byte(0))
	f.Add(uint32(1), byte(255))
	f.Fuzz(func(t *testing.T, index uint32, change byte) {
		b, p := passwordMFAPlanFixture(t)
		b.OperationID, b.SchemaID = "identity.username.signin", "username-signin"
		p.Feature.Operation.Owner = "identity/username"
		p.Feature.Operation.OperationID, p.Feature.Operation.SchemaID = b.OperationID, b.SchemaID
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal(err)
		}
		wire[uint64(index)%uint64(len(wire))] ^= change
		decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err != nil {
			return
		}
		again, err := encodeFeaturePlan(b, [32]byte{1}, decoded)
		if err != nil || !bytes.Equal(wire, again) || decoded.Feature.Operation.OperationID != "identity.username.signin" {
			t.Fatal("accepted original username challenge lost canonical action custody")
		}
	})
}
