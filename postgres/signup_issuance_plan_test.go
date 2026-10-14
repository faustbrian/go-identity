package postgres

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestSignupIssuanceTargetFrozenAndScoped(t *testing.T) {
	_, command, p := featurePlanFixture(t)
	s, _ := command.Feature()
	b := s.Binding
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	b.UserID, b.AnonymousFlowID = "", string(b.CommandID)
	b.RecordID = ""
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	p.Feature = &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}, Operation: op}
	p.Contributors[3] = p.Feature.Contributor
	p.SubjectType, p.Lifecycle = "user", &LifecyclePlan{EventType: "user.created.v1"}
	p.Audits[0].RetentionClass = "protected"
	p.CapabilityIssuance = issuanceTestPlan()
	p.CapabilityIssuance.RegistrationUserID = "new-user"
	p.Contributors = append(p.Contributors, p.CapabilityIssuance.Contributor)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	p.Digest = sha256.Sum256(wire)
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("selected target lost in original history", err)
	}
	changed := p
	changed.CapabilityIssuance = cloneCapabilityIssuancePlan(p.CapabilityIssuance)
	changed.CapabilityIssuance.RegistrationUserID = "another-user"
	other, err := encodeFeaturePlan(b, [32]byte{1}, changed)
	if err != nil || bytes.Equal(wire, other) || got.CapabilityIssuance.RegistrationUserID != "new-user" {
		t.Fatal("target escaped frozen intent", err)
	}
	for _, mutate := range []func(*CommandPlan, *identity.CommandBinding){
		func(p *CommandPlan, b *identity.CommandBinding) { b.UserID = "new-user"; b.AnonymousFlowID = "" },
		func(p *CommandPlan, _ *identity.CommandBinding) {
			p.Feature.Operation.OperationID = "identity.password.signin"
		},
		func(p *CommandPlan, _ *identity.CommandBinding) { p.Feature.Operation.SchemaVersion++ },
		func(p *CommandPlan, _ *identity.CommandBinding) { p.Feature.Contributor.ContractID = "foreign" },
		func(p *CommandPlan, _ *identity.CommandBinding) { p.Lifecycle.EventType = "other.created.v1" },
		func(p *CommandPlan, _ *identity.CommandBinding) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.identifier.attach"
		},
		func(p *CommandPlan, _ *identity.CommandBinding) { p.CapabilityIssuance.RegistrationUserID = "\x00" },
	} {
		bad, binding := p, b
		feature, lifecycle := *p.Feature, *p.Lifecycle
		bad.Feature, bad.Lifecycle = &feature, &lifecycle
		bad.CapabilityIssuance = cloneCapabilityIssuancePlan(p.CapabilityIssuance)
		mutate(&bad, &binding)
		if _, err := encodeFeaturePlan(binding, [32]byte{1}, bad); err == nil {
			t.Fatal("foreign registration issuance admitted")
		}
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated selected-target history admitted")
		}
	}
}
