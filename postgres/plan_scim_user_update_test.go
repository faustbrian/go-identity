package postgres

import (
	"bytes"
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func scimUpdatePlanExample() (identity.CommandBinding, CommandPlan) {
	b := scimUpdateIntentFixture("identity.scim.user-patch").Binding
	op := scimUserUpdateOperation(b.OperationID)
	return b, CommandPlan{
		Contributors: []ContributorDescriptor{(&Repository{}).Descriptor(), {Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}, {Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, scimUserCreationDescriptor()},
		Audits:       []AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: [32]byte{1}, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 4096, MaxAggregateBytes: 4096, Required: true}},
		Lifecycle:    &LifecyclePlan{EventType: "identity.scim.user_patched.v1", BeforeVersion: 7, AfterVersion: 8},
		Feature:      &FeatureRegistration{Contributor: scimUserCreationDescriptor(), Operation: op}, SubjectType: "scim_user",
		SCIMUserUpdate: &SCIMUserUpdatePlan{Required: true, ExpectedVersion: 17},
	}
}

type scimUpdatePlanParticipant struct{ scopeFeatureParticipant }

func (*scimUpdatePlanParticipant) Descriptor() ContributorDescriptor {
	return scimUserCreationDescriptor()
}
func (*scimUpdatePlanParticipant) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return nil
}

func TestSCIMUserUpdatePlanRetainsCoreVersionIndependently(t *testing.T) {
	b, p := scimUpdatePlanExample()
	for _, required := range []bool{false, true} {
		p.SCIMUserUpdate.Required = required
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err != nil || decoded.SCIMUserUpdate == nil || *decoded.SCIMUserUpdate != *p.SCIMUserUpdate || decoded.Lifecycle.BeforeVersion != 7 || decoded.Lifecycle.AfterVersion != 8 {
			t.Fatal("core CAS metadata substituted SCIM generation", err)
		}
		if _, err := decodeFeaturePlan(b, [32]byte{1}, append(bytes.Clone(wire), 0)); err == nil {
			t.Fatal("noncanonical plan trailing bytes admitted")
		}
	}
	p.SCIMUserUpdate = nil
	if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
		t.Fatal("SCIM update plan omitted required core recovery evidence")
	}
}

func TestSCIMUserUpdatePlanMustMatchOriginalTypedFields(t *testing.T) {
	intent := scimUpdateIntentFixture("identity.scim.user-patch")
	fields, err := SCIMUserUpdateFields(intent, storageSchema())
	if err != nil {
		t.Fatal(err)
	}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: intent.Binding, Operation: scimUserUpdateOperation(intent.Binding.OperationID), Fields: fields})
	_, plan := scimUpdatePlanExample()
	phase := &scimUpdatePlanParticipant{}
	if err := validateFeatureCommand(phase, command, plan); err != nil {
		t.Fatal("matching core metadata rejected", err)
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.SCIMUserUpdate = nil },
		func(p *CommandPlan) { p.SCIMUserUpdate = &SCIMUserUpdatePlan{Required: false, ExpectedVersion: 17} },
		func(p *CommandPlan) { p.SCIMUserUpdate = &SCIMUserUpdatePlan{Required: true, ExpectedVersion: 18} },
		func(p *CommandPlan) { p.SubjectType = "identity.user" },
	} {
		candidate := plan
		change(&candidate)
		if err := validateFeatureCommand(phase, command, candidate); err == nil {
			t.Fatal("plan metadata escaped original command")
		}
	}
	withoutFinalCheck := &scopeFeatureParticipant{}
	if err := validateFeatureCommand(withoutFinalCheck, command, plan); err == nil {
		t.Fatal("SCIM update omitted mandatory final check")
	}
}

func FuzzSCIMUserUpdatePlan(f *testing.F) {
	b, p := scimUpdatePlanExample()
	valid, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0xa3})
	f.Add(append(bytes.Clone(valid), 0))
	f.Fuzz(func(t *testing.T, wire []byte) {
		decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err != nil {
			return
		}
		canonical, err := encodeFeaturePlan(b, [32]byte{1}, decoded)
		if err != nil || !bytes.Equal(canonical, wire) {
			t.Fatal("accepted SCIM plan was not canonical")
		}
	})
}
