package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestDisableSessionEffectAcceptsOnlyItsExactScope(t *testing.T) {
	_, input := mfaActionSessionFixture(t)
	b, _ := input.Command.Feature()
	b.Binding.OperationID, b.Binding.SchemaID = "identity.mfa.disable", "mfa-disable"
	b.Binding.RecordID = string(b.Binding.UserID)
	f := kernel.FeatureRegistration{Contributor: kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}, Operation: identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.Binding.OperationID, SchemaID: b.Binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
	l := kernel.LifecyclePlan{EventType: "factor.removed.v1", BeforeVersion: 4, AfterVersion: 5}
	e := &MFARecoverySessionEffect{disable: true}
	if !e.acceptsScope(b.Binding, f, l) {
		t.Fatal("exact native disable session effect denied")
	}
	for _, event := range []string{"factor.changed.v1", "factor.updated.v1", "factor.reset.v1"} {
		bad := l
		bad.EventType = event
		if e.acceptsScope(b.Binding, f, bad) {
			t.Fatal("disable effect broadened lifecycle scope")
		}
	}
	if (&MFARecoverySessionEffect{factorManagement: true}).acceptsScope(b.Binding, f, l) {
		t.Fatal("old factor-update owner borrowed disable authority")
	}
}
