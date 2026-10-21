package postgres

import (
	"bytes"
	"context"
	"testing"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func anonymousUpgradePreparationFixture(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	_, command, original := featurePlanFixture(t)
	spec, _ := command.Feature()
	b := spec.Binding
	b.OperationID = "identity.anonymous.upgrade"
	b.SchemaID = "identity.anonymous.upgrade.prepare.native-v1"
	b.RecordID = ""
	b.ActorKind, b.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
	registration := FeatureRegistration{Contributor: anonymousCreationDescriptor(), Operation: identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}}
	original.Feature = &registration
	original.SubjectType = "anonymous_upgrade_preparation"
	original.Contributors[3] = registration.Contributor
	original.Lifecycle = &LifecyclePlan{EventType: "anonymous.upgrade.prepared.v1"}
	original.Audits[0].EventType, original.Audits[0].RetentionClass = b.OperationID, "protected"
	original.Audits[0].BindingDigest = securityAuditScopeDigest(b, &registration.Operation, original.SubjectType, featureTargetID(b), audit.ActorHuman, "identity-feature-audit-binding-v1")
	final := original
	final.CapabilityIssuance = issuanceTestPlan()
	final.CapabilityIssuance.Grants[0].Purpose = "identity.anonymous.upgrade"
	final.Contributors = append(append([]ContributorDescriptor(nil), original.Contributors...), final.CapabilityIssuance.Contributor)
	return b, original, final
}

type anonymousUpgradePreparationProbe struct {
	outputPreparationParticipant
	expected identity.Command
}

func (*anonymousUpgradePreparationProbe) Descriptor() ContributorDescriptor {
	return anonymousCreationDescriptor()
}
func (p *anonymousUpgradePreparationProbe) ValidateAnonymousUpgradePreparation(c identity.Command, issuance *CapabilityIssuancePlan) error {
	if c != p.expected || issuance != nil && (len(issuance.Grants) != 1 || issuance.Grants[0].Purpose != "identity.anonymous.upgrade") {
		return invalidPlan()
	}
	return nil
}
func (*anonymousUpgradePreparationProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}

func TestAnonymousUpgradePreparationRequiresTypedOwnerAndFinalIssuance(t *testing.T) {
	b, original, final := anonymousUpgradePreparationFixture(t)
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: original.Feature.Operation, Fields: []identity.FeatureField{{Name: "original", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "frozen-upgrade"}}}})
	typed := &anonymousUpgradePreparationProbe{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{original.Feature.Operation}}}, expected: command}
	for _, owner := range []Contributor{typed, &untypedAnonymousUpgradeProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{original.Feature.Operation}}}} {
		r, err := NewContributorRegistry([]Contributor{&Repository{}, &riskPassiveProbe{registryContributor{original.Contributors[1]}}, &riskPassiveProbe{registryContributor{original.Contributors[2]}}, owner, &issuancePlanProbe{}})
		if err != nil {
			t.Fatal(err)
		}
		original.Contributors = r.Descriptors()[:4]
		final.Contributors = r.Descriptors()
		original.Digest, err = FeaturePlanDigest(b, [32]byte{1}, original)
		if err != nil {
			t.Fatal(err)
		}
		final.Digest, err = FeaturePlanDigest(b, [32]byte{1}, final)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.admitFeaturePlanMode(b, [32]byte{1}, original, true); (owner == typed) != (err == nil) {
			t.Fatal("original preparation typed admission", err)
		}
		if _, err := r.admitFeaturePlan(b, [32]byte{1}, final); (owner == typed) != (err == nil) {
			t.Fatal("final issuance typed admission", err)
		}
		if _, err := r.admitFeaturePlan(b, [32]byte{1}, original); err == nil {
			t.Fatal("issuance-free original executed as final command")
		}
	}
	if err := validateFeatureCommand(typed, command, final); err != nil {
		t.Fatal("exact native validation", err)
	}
	if err := validateFeatureCommand(typed, identity.Command{}, final); err == nil {
		t.Fatal("foreign original command gained preparation")
	}
	alias := original.Feature.Operation
	alias.SchemaID += ".alias"
	if featureContributorOwns(typed.Descriptor(), alias) {
		t.Fatal("schema alias bypassed closed preparation")
	}
}

// Issuance is a distinct durable command: a signed checkpoint is not a row the
// real one-use participant can reserve. This test is declaration/history proof,
// not authentication, issuance commitment or native upgrade acceptance.
func TestAnonymousUpgradePreparationAddsOnlyOriginalTargetGrant(t *testing.T) {
	b, original, final := anonymousUpgradePreparationFixture(t)
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("closed anonymous preparation cannot retain its generated one-use grant")
	}
	for _, p := range []CommandPlan{original, final} {
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal("closed preparation declaration", err)
		}
		decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err != nil {
			t.Fatal("original preparation history", err)
		}
		again, err := encodeFeaturePlan(b, [32]byte{1}, decoded)
		if err != nil || !bytes.Equal(wire, again) {
			t.Fatal("preparation history changed", err)
		}
	}
	for name, change := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"foreign-actor":  func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorID = "another-human" },
		"missing-target": func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "" },
		"guest-record":   func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "guest" },
		"schema-alias": func(b *identity.CommandBinding, p *CommandPlan) {
			b.SchemaID += ".alias"
			p.Feature.Operation.SchemaID = b.SchemaID
		},
		"wrong-owner": func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Contributor.ContractID = "identity.other" },
		"wrong-purpose": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.password.reset-complete"
		},
		"multiple-grants": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants = append(p.CapabilityIssuance.Grants, p.CapabilityIssuance.Grants[0])
		},
		"recipient-override": func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance.RegistrationUserID = "other" },
		"delivery": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Delivery = deliveryTestPlan()
			p.Contributors = append(p.Contributors, p.Delivery.Contributor)
		},
		"consumption": func(_ *identity.CommandBinding, p *CommandPlan) {
			g := p.CapabilityIssuance.Grants[0]
			p.Capability = &g
		},
		"guest-mutation":    func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.AfterVersion = 1 },
		"unprotected-audit": func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
	} {
		t.Run(name, func(t *testing.T) {
			b, original, final := anonymousUpgradePreparationFixture(t)
			f, l := *final.Feature, *final.Lifecycle
			final.Feature, final.Lifecycle = &f, &l
			final.Audits = append([]AuditPlan(nil), final.Audits...)
			change(&b, &final)
			if preparationFinalDeclaration(b, original, final) {
				t.Fatal("preparation expanded original target/profile")
			}
		})
	}
}
