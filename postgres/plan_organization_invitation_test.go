package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func organizationInvitationPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := emailVerificationPlanFixture(t)
	b.OperationID, b.SchemaID, b.RecordID = "identity.organization.invitation.accept", "organization-invitation-accept", "invitation"
	b.ActorID = identity.ActorID(b.UserID)
	p.Feature.Operation = identity.FeatureOperation{Owner: "organization", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
	p.Feature.Contributor = ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.invitation", Version: 1}
	p.Contributors[3] = p.Feature.Contributor
	p.SubjectType = "invitation"
	p.Audits[0].EventType = "identity.organization.accept_invitation"
	p.Lifecycle = &LifecyclePlan{EventType: "invitation.accepted.v1", BeforeVersion: 1, AfterVersion: 2}
	p.Capability.Purpose = "identity.organization.invitation.accept"
	return b, p
}

// These probes exercise closed registration/admission, not durable invitation
// mutation, cryptographic verification or membership authorization.
type invitationConsumptionProbe struct {
	scopeFeatureParticipant
	expected identity.Command
	proof    CapabilityPlan
}

func (*invitationConsumptionProbe) Descriptor() ContributorDescriptor {
	return organizationInvitationDescriptor()
}
func (p *invitationConsumptionProbe) ValidateOrganizationInvitationConsumption(c identity.Command, proof CapabilityPlan) error {
	if c != p.expected || proof != p.proof {
		return invalidPlan()
	}
	return nil
}
func (*invitationConsumptionProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}

type invitationLifecycleProbe struct{ riskPassiveProbe }

type untypedInvitationProbe struct{ scopeFeatureParticipant }

func (*untypedInvitationProbe) Descriptor() ContributorDescriptor {
	return organizationInvitationDescriptor()
}

func (*invitationLifecycleProbe) PersistOrganizationInvitation(context.Context, Work) error {
	return nil
}

func TestOrganizationInvitationAdmissionRequiresAtomicNativeOwners(t *testing.T) {
	b, p := organizationInvitationPlanFixture(t)
	c, _, _ := coordinatorFixture(t)
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: []identity.FeatureField{{Name: "organization.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "organization-a"}}}})
	owner := &invitationConsumptionProbe{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}, expected: command, proof: *p.Capability}
	audit := &riskPassiveProbe{registryContributor{p.Contributors[1]}}
	outbox := &invitationLifecycleProbe{riskPassiveProbe{registryContributor{p.Contributors[2]}}}
	entries := []Contributor{&Repository{}, audit, outbox, owner, &magicLinkPreparationCounter{}, &capabilityExecutionProbe{}}
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	p.Contributors = registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 1, 2, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, b.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, p.Feature.Operation, p.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.PrepareCommandPlan(b, command, p); err != nil {
		t.Fatal("complete original invitation owner cannot prepare", err)
	}
	changed := p
	copyProof := *p.Capability
	copyProof.ProofFingerprint[0]++
	changed.Capability = &copyProof
	if _, err := c.PrepareCommandPlan(b, command, changed); err == nil {
		t.Fatal("native original proof validation skipped")
	}
	entries[2] = &outbox.riskPassiveProbe
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrepareCommandPlan(b, command, p); err == nil {
		t.Fatal("ordinary outbox admitted without atomic membership event")
	}
	entries[2] = outbox
	entries[3] = &untypedInvitationProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}}
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrepareCommandPlan(b, command, p); err == nil {
		t.Fatal("untyped feature admitted invitation consumption")
	}
}

func TestOrganizationInvitationConsumptionPlanConservesClosedOriginalProof(t *testing.T) {
	b, p := organizationInvitationPlanFixture(t)
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal("closed invitation consumption unavailable", err)
	}
	restored, err := decodeFeaturePlan(b, fp, wire)
	if err != nil || restored.Capability == nil || *restored.Capability != *p.Capability || restored.Digest != sha256.Sum256(wire) {
		t.Fatal("lost original invitation consumption", err)
	}
	again, err := encodeFeaturePlan(b, fp, restored)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("changed frozen invitation plan", err)
	}
	for n := range wire {
		if _, err := decodeFeaturePlan(b, fp, wire[:n]); err == nil {
			t.Fatal("truncated invitation plan accepted", n)
		}
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Capability = nil; p.Contributors = p.Contributors[:len(p.Contributors)-1] },
		func(p *CommandPlan) { p.Capability.Purpose = "identity.identifier.verify" },
		func(p *CommandPlan) { p.Capability.MaxUses = 2 },
		func(p *CommandPlan) { p.Capability.ProofFingerprint = [32]byte{} },
		func(p *CommandPlan) {
			p.CommandCounters = nil
			p.Contributors = append(p.Contributors[:4], p.Contributors[5:]...)
		},
		func(p *CommandPlan) { p.SubjectType = "organization" },
		func(p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		func(p *CommandPlan) { p.Lifecycle.EventType = "membership.created.v1" },
		func(p *CommandPlan) { p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = 0, 1 },
		func(p *CommandPlan) {
			p.Feature.Contributor.ContractID = "organization.membership"
			p.Contributors[3] = p.Feature.Contributor
		},
	} {
		_, bad := organizationInvitationPlanFixture(t)
		mutate(&bad)
		if _, err := encodeFeaturePlan(b, fp, bad); err == nil {
			t.Fatal("open or mismatched invitation plan accepted")
		}
	}
}

func organizationInvitationSendPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := organizationInvitationPlanFixture(t)
	b.OperationID, b.SchemaID = organizationInvitationSendOperation().OperationID, organizationInvitationSendOperation().SchemaID
	b.ActorID = "owner-a"
	p.Feature.Operation = organizationInvitationSendOperation()
	p.Capability = nil
	p.Contributors = p.Contributors[:len(p.Contributors)-1]
	p.Audits[0].EventType = "identity.organization.create_invitation"
	p.Lifecycle = &LifecyclePlan{EventType: "invitation.created.v1", BeforeVersion: 0, AfterVersion: 1}
	return b, p
}

func TestOrganizationInvitationPreparationAddsOnlyClosedOriginalIssuance(t *testing.T) {
	b, original := organizationInvitationSendPlanFixture(t)
	final := original
	final.CapabilityIssuance = issuanceTestPlan()
	final.CapabilityIssuance.Grants[0].Purpose = "identity.organization.invitation.accept"
	final.Delivery = deliveryTestPlan()
	final.Delivery.Intents[0].SubjectID = string(b.UserID)
	final.Delivery.Intents[0].Purpose = "identity.organization.invitation.accept"
	final.Delivery.Intents[0].ExpiresAt = final.CapabilityIssuance.Grants[0].ExpiresAt
	final.Contributors = append(append([]ContributorDescriptor(nil), original.Contributors...), final.CapabilityIssuance.Contributor, final.Delivery.Contributor)
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("original invitation cannot retain generated issuance and delivery")
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CapabilityIssuance.Grants[0].Purpose = "identity.magic-link.consume" },
		func(p *CommandPlan) { p.CapabilityIssuance.RegistrationUserID = b.UserID },
		func(p *CommandPlan) { p.Delivery = nil; p.Contributors = p.Contributors[:len(p.Contributors)-1] },
		func(p *CommandPlan) {
			p.CapabilityIssuance.Grants = append(p.CapabilityIssuance.Grants, p.CapabilityIssuance.Grants[0])
		},
	} {
		changed := final
		changed.CapabilityIssuance = cloneCapabilityIssuancePlan(final.CapabilityIssuance)
		mutate(&changed)
		if preparationFinalDeclaration(b, original, changed) {
			t.Fatal("open invitation generation admitted")
		}
	}
}

func FuzzOrganizationInvitationConsumptionProfile(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa5})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 65536 {
			return
		}
		b, p := organizationInvitationPlanFixture(t)
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range [][]byte{wire, input} {
			got, err := decodeFeaturePlan(b, [32]byte{1}, candidate)
			if err != nil {
				continue
			}
			canonical, err := encodeFeaturePlan(b, [32]byte{1}, got)
			if err != nil || !bytes.Equal(candidate, canonical) || got.Capability == nil || got.Capability.Purpose != "identity.organization.invitation.accept" || got.Capability.MaxUses != 1 {
				t.Fatal("foreign or noncanonical invitation history admitted")
			}
		}
	})
}
