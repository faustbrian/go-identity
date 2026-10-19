package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func organizationInvitationResendPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := organizationInvitationSendPlanFixture(t)
	b.OperationID, b.SchemaID = "identity.organization.invitation.resend", "organization-invitation-resend"
	p.Feature.Operation.OperationID, p.Feature.Operation.SchemaID = b.OperationID, b.SchemaID
	p.Audits[0].EventType, p.Audits[0].RetentionClass = "identity.organization.resend_invitation", "standard"
	p.Lifecycle = &LifecyclePlan{EventType: "invitation.resent.v1", BeforeVersion: 3, AfterVersion: 4}
	return b, p
}

// These are coordinator declaration/history boundaries, not genuine sender,
// invitation supersession, authorization or cryptographic consumer proof.
func TestOrganizationInvitationResendKeepsClosedPreparationAndHistory(t *testing.T) {
	b, p := organizationInvitationResendPlanFixture(t)
	if !validOrganizationInvitationPreparation(b, p) {
		t.Fatal("exact resend declaration rejected by send-only preparation")
	}
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal(err)
	}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation})
	claim, err := prepareClaim(command, fp)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until, state, profile := now.Add(time.Second), "pending", int16(3)
	observed := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: claim.safeFields,
		fingerprint: fp[:], state: &state, until: &until, now: now, preparationProfile: &profile, declaration: wire}
	q, _ := queryInputs(b)
	result, err := commandReceipt(q, observed, nil)
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress || result.Binding != b {
		t.Fatal("resend lost original pending preparation history", err)
	}
	final := p
	final.CapabilityIssuance = issuanceTestPlan()
	final.CapabilityIssuance.Grants[0].Purpose = "identity.organization.invitation.accept"
	final.Delivery = deliveryTestPlan()
	final.Delivery.Intents[0].SubjectID = string(b.UserID)
	final.Delivery.Intents[0].Purpose = "identity.organization.invitation.accept"
	final.Delivery.Intents[0].ExpiresAt = final.CapabilityIssuance.Grants[0].ExpiresAt
	final.Contributors = append(append([]ContributorDescriptor(nil), p.Contributors...), final.CapabilityIssuance.Contributor, final.Delivery.Contributor)
	if !validOrganizationInvitationIssuance(b, final) || !preparationFinalDeclaration(b, p, final) {
		t.Fatal("resend cannot attach its original successor proof and delivery")
	}
	for name, alter := range map[string]func(*CommandPlan){
		"created-event":    func(p *CommandPlan) { p.Lifecycle.EventType = "invitation.created.v1" },
		"zero-predecessor": func(p *CommandPlan) { p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = 0, 1 },
		"skip-version":     func(p *CommandPlan) { p.Lifecycle.AfterVersion++ },
		"overflow":         func(p *CommandPlan) { p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = ^uint64(0), 0 },
		"unconsumable-successor": func(p *CommandPlan) {
			p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = ^uint64(0)-1, ^uint64(0)
		},
		"send-audit":          func(p *CommandPlan) { p.Audits[0].EventType = "identity.organization.create_invitation" },
		"protected-retention": func(p *CommandPlan) { p.Audits[0].RetentionClass = "protected" },
		"optional-audit":      func(p *CommandPlan) { p.Audits[0].Required = false },
		"missing-counter":     func(p *CommandPlan) { p.CommandCounters = nil },
		"different-owner":     func(p *CommandPlan) { p.Feature.Contributor.ContractID = "organization.membership" },
		"schema-alias":        func(p *CommandPlan) { p.Feature.Operation.SchemaID = "organization-invitation-send" },
	} {
		t.Run(name, func(t *testing.T) {
			_, bad := organizationInvitationResendPlanFixture(t)
			alter(&bad)
			if validOrganizationInvitationPreparation(b, bad) {
				t.Fatal("foreign resend declaration accepted")
			}
		})
	}
	// A type name or closed declaration cannot create current recipient custody.
	if err := (Work{}).RequireOrganizationInvitationRecipient(context.Background(), &invitationIssuanceProbe{}, RecipientRecord{}); err == nil {
		t.Fatal("resend declaration fabricated an authoritative recipient")
	}
}

func TestOrganizationInvitationAcceptKeepsPositiveResentVersion(t *testing.T) {
	for _, before := range []uint64{1, 2, 4, ^uint64(0) - 1} {
		b, p := organizationInvitationPlanFixture(t)
		p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = before, before+1
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal("resent successor could not enter original consuming owner", before, err)
		}
		restored, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err != nil || restored.Lifecycle.BeforeVersion != before || restored.Lifecycle.AfterVersion != before+1 {
			t.Fatal("consumption discarded original successor version", err)
		}
		again, err := encodeFeaturePlan(b, [32]byte{1}, restored)
		if err != nil || !bytes.Equal(wire, again) {
			t.Fatal("consumption changed original plan bytes", err)
		}
	}
}

func TestOrganizationInvitationResendRegistryRejectsAliases(t *testing.T) {
	for name, alter := range map[string]func(*identity.FeatureOperation, *ContributorDescriptor){
		"schema":  func(op *identity.FeatureOperation, _ *ContributorDescriptor) { op.SchemaID += "-other" },
		"version": func(op *identity.FeatureOperation, _ *ContributorDescriptor) { op.SchemaVersion++ },
		"owner": func(op *identity.FeatureOperation, d *ContributorDescriptor) {
			op.Owner, d.Owner = "identity/other", "identity/other/postgres"
		},
		"contract": func(_ *identity.FeatureOperation, d *ContributorDescriptor) { d.ContractID = "organization.generic" },
		"record-policy": func(op *identity.FeatureOperation, _ *ContributorDescriptor) {
			op.RecordRequirement = identity.FeatureRecordOmitted
		},
		"subject-policy": func(op *identity.FeatureOperation, _ *ContributorDescriptor) {
			op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		},
	} {
		t.Run(name, func(t *testing.T) {
			op, descriptor := organizationInvitationResendOperation(), organizationInvitationDescriptor()
			alter(&op, &descriptor)
			if op.Validate() != nil || !validContributorDescriptor(descriptor) {
				t.Fatal("malformed fixture cannot exercise generic registration")
			}
			if _, err := NewContributorRegistry([]Contributor{&featureRegistryContributor{descriptor: descriptor, operations: []identity.FeatureOperation{op}}}); err == nil {
				t.Fatal("resend alias entered generic feature registration")
			}
		})
	}
}

func TestOrganizationInvitationResendBindsExactSuccessorGrant(t *testing.T) {
	b, p := organizationInvitationResendPlanFixture(t)
	p.CapabilityIssuance = issuanceTestPlan()
	p.CapabilityIssuance.Grants[0].Purpose = "identity.organization.invitation.accept"
	p.Delivery = deliveryTestPlan()
	p.Delivery.Intents[0].SubjectID = string(b.UserID)
	p.Delivery.Intents[0].Purpose = "identity.organization.invitation.accept"
	p.Delivery.Intents[0].ExpiresAt = p.CapabilityIssuance.Grants[0].ExpiresAt
	q := RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: identity.IdentifierEmail,
		CanonicalValue: "Canonical@example.test", Eligibility: RecipientVerified}
	row := recipientRowFixture()
	row.tenant, row.user = string(b.TenantID), string(b.UserID)
	recipient, err := decodeRecipient(q, row, "19", "23")
	if err != nil {
		t.Fatal(err)
	}
	owner := &invitationIssuanceProbe{outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}}}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: []identity.FeatureField{
		{Name: "organization.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "org-a"}},
		{Name: "organization.invitation-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 3}},
		{Name: "organization.role", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "member"}},
		{Name: "organization.invitation-expires-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.CapabilityIssuance.Grants[0].ExpiresAt}},
	}})
	state := &workState{binding: b, featureInvocation: owner, featureApplying: true, featureApplyCommand: &command,
		invitationRecipient: &organizationInvitationRecipientAdmission{owner: owner, recipient: recipient}}
	payload := capability.Payload{Subject: string(b.UserID), Tenant: string(b.TenantID), Resource: b.RecordID,
		CorrelationID: string(b.CommandID), Operation: "identity.organization.invitation.accept", MaxUses: 1,
		ExpiresAt: p.CapabilityIssuance.Grants[0].ExpiresAt, Caveats: map[string]string{
			"organization.id": "org-a", "organization.invitation-version": "4", "organization.role": "member",
			"organization.recipient-identifier": "identifier", "organization.recipient-identifier-version": "11"}}
	if user, err := organizationInvitationIssuanceSubject(state, p, payload); err != nil || user != b.UserID {
		t.Fatal("original successor grant rejected", err)
	}
	for _, version := range []string{"1", "3", "5", "04", "18446744073709551616"} {
		payload.Caveats["organization.invitation-version"] = version
		if _, err := organizationInvitationIssuanceSubject(state, p, payload); err == nil {
			t.Fatal("non-successor grant admitted", version)
		}
	}
	payload.Caveats["organization.invitation-version"] = "4"
	payload.ExpiresAt = payload.ExpiresAt.Add(time.Second)
	if _, err := organizationInvitationIssuanceSubject(state, p, payload); err == nil {
		t.Fatal("successor grant renewed the original frozen deadline")
	}
}
