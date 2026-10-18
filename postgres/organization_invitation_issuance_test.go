package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

type invitationIssuanceProbe struct{ outputPreparationParticipant }

func (*invitationIssuanceProbe) Descriptor() ContributorDescriptor {
	return organizationInvitationDescriptor()
}
func (*invitationIssuanceProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}
func (*invitationIssuanceProbe) ValidateOrganizationInvitationIssuance(identity.Command, CommandPlan) error {
	return nil
}

func TestOrganizationInvitationIssuanceRequiresOriginalRecipientFence(t *testing.T) {
	b, p := organizationInvitationSendPlanFixture(t)
	p.CapabilityIssuance = issuanceTestPlan()
	p.CapabilityIssuance.Grants[0].Purpose = "identity.organization.invitation.accept"
	p.Delivery = deliveryTestPlan()
	p.Delivery.Intents[0].SubjectID = string(b.UserID)
	p.Delivery.Intents[0].Purpose = "identity.organization.invitation.accept"
	p.Delivery.Intents[0].ExpiresAt = p.CapabilityIssuance.Grants[0].ExpiresAt
	q := RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "Canonical@example.test", Eligibility: RecipientVerified}
	row := recipientRowFixture()
	row.tenant, row.user = string(b.TenantID), string(b.UserID)
	r, err := decodeRecipient(q, row, "19", "23")
	if err != nil {
		t.Fatal(err)
	}
	owner := &invitationIssuanceProbe{outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{organizationInvitationSendOperation()}}}}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: organizationInvitationSendOperation(), Fields: []identity.FeatureField{
		{Name: "organization.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "org-a"}},
		{Name: "organization.invitation-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 0}},
		{Name: "organization.role", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "member"}},
		{Name: "organization.invitation-expires-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.CapabilityIssuance.Grants[0].ExpiresAt}},
	}})
	s := &workState{binding: b, featureInvocation: owner, featureApplying: true, featureApplyCommand: &command}
	payload := capability.Payload{Subject: string(b.UserID), Tenant: string(b.TenantID), Resource: b.RecordID, CorrelationID: string(b.CommandID), Operation: "identity.organization.invitation.accept", MaxUses: 1, ExpiresAt: p.CapabilityIssuance.Grants[0].ExpiresAt, Caveats: map[string]string{"organization.id": "org-a", "organization.invitation-version": "1", "organization.role": "member", "organization.recipient-identifier": "identifier", "organization.recipient-identifier-version": "11"}}
	if _, err := organizationInvitationIssuanceSubject(s, p, payload); err == nil {
		t.Fatal("declaration selected unfenced recipient")
	}
	s.invitationRecipient = &organizationInvitationRecipientAdmission{owner: owner, recipient: r}
	if got, err := organizationInvitationIssuanceSubject(s, p, payload); err != nil || got != b.UserID {
		t.Fatal("original fenced recipient unavailable", err)
	}
	for _, mutate := range []func(*capability.Payload){
		func(p *capability.Payload) { p.Subject = "foreign" },
		func(p *capability.Payload) { p.Tenant = "foreign" },
		func(p *capability.Payload) { p.Resource = "foreign" },
		func(p *capability.Payload) { p.CorrelationID = "foreign" },
		func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(1) },
		func(p *capability.Payload) { p.Caveats["organization.id"] = "foreign" },
		func(p *capability.Payload) { p.Caveats["organization.role"] = "owner" },
		func(p *capability.Payload) { p.Caveats["organization.invitation-version"] = "2" },
		func(p *capability.Payload) { p.Caveats["organization.recipient-identifier"] = "foreign" },
		func(p *capability.Payload) { p.Caveats["organization.recipient-identifier-version"] = "12" },
		func(p *capability.Payload) { p.Caveats["extra"] = "unsupported" },
	} {
		changed := payload
		changed.Caveats = make(map[string]string, len(payload.Caveats))
		for k, v := range payload.Caveats {
			changed.Caveats[k] = v
		}
		mutate(&changed)
		if _, err := organizationInvitationIssuanceSubject(s, p, changed); err == nil {
			t.Fatal("changed signed original scope admitted")
		}
	}
	s.featureInvocation = &invitationIssuanceProbe{}
	if _, err := organizationInvitationIssuanceSubject(s, p, payload); err == nil {
		t.Fatal("foreign owner borrowed successful recipient fence")
	}
}
