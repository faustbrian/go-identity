package postgres

import (
	"context"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// OrganizationInvitationIssuanceContributor owns the closed invitation-send
// workflow. Preparation validates current genuine owner/session, organization,
// verified recipient and pending limits before acknowledged token generation.
// Validation is pure; generated proof/address custody is authenticated and
// encrypted by the existing preparation owner. Apply and final commit check
// repeat current authority; issuance and delivery share the sole transaction.
type OrganizationInvitationIssuanceContributor interface {
	FeaturePreparationContributor
	FeatureCommitContributor
	ValidateOrganizationInvitationIssuance(identity.Command, CommandPlan) error
}

type organizationInvitationRecipientAdmission struct {
	owner     OrganizationInvitationIssuanceContributor
	recipient RecipientRecord
}

// The existing preparation journal freezes this declaration before token
// generation. It can prove an unfinished/denied attempt, never final issuance.
func validOrganizationInvitationPreparation(b identity.CommandBinding, p CommandPlan) bool {
	return b.ActorKind == authorization.SubjectUser && p.Feature != nil &&
		p.Feature.Operation == organizationInvitationSendOperation() &&
		p.Feature.Contributor == organizationInvitationDescriptor() && b.ValidateFor(p.Feature.Operation) == nil &&
		p.SubjectType == "invitation" && p.CommandCounters != nil &&
		p.Lifecycle != nil && *p.Lifecycle == (LifecyclePlan{EventType: "invitation.created.v1", BeforeVersion: 0, AfterVersion: 1}) &&
		len(p.Audits) == 1 && p.Audits[0].EventType == "identity.organization.create_invitation" && p.Audits[0].RetentionClass == "protected" &&
		!preparationProtected(p) && p.Delivery == nil && p.MFAContinuation == nil && p.MFACompletion == nil &&
		p.MagicLinkRegistration == nil && !p.SignupAcceptance && !p.MagicLinkRequestAcceptance
}

func validOrganizationInvitationIssuance(b identity.CommandBinding, p CommandPlan) bool {
	if b.ActorKind != authorization.SubjectUser {
		return false
	}
	i := p.CapabilityIssuance
	if i == nil || p.Feature == nil || p.Feature.Operation != organizationInvitationSendOperation() || p.Feature.Contributor != organizationInvitationDescriptor() || b.ValidateFor(p.Feature.Operation) != nil || p.SubjectType != "invitation" || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "invitation.created.v1", BeforeVersion: 0, AfterVersion: 1}) || p.CommandCounters == nil || p.Capability != nil || p.OTP != nil || p.RiskEvidence != nil || p.CaptchaEvidence != nil || i.RegistrationUserID != "" || i.ResetRecipientUserID != "" || i.MagicLinkRecipientUserID != "" || i.MFAContinuationUserID != "" || len(i.Grants) != 1 || i.Grants[0].Purpose != "identity.organization.invitation.accept" || !validCapabilityIssuancePlan(i) || p.Delivery == nil || !validDeliveryPlan(p.Delivery) || len(p.Delivery.Intents) != 1 {
		return false
	}
	d := p.Delivery.Intents[0]
	return d.SubjectID == string(b.UserID) && d.Purpose == "identity.organization.invitation.accept" && d.ExpiresAt.Equal(i.Grants[0].ExpiresAt)
}

// RequireOrganizationInvitationRecipient fences the exact verified existing
// email recipient under primary authority/identifier share locks, then retains
// admission for this native invocation only. The same original identifier and
// version must already be frozen in the command. This does not authorize the
// sending owner, pending limit, signing or delivery; those remain native checks.
// Rejection poisons Work. Preparation admission cannot be reused by a later
// Work: Apply must perform this fence again before staging an issued grant.
func (w Work) RequireOrganizationInvitationRecipient(ctx context.Context, owner OrganizationInvitationIssuanceContributor, recipient RecipientRecord) error {
	if err := w.usable(); err != nil {
		return err
	}
	fail := func() error { return w.fail(w.state.ctx, invalidWork()) }
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || ctx == nil || f.Operation != organizationInvitationSendOperation() || f.Contributor != organizationInvitationDescriptor() || recipient.Validate() != nil || recipient.Suppressed || recipient.Query.Kind != identity.IdentifierEmail || recipient.Query.Eligibility != RecipientVerified || recipient.Query.UserID != b.UserID || recipient.User.ID != b.UserID || w.state.invitationRecipient != nil {
		return fail()
	}
	command := w.state.featurePreparationCommand
	if w.state.featureApplying {
		command = w.state.featureApplyCommand
	}
	if command == nil {
		return fail()
	}
	s, ok := command.Feature()
	if !ok {
		return fail()
	}
	matched := 0
	for _, field := range s.Fields {
		switch field.Name {
		case "organization.recipient-identifier":
			if field.Value.Kind != identity.FeatureText || field.Value.Text != string(recipient.Identifier.ID) {
				return fail()
			}
			matched++
		case "organization.recipient-identifier-version":
			if field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != recipient.Identifier.Version {
				return fail()
			}
			matched++
		}
	}
	if matched != 2 {
		return fail()
	}
	if err := w.RequireRecipient(ctx, owner, recipient); err != nil {
		return err
	}
	w.state.invitationRecipient = &organizationInvitationRecipientAdmission{owner: owner, recipient: recipient}
	return nil
}

func organizationInvitationIssuanceSubject(s *workState, p CommandPlan, payload capability.Payload) (identity.UserID, error) {
	if s == nil || s.invitationRecipient == nil || !s.featureApplying || !sameParticipant(s.featureInvocation, s.invitationRecipient.owner) || !validOrganizationInvitationIssuance(s.binding, p) || s.featureApplyCommand == nil {
		return "", invalidWork()
	}
	r := s.invitationRecipient.recipient
	b := s.binding
	if payload.Subject != string(r.User.ID) || payload.Tenant != string(b.TenantID) || payload.Resource != b.RecordID || payload.CorrelationID != string(b.CommandID) || payload.Operation != "identity.organization.invitation.accept" || payload.Bearer || payload.MaxUses != 1 || len(payload.Caveats) != 5 || !payload.ExpiresAt.Equal(p.CapabilityIssuance.Grants[0].ExpiresAt) || payload.Caveats["organization.recipient-identifier"] != string(r.Identifier.ID) || payload.Caveats["organization.recipient-identifier-version"] != strconv.FormatUint(r.Identifier.Version, 10) || payload.Caveats["organization.invitation-version"] != "1" || payload.Caveats["organization.role"] != "member" {
		return "", invalidWork()
	}
	command, ok := s.featureApplyCommand.Feature()
	if !ok {
		return "", invalidWork()
	}
	matched := 0
	for _, f := range command.Fields {
		switch f.Name {
		case "organization.id":
			if f.Value.Kind != identity.FeatureText || f.Value.Text != payload.Caveats["organization.id"] {
				return "", invalidWork()
			}
			matched++
		case "organization.invitation-expires-at":
			if f.Value.Kind != identity.FeatureTime || !f.Value.Time.Equal(payload.ExpiresAt) {
				return "", invalidWork()
			}
			matched++
		case "organization.invitation-version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 != 0 {
				return "", invalidWork()
			}
			matched++
		case "organization.role":
			if f.Value.Kind != identity.FeatureText || f.Value.Text != "member" {
				return "", invalidWork()
			}
			matched++
		}
	}
	if matched != 4 {
		return "", invalidWork()
	}
	return r.User.ID, nil
}
