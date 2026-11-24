package postgres

import (
	"context"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

const (
	ssoSAMLLogoutRelayIssuePurpose  = "identity.sso.saml-logout-relay-issue"
	ssoSAMLLogoutRelaySettlePurpose = "identity.sso.saml-logout-relay-settle"
	ssoSAMLLogoutRequestSubject     = "sso_saml_logout_request"
	samlLogoutRelayLocalCommand     = "sso.saml.logout.local-command"
	samlLogoutRelayOrganization     = "sso.saml.logout.organization"
	samlLogoutRelayProvider         = "sso.saml.logout.provider"
	samlLogoutRelayRequest          = "sso.saml.logout.request"
	samlLogoutRelayIssuedAt         = "sso.saml.logout.issued-at"
	samlLogoutRelayExpiresAt        = "sso.saml.logout.expires-at"
)

// SSOSAMLLogoutRelayIssueOperation selects remote request custody after the
// original local revocation. The record is the new issuance command, not the
// local session. This profile grants no browser or account authority.
func SSOSAMLLogoutRelayIssueOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/saml", OperationID: ssoSAMLLogoutRelayIssuePurpose,
		SchemaID: "sso-enterprise-saml-logout-relay-issue-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// SSOSAMLLogoutRelayIssueDescriptor identifies the native remote-request owner.
func SSOSAMLLogoutRelayIssueDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-logout-relay-issue", Version: 1}
}

// SSOSAMLLogoutRelayIssueLifecycle records one remote request reservation.
func SSOSAMLLogoutRelayIssueLifecycle() LifecyclePlan {
	return LifecyclePlan{EventType: "sso.saml_logout.requested.v1", AfterVersion: 1}
}

// SSOSAMLLogoutRelayIssueIntent binds one already committed local logout to the
// selected provider, exact signed redirect digest, and the original whole-second
// UTC window. The caller must independently prove local commit and route/cutoff
// authority. No raw wire or handle belongs in the command fields.
type SSOSAMLLogoutRelayIssueIntent struct {
	LocalCommandID             identity.CommandID
	OrganizationID, ProviderID string
	RequestDigest              [32]byte
	IssuedAt, ExpiresAt        time.Time
}

// SSOSAMLLogoutRelayIssueFields encodes the remote request intent. The command's
// CorrelationID must equal LocalCommandID, distinct from its own CommandID.
func SSOSAMLLogoutRelayIssueFields(intent SSOSAMLLogoutRelayIssueIntent) ([]identity.FeatureField, error) {
	_, err := identity.ParseCommandID(string(intent.LocalCommandID))
	if err != nil || !queryScopeText(intent.OrganizationID) || !queryScopeText(intent.ProviderID) || intent.RequestDigest == ([32]byte{}) ||
		!validSAMLLogoutRelayInstant(intent.IssuedAt) || !validSAMLLogoutRelayInstant(intent.ExpiresAt) || !intent.ExpiresAt.After(intent.IssuedAt) ||
		intent.ExpiresAt.Sub(intent.IssuedAt) > 5*time.Minute {
		return nil, invalidPlan()
	}
	return []identity.FeatureField{
		{Name: samlLogoutRelayExpiresAt, Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: intent.ExpiresAt}},
		{Name: samlLogoutRelayIssuedAt, Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: intent.IssuedAt}},
		{Name: samlLogoutRelayLocalCommand, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(intent.LocalCommandID)}},
		{Name: samlLogoutRelayOrganization, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: intent.OrganizationID}},
		{Name: samlLogoutRelayProvider, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: intent.ProviderID}},
		{Name: samlLogoutRelayRequest, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: intent.RequestDigest[:]}},
	}, nil
}

func validSAMLLogoutRelayInstant(at time.Time) bool {
	return at.Location() == time.UTC && at.Unix() > 0 && at.Year() <= 9999 && at.Nanosecond() == 0
}

func validSSOSAMLLogoutRelayIssueBinding(b identity.CommandBinding) bool {
	local, err := identity.ParseCommandID(b.CorrelationID)
	return err == nil && local != b.CommandID && b.ValidateFor(SSOSAMLLogoutRelayIssueOperation()) == nil &&
		b.ActorKind == authorization.SubjectUser && string(b.ActorID) == string(b.UserID) && b.RecordID == string(b.CommandID)
}

func validSSOSAMLLogoutRelayIssuePlan(b identity.CommandBinding, p CommandPlan) bool {
	if !validSSOSAMLLogoutRelayIssueBinding(b) || p.Feature == nil ||
		*p.Feature != (FeatureRegistration{Operation: SSOSAMLLogoutRelayIssueOperation(), Contributor: SSOSAMLLogoutRelayIssueDescriptor()}) ||
		p.SubjectType != ssoSAMLLogoutRequestSubject || p.Lifecycle == nil || *p.Lifecycle != SSOSAMLLogoutRelayIssueLifecycle() ||
		len(p.Audits) != 1 || p.Audits[0].EventType != ssoSAMLLogoutRelayIssuePurpose || p.Audits[0].RetentionClass != "protected" || !p.Audits[0].Required ||
		p.Capability != nil || p.Delivery != nil || p.RiskEvidence != nil || p.CommandCounters != nil || p.OTP != nil || p.CaptchaReplayReservation || p.CaptchaEvidence != nil {
		return false
	}
	i := p.CapabilityIssuance
	return validCapabilityIssuancePlan(i) && len(i.Grants) == 1 && i.Grants[0].Purpose == ssoSAMLLogoutRelaySettlePurpose &&
		i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == ""
}

func decodeSSOSAMLLogoutRelayIssue(command identity.Command) (SSOSAMLLogoutRelayIssueIntent, bool) {
	spec, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, bearer := command.SessionToken()
	_, otp := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	if !ok || spec.Operation != SSOSAMLLogoutRelayIssueOperation() || !validSSOSAMLLogoutRelayIssueBinding(spec.Binding) ||
		len(spec.Fields) != 6 || cookie || bearer || otp || recovery {
		return SSOSAMLLogoutRelayIssueIntent{}, false
	}
	var intent SSOSAMLLogoutRelayIssueIntent
	for _, field := range spec.Fields {
		v := field.Value
		switch field.Name {
		case samlLogoutRelayLocalCommand:
			intent.LocalCommandID = identity.CommandID(v.Text)
		case samlLogoutRelayOrganization:
			intent.OrganizationID = v.Text
		case samlLogoutRelayProvider:
			intent.ProviderID = v.Text
		case samlLogoutRelayRequest:
			if len(v.Bytes) != len(intent.RequestDigest) {
				return SSOSAMLLogoutRelayIssueIntent{}, false
			}
			intent.RequestDigest = [32]byte(v.Bytes)
		case samlLogoutRelayIssuedAt:
			intent.IssuedAt = v.Time
		case samlLogoutRelayExpiresAt:
			intent.ExpiresAt = v.Time
		}
	}
	want, err := SSOSAMLLogoutRelayIssueFields(intent)
	if err != nil || string(intent.LocalCommandID) != spec.Binding.CorrelationID || !slices.EqualFunc(spec.Fields, want, equalSAMLIDPLogoutField) {
		return SSOSAMLLogoutRelayIssueIntent{}, false
	}
	return intent, true
}

func validSSOSAMLLogoutRelayIssueCommand(command identity.Command, plan CommandPlan) bool {
	intent, ok := decodeSSOSAMLLogoutRelayIssue(command)
	issuance := plan.CapabilityIssuance
	return ok && issuance != nil && len(issuance.Grants) == 1 && issuance.Grants[0].ExpiresAt.Equal(intent.ExpiresAt)
}

func validSSOSAMLLogoutRelayIssueGrant(b identity.CommandBinding, intent SSOSAMLLogoutRelayIssueIntent, p capability.Payload) bool {
	return p.Operation == ssoSAMLLogoutRelaySettlePurpose && p.Resource == b.RecordID && p.CorrelationID == string(intent.LocalCommandID) &&
		p.Subject == string(b.UserID) && p.Tenant == string(b.TenantID) && p.MaxUses == 1 && !p.Bearer &&
		p.IssuedAt.Equal(intent.IssuedAt) && p.NotBefore.Equal(intent.IssuedAt) && p.ExpiresAt.Equal(intent.ExpiresAt)
}

// RequireSSOSAMLLogoutRelayIssue fences the exact participant and original
// immutable command during Apply or the final check. A denial poisons live
// Work. The native owner still proves the local receipt, provider and cutoff.
func (w Work) RequireSSOSAMLLogoutRelayIssue(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, intent SSOSAMLLogoutRelayIssueIntent) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	b, f, lifecycle, err := w.FeatureScope(owner)
	if err != nil || f.Operation != SSOSAMLLogoutRelayIssueOperation() || f.Contributor != SSOSAMLLogoutRelayIssueDescriptor() ||
		lifecycle != SSOSAMLLogoutRelayIssueLifecycle() || w.state.subjectType != ssoSAMLLogoutRequestSubject || w.state.featurePreparationPlan != nil {
		return w.fail(ctx, invalidWork())
	}
	if w.state.featureApplying {
		if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
			return err
		}
	} else if w.state.featureReceipt == nil || w.state.featureCommitCommand == nil || *w.state.featureCommitCommand != command {
		return w.fail(ctx, invalidWork())
	}
	got, valid := decodeSSOSAMLLogoutRelayIssue(command)
	spec, _ := command.Feature()
	if !valid || spec.Binding != b || got != intent {
		return w.fail(ctx, invalidPlan())
	}
	return nil
}
