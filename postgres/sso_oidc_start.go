package postgres

import (
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func ssoOIDCStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oidc-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// SSOOIDCExplicitLinkStartOperation selects authenticated initiation of the
// existing enterprise OIDC transaction. The real native owner must verify
// original session, consent, factor and organization scope. The descriptor
// only selects member-bound state issuance, never sign-in or linking itself.
func SSOOIDCExplicitLinkStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oidc-link-v1",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func ssoOIDCStartSelected(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation.OperationID == "identity.sso.signin-start"
}

func ssoOIDCStartClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == "identity.sso.signin-start" &&
		(*q.feature == ssoOIDCStartOperation() || *q.feature == SSOOIDCExplicitLinkStartOperation())
}

// Admission owns no callback grant; an attached plan for the exact native
// enterprise owner may add one grant scoped to the original anonymous flow or
// the original authenticated member, depending on the fixed schema.
// Mixed protocol purpose, subject overrides and social OAuth custody cannot
// enter this profile. No assertion or eventual session authority is granted.
func validSSOOIDCStart(b identity.CommandBinding, p CommandPlan) bool {
	owner := ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-start", Version: 1}
	if p.Feature == nil || p.Feature.Contributor != owner || b.ValidateFor(p.Feature.Operation) != nil || b.RecordID != string(b.CommandID) {
		return false
	}
	switch p.Feature.Operation {
	case ssoOIDCStartOperation():
		if b.UserID != "" || b.AnonymousFlowID == "" || b.ActorKind != authorization.SubjectServiceAccount {
			return false
		}
	case SSOOIDCExplicitLinkStartOperation():
		if b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || p.CommandCounters != nil {
			return false
		}
	default:
		return false
	}
	if p.SubjectType != "sso_login_transaction" || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}) || p.Capability != nil || p.Delivery != nil {
		return false
	}
	i := p.CapabilityIssuance
	return i == nil || validCapabilityIssuancePlan(i) && len(i.Grants) == 1 && i.Grants[0].Purpose == "identity.sso.oidc-callback" && i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == ""
}

func validSSOOIDCExplicitLinkStartCommand(command identity.Command, p CommandPlan) bool {
	f, ok := command.Feature()
	_, bearer := command.SessionToken()
	_, cookie := command.PreAuthCookie()
	_, otp := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	return ok && f.Operation == SSOOIDCExplicitLinkStartOperation() && p.Feature != nil && p.Feature.Operation == f.Operation &&
		bearer && !cookie && !otp && !recovery && validSSOOIDCStart(f.Binding, p)
}
