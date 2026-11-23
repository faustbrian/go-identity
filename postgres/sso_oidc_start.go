package postgres

import (
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
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

// SSOOAuth2SigninStartOperation selects anonymous enterprise OAuth 2.0 state
// issuance by the native SSO owner. It does not authorize a callback or session.
func SSOOAuth2SigninStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oauth2-v1",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// SSOSAMLSigninStartOperation selects the native SP-initiated SAML browser
// transaction. Its single grant is only for the original SAML ACS; this
// selection neither signs a request nor authorizes a callback or session.
func SSOSAMLSigninStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.saml-start", SchemaID: "identity.sso.saml-start.v1",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func ssoEnterpriseStartProfile(op identity.FeatureOperation) (ContributorDescriptor, capability.Purpose) {
	const owner = "sso/postgres"
	switch op {
	case ssoOIDCStartOperation(), SSOOIDCExplicitLinkStartOperation():
		return ContributorDescriptor{Owner: owner, ContractID: "sso.oidc-login-start", Version: 1}, "identity.sso.oidc-callback"
	case SSOOAuth2SigninStartOperation():
		return ContributorDescriptor{Owner: owner, ContractID: "sso.oauth2-login-start", Version: 1}, "identity.sso.oauth-callback"
	case SSOSAMLSigninStartOperation():
		return ContributorDescriptor{Owner: owner, ContractID: "sso.saml-login-start", Version: 1}, "identity.sso.saml-acs"
	default:
		return ContributorDescriptor{}, ""
	}
}

func enterpriseSigninStartOperationID(operation string) bool {
	return operation == "identity.sso.signin-start" || operation == SSOSAMLSigninStartOperation().OperationID
}

func ssoEnterpriseStartSelected(p CommandPlan) bool {
	return p.Feature != nil && enterpriseSigninStartOperationID(p.Feature.Operation.OperationID)
}

func ssoEnterpriseStartClaim(q claimRequest) bool {
	if q.feature == nil || q.purpose != q.feature.OperationID {
		return false
	}
	_, purpose := ssoEnterpriseStartProfile(*q.feature)
	return purpose != ""
}

// Admission owns no callback grant; an attached plan for the exact native
// enterprise owner may add one grant scoped to the original anonymous flow or
// the original authenticated member, depending on the fixed schema.
// Mixed protocol purpose, subject overrides and social OAuth custody cannot
// enter this profile. No assertion or eventual session authority is granted.
func validSSOEnterpriseStart(b identity.CommandBinding, p CommandPlan) bool {
	if p.Feature == nil || b.ValidateFor(p.Feature.Operation) != nil || b.RecordID != string(b.CommandID) {
		return false
	}
	op := p.Feature.Operation
	owner, purpose := ssoEnterpriseStartProfile(op)
	if purpose == "" || p.Feature.Contributor != owner {
		return false
	}
	switch op {
	case ssoOIDCStartOperation(), SSOOAuth2SigninStartOperation(), SSOSAMLSigninStartOperation():
		if b.UserID != "" || b.AnonymousFlowID == "" || b.ActorKind != authorization.SubjectServiceAccount || op != ssoOIDCStartOperation() && p.CommandCounters != nil {
			return false
		}
	case SSOOIDCExplicitLinkStartOperation():
		if b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || p.CommandCounters != nil {
			return false
		}
	default:
		return false
	}
	event := "oauth.rp_transaction.created.v1"
	if op == SSOSAMLSigninStartOperation() {
		event = "sso.saml_transaction.created.v1"
	}
	if p.SubjectType != "sso_login_transaction" || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: event, AfterVersion: 1}) || p.Capability != nil || p.Delivery != nil {
		return false
	}
	i := p.CapabilityIssuance
	return i == nil || validCapabilityIssuancePlan(i) && len(i.Grants) == 1 && i.Grants[0].Purpose == purpose && i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == ""
}

func validSSOOIDCExplicitLinkStartCommand(command identity.Command, p CommandPlan) bool {
	f, ok := command.Feature()
	_, bearer := command.SessionToken()
	_, cookie := command.PreAuthCookie()
	_, otp := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	return ok && f.Operation == SSOOIDCExplicitLinkStartOperation() && p.Feature != nil && p.Feature.Operation == f.Operation &&
		bearer && !cookie && !otp && !recovery && validSSOEnterpriseStart(f.Binding, p)
}

func validSSOOAuth2StartCommand(command identity.Command, p CommandPlan) bool {
	return validAnonymousEnterpriseStartCommand(command, p, SSOOAuth2SigninStartOperation())
}

func validSSOSAMLStartCommand(command identity.Command, p CommandPlan) bool {
	return validAnonymousEnterpriseStartCommand(command, p, SSOSAMLSigninStartOperation())
}

func validAnonymousEnterpriseStartCommand(command identity.Command, p CommandPlan, selected identity.FeatureOperation) bool {
	f, ok := command.Feature()
	_, bearer := command.SessionToken()
	_, cookie := command.PreAuthCookie()
	_, otp := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	return ok && f.Operation == selected && p.Feature != nil && p.Feature.Operation == f.Operation &&
		cookie && !bearer && !otp && !recovery && validSSOEnterpriseStart(f.Binding, p)
}
