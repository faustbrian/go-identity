package postgres

import (
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const ssoOIDCSigninPurpose = "identity.sso.oidc-callback"
const ssoOAuth2SigninPurpose = "identity.sso.oauth-callback"

func ssoOIDCSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/oidc", OperationID: ssoOIDCSigninPurpose, SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func ssoOIDCSigninDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-callback", Version: 1}
}

// SSOOAuth2SigninOperation selects only the native anonymous enterprise OAuth
// callback. The operation does not establish provider or session authority.
func SSOOAuth2SigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/oauth2", OperationID: ssoOAuth2SigninPurpose, SchemaID: "sso-enterprise-oauth2-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func ssoOAuth2SigninDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oauth2-login-callback", Version: 1}
}

func ssoOAuth2CallbackClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == ssoOAuth2SigninPurpose && *q.feature == SSOOAuth2SigninOperation()
}

func ssoEnterpriseCallbackClaim(q claimRequest) bool {
	return ssoOIDCCallbackClaim(q) || ssoOAuth2CallbackClaim(q)
}

func ssoOIDCCallbackClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == ssoOIDCSigninPurpose && ssoOIDCConsumptionOperation(*q.feature)
}

func ssoOIDCConsumptionOperation(op identity.FeatureOperation) bool {
	return op == ssoOIDCSigninOperation() || op == SSOOIDCExplicitLinkCallbackOperation()
}

func ssoEnterpriseConsumptionOperation(op identity.FeatureOperation) bool {
	return ssoOIDCConsumptionOperation(op) || op == SSOOAuth2SigninOperation()
}

// The signed enterprise state is resource-bound to the original start
// command. The callback is a different command; it cannot pick a user.
func validSSOOIDCSigninBinding(b identity.CommandBinding) bool {
	return validEnterpriseSigninBinding(b, ssoOIDCSigninOperation())
}

func validSSOOAuth2SigninBinding(b identity.CommandBinding) bool {
	return validEnterpriseSigninBinding(b, SSOOAuth2SigninOperation())
}

func validEnterpriseSigninBinding(b identity.CommandBinding, op identity.FeatureOperation) bool {
	start, err := identity.ParseCommandID(b.RecordID)
	return err == nil && start != b.CommandID && b.ValidateFor(op) == nil && b.ActorKind == authorization.SubjectServiceAccount && b.UserID == "" && b.AnonymousFlowID != ""
}
