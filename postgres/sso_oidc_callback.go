package postgres

import (
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const ssoOIDCSigninPurpose = "identity.sso.oidc-callback"

func ssoOIDCSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/oidc", OperationID: ssoOIDCSigninPurpose, SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func ssoOIDCSigninDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-callback", Version: 1}
}

func ssoOIDCCallbackClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == ssoOIDCSigninPurpose && ssoOIDCConsumptionOperation(*q.feature)
}

func ssoOIDCConsumptionOperation(op identity.FeatureOperation) bool {
	return op == ssoOIDCSigninOperation() || op == SSOOIDCExplicitLinkCallbackOperation()
}

// The signed enterprise state is resource-bound to the original start
// command. The callback is a different command; it cannot pick a user.
func validSSOOIDCSigninBinding(b identity.CommandBinding) bool {
	start, err := identity.ParseCommandID(b.RecordID)
	return err == nil && start != b.CommandID && b.ValidateFor(ssoOIDCSigninOperation()) == nil && b.ActorKind == authorization.SubjectServiceAccount && b.UserID == "" && b.AnonymousFlowID != ""
}
