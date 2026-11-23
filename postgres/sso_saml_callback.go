package postgres

import identity "github.com/faustbrian/go-identity"

const ssoSAMLSigninPurpose = "identity.sso.saml-acs"

// SSOSAMLSigninOperation identifies the SP-initiated native SAML callback. It
// binds an anonymous flow to its distinct original start; it does not verify
// signatures, consume correlation, or establish session authority.
func SSOSAMLSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/saml", OperationID: ssoSAMLSigninPurpose, SchemaID: "sso-enterprise-saml-acs-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func ssoSAMLSigninDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-login-callback", Version: 1}
}

func ssoSAMLCallbackClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == ssoSAMLSigninPurpose && *q.feature == SSOSAMLSigninOperation()
}
