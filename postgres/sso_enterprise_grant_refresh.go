package postgres

import identity "github.com/faustbrian/go-identity"

const ssoEnterpriseGrantRefreshPurpose = "identity.sso.provider-token.refresh"

// SSOEnterpriseGrantRefreshOperation selects the exact prepared native grant
// refresh. The descriptor grants no ability to use or rotate a grant.
func SSOEnterpriseGrantRefreshOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: ssoEnterpriseGrantRefreshPurpose,
		SchemaID: ssoEnterpriseGrantRefreshPurpose + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func ssoEnterpriseGrantRefreshDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.enterprise-token-vault", Version: 1}
}

func ssoEnterpriseGrantRefreshClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == ssoEnterpriseGrantRefreshPurpose && *q.feature == SSOEnterpriseGrantRefreshOperation()
}
