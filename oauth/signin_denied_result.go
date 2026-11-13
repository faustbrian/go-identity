package oauth

import identity "github.com/faustbrian/go-identity"

// NewDeniedSigninCallbackResult projects only an exact committed anonymous
// provider-denial transition and original allowlisted error callback. It grants
// no identity, session, credential delivery or current authentication. Native
// state/browser/current-authority admission remains mandatory before receipt.
func NewDeniedSigninCallbackResult(receipt identity.CommandResult, callback ValidatedCallbackURL) (SigninCallbackResult, error) {
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "identity.oauth.callback.anonymous-denied-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if receipt.Validate() != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Feature.Operation != op || receipt.Feature.BeforeVersion != 1 || receipt.Feature.AfterVersion != 2 || callback.raw == "" {
		return SigninCallbackResult{}, failure(InvalidInput, nil)
	}
	return SigninCallbackResult{Outcome: IdentityDeliveryResult{denied: &callback}}, nil
}
