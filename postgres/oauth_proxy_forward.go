package postgres

import (
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const oauthProxyForwardPurpose = "identity.oauth.proxy-forward"

// OAuthProxyForwardOperation selects only the native completion of one
// production proxy transaction. The anonymous flow is the proxy transaction
// locator, not a production user, pre-auth session, or browser credential.
func OAuthProxyForwardOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "identity/oauth/proxy", OperationID: oauthProxyForwardPurpose,
		SchemaID: oauthProxyForwardPurpose + ".native-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
}

// OAuthProxyForwardDescriptor identifies the OAuth PostgreSQL owner of this
// one closed transaction. Registering a matching name does not grant authority.
func OAuthProxyForwardDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: oauthProxyForwardPurpose, Version: 1}
}

// OAuthProxyForwardLifecycle is a proxy-record effect, never session creation
// or a local account transition. The native adapter still owns the record CAS.
func OAuthProxyForwardLifecycle() LifecyclePlan {
	return LifecyclePlan{EventType: "oauth.proxy.completed.v1", BeforeVersion: 1, AfterVersion: 2}
}

// OAuthProxyForwardContributor validates exact original callback custody. The
// normal preparation owner reserves its original single-use state before
// generation. The native adapter must check current original authority and
// commit only the tokenless proxy outcome; no local identity effect is allowed.
type OAuthProxyForwardContributor interface {
	FeatureAdmissionPreparationContributor
	FeatureCommitContributor
	ValidateOAuthProxyForward(identity.Command, CapabilityPlan) error
}

func validOAuthProxyForwardBinding(b identity.CommandBinding) bool {
	return b.ValidateFor(OAuthProxyForwardOperation()) == nil && b.ActorKind == authorization.SubjectServiceAccount &&
		b.UserID == "" && b.AnonymousFlowID != "" && b.RecordID == b.AnonymousFlowID
}

func oauthProxyForwardClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == oauthProxyForwardPurpose && *q.feature == OAuthProxyForwardOperation()
}

// OAuthProxyForwardConsumption returns the original provisionally consumed
// state to the registered proxy adapter in its synchronous Apply. This does
// not release a preview artifact or grant local authentication authority.
func (w Work) OAuthProxyForwardConsumption(owner OAuthProxyForwardContributor) (CapabilityReservationBinding, error) {
	return w.providerSigninConsumption(owner, OAuthProxyForwardOperation())
}
