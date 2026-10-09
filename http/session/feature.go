package sessionhttp

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// NewFeature constructs the currently implemented session get/self-signout
// contribution from real typed owner services, without IO or registration.
// It requires one consistent explicit GetConfig/SignOutConfig; nil/zero/closed
// owners deny atomically. Only those two operations are contributed, not future
// session capabilities. Cookie uses exact origin and active primary synchronizer
// state, with no independent token-age claim; bearer contributes CSRFNone and
// never borrows cookie authority. Disabled means omit this feature entirely.
//
// Pass the returned immutable contribution to FeatureServices and
// NewSelectedHandler. Base HTTP never imports this integration. Domain stores,
// transactions, authentication, CSRF and rate remain owned by the configured
// handlers/services. Construction copies metadata; borrowed dependencies must
// outlive concurrent requests. Separate owned Wire contributions describe the
// actual selected JSON, credential and CSRF profile for NewDocumentedHandler;
// direct-contract summaries never become wire response schemas.
func NewFeature(c SignOutConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(c, nil)
}

// NewFeatureWithMiddleware contributes the same two real operations with the
// selected trusted middleware applied independently at their owned phases.
// After-auth hooks obtain either GetState or SignOutState through PipelineValue;
// no shared global principal or duplicate authentication/rate owner is added.
// All selected dependencies are validated before wrapper construction. Hooks
// may be constructed once per operation and must support concurrent requests.
// The factory returns no partial feature on failure; it performs no owner IO.
func NewFeatureWithMiddleware(c SignOutConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	signout, err := NewSignOutHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	get, err := NewGetHandlerWithMiddleware(c.GetConfig, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	csrf := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}
	if c.Transport == session.CredentialCookie {
		csrf = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
	}
	read, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/session", OperationID: "identity.session.get", Handler: get, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	logout, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/session", OperationID: "identity.session.signout", Handler: signout, CSRF: csrf, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	read.Wire = sessionWire(c, false)
	logout.Wire = sessionWire(c, true)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/session", Operations: []identityhttp.OperationDescriptor{read, logout}})
}
