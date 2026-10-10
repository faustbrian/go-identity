package passwordhttp

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// NewChangeFeature selects only the real keyed password-change operation.
// Omit this contribution to expose neither route nor metadata. Construction
// validates and freezes the selected credential profile without native IO.
// It does not select verification, signin, registration, reset or recovery.
func NewChangeFeature(c ChangeConfig) (identityhttp.Feature, error) {
	return NewChangeFeatureWithMiddleware(c, nil)
}

// NewChangeFeatureWithMiddleware contributes the same typed owner phases and
// actual wire contract. Base HTTP does not import this optional integration.
// Borrowed owners and trusted hooks must outlive concurrent routed requests;
// hooks cannot replace frozen input or grant primary transaction authority.
func NewChangeFeatureWithMiddleware(c ChangeConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	h, err := NewChangeHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	csrf := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}
	if c.Transport == session.CredentialCookie {
		csrf = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.change", Handler: h, CSRF: csrf, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = changeWire(c)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/password", Operations: []identityhttp.OperationDescriptor{op}})
}
