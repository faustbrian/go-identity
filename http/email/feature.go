package emailhttp

import identityhttp "github.com/faustbrian/go-identity/http"

// NewConfirmationFeature explicitly selects original-signup confirmation only.
// Omission exposes no handler or metadata. This no-session profile does not
// select verification delivery, scanner validation, address change or auto-login.
func NewConfirmationFeature(c ConfirmationConfig) (identityhttp.Feature, error) {
	return NewConfirmationFeatureWithMiddleware(c, nil)
}

// NewConfirmationFeatureWithMiddleware contributes the actual protected
// operation pipeline and its concrete wire schema, not a placeholder handler.
func NewConfirmationFeatureWithMiddleware(c ConfirmationConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	h, err := NewConfirmationHandlerWithMiddleware(c, m)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/email", OperationID: "identity.email.verification-confirm", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = confirmationWire()
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/email", Operations: []identityhttp.OperationDescriptor{op}})
}
