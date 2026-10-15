package emailhttp

import (
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewConfirmationFeature explicitly selects original-signup confirmation only.
// Omission exposes no handler or metadata. This no-session profile does not
// select verification delivery, scanner validation, address change or auto-login.
func NewConfirmationFeature(c ConfirmationConfig) (identityhttp.Feature, error) {
	return NewConfirmationFeatureWithMiddleware(c, nil)
}

// NewConfirmationFeatureWithMiddleware contributes the actual protected
// operation pipeline and its concrete wire schema, not a placeholder handler.
func NewConfirmationFeatureWithMiddleware(c ConfirmationConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{SignupConfirmation: &c}, m)
}

func newEmailConfirmationOperation(h http.Handler, action, profile string) (identityhttp.OperationDescriptor, error) {
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/email", OperationID: action, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = confirmationWireFor(action, profile)
	return op, nil
}
