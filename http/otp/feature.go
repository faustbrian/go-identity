package otphttp

import identityhttp "github.com/faustbrian/go-identity/http"

// NewSigninFeature explicitly selects only original-flow OTP signin and its
// concrete wire description. Omit this contribution to expose neither route
// nor metadata. Construction validates borrowed owners without invoking them;
// it does not select Send, recovery, session reads or other OTP purposes.
func NewSigninFeature(c SigninConfig) (identityhttp.Feature, error) {
	return NewSigninFeatureWithMiddleware(c, nil)
}

// NewSigninFeatureWithMiddleware selects the real typed owner phases. The router
// may append middleware without replacing frozen admission or response custody.
// No global registration, provider IO or persistence occurs during construction.
func NewSigninFeatureWithMiddleware(c SigninConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	h, err := NewSigninHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/otp", OperationID: "identity.otp.signin", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = signinWire()
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/otp", Operations: []identityhttp.OperationDescriptor{op}})
}
