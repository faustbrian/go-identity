package otphttp

import identityhttp "github.com/faustbrian/go-identity/http"

// NewSigninRecoveryFeature explicitly selects historical recovery only. It
// neither selects signin/Send nor advertises live authentication. Construction
// validates dependencies without native IO; omission exposes no route/metadata.
func NewSigninRecoveryFeature(c SigninRecoveryConfig) (identityhttp.Feature, error) {
	return NewSigninRecoveryFeatureWithMiddleware(c, nil)
}

// NewSigninRecoveryFeatureWithMiddleware binds the real recovery phases and
// concrete wire schema. The selected native owner retains authorization of
// original historical custody; hooks cannot supply credentials or new attempts.
func NewSigninRecoveryFeatureWithMiddleware(c SigninRecoveryConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	h, err := NewSigninRecoveryHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/otp", OperationID: "identity.otp.signin.recover", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = signinRecoveryWire()
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/otp", Operations: []identityhttp.OperationDescriptor{op}})
}

// NewSigninFeatureWithRecovery selects both operations under their one canonical
// owner. Each retains its own validated frozen configuration; invalid selection
// returns no partial contribution. Do not supply two separate OTP features to
// one router: duplicate feature ownership is rejected.
func NewSigninFeatureWithRecovery(c SigninConfig, recovery SigninRecoveryConfig) (identityhttp.Feature, error) {
	return NewSigninFeatureWithRecoveryAndMiddleware(c, recovery, nil)
}

// NewSigninFeatureWithRecoveryAndMiddleware combines both real typed pipelines
// without global registration, native calls or credential-sharing shortcuts.
func NewSigninFeatureWithRecoveryAndMiddleware(c SigninConfig, recovery SigninRecoveryConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	signin, err := NewSigninFeatureWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	history, err := NewSigninRecoveryFeatureWithMiddleware(recovery, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	operations := history.Operations()
	// Standalone recovery declares its original-flow scheme. In this combined
	// profile signin already owns the same declaration; recovery references it.
	// Keep the base composer's duplicate-component rejection unchanged.
	for i := range operations {
		operations[i].Wire.SecuritySchemes = nil
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/otp", Operations: append(signin.Operations(), operations...)})
}
