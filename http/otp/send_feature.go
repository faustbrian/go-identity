package otphttp

import identityhttp "github.com/faustbrian/go-identity/http"

// NewEmailSigninSendFeature explicitly selects email-signin Send only. Omit it
// to expose neither route nor metadata. It does not select session/MFA purposes,
// SMS, signin consumption or recovery. Construction invokes no native owner.
func NewEmailSigninSendFeature(c EmailSigninSendConfig) (identityhttp.Feature, error) {
	return NewEmailSigninSendFeatureWithMiddleware(c, nil)
}

// NewEmailSigninSendFeatureWithMiddleware contributes the real protected typed
// pipeline and concrete selected wire contract, retaining native replay custody.
func NewEmailSigninSendFeatureWithMiddleware(c EmailSigninSendConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	h, err := NewEmailSigninSendHandlerWithMiddleware(c, m)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/otp", OperationID: "identity.otp.send", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = emailSigninSendWire()
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/otp", Operations: []identityhttp.OperationDescriptor{op}})
}

// NewEmailSigninFeature selects email Send, consuming signin and outcome-only
// recovery under their single canonical OTP owner. All configurations must
// describe the intended deployment; each is independently validated and frozen.
// Construction performs no native IO and returns no partial contribution.
// This profile does not select initiation or session-read/logout features.
func NewEmailSigninFeature(send EmailSigninSendConfig, signin SigninConfig, recovery SigninRecoveryConfig) (identityhttp.Feature, error) {
	return NewEmailSigninFeatureWithMiddleware(send, signin, recovery, nil)
}

// NewEmailSigninFeatureWithMiddleware preserves each operation's distinct typed
// state, rate admission and response custody without duplicate flow schemes.
func NewEmailSigninFeatureWithMiddleware(send EmailSigninSendConfig, signin SigninConfig, recovery SigninRecoveryConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	start, err := NewEmailSigninSendFeatureWithMiddleware(send, m)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	finish, err := NewSigninFeatureWithRecoveryAndMiddleware(signin, recovery, m)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	operations := start.Operations()
	for i := range operations {
		kept := make([]identityhttp.WireComponent, 0, len(operations[i].Wire.SecuritySchemes))
		for _, scheme := range operations[i].Wire.SecuritySchemes {
			if scheme.Name != "IdentityOTPOriginalFlow" {
				kept = append(kept, scheme)
			}
		}
		operations[i].Wire.SecuritySchemes = kept
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/otp", Operations: append(operations, finish.Operations()...)})
}
