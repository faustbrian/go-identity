package otphttp

import identityhttp "github.com/faustbrian/go-identity/http"

// NewEmailChangeFeature independently selects genuine-primary OTP request,
// consuming confirmation and original metadata recovery. Native selection alone
// enables none of these routes. Missing owners/policies deny atomically.
func NewEmailChangeFeature(c EmailChangeConfig) (identityhttp.Feature, error) {
	return NewEmailChangeFeatureWithMiddleware(c, nil)
}

// NewEmailChangeFeatureWithMiddleware retains the real typed owner phases and
// closed secret-safe wire shapes through operation middleware binding. It does
// not select verification-only, initial-primary, signin or stronger-factor routes.
func NewEmailChangeFeatureWithMiddleware(c EmailChangeConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	ops := make([]identityhttp.OperationDescriptor, 0, 3)
	for mode, id := range []string{"identity.otp.email-change-request", "identity.otp.email-change-confirm", "identity.otp.email-change-confirm.recover"} {
		h, err := newEmailOTPHandler(c.transport(), &c, mode, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/otp", OperationID: id, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = emailOTPWire(c.transport(), mode, true)
		if mode != 0 {
			op.Wire.SecuritySchemes = nil
		}
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/otp", Operations: ops})
}
