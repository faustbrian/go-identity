package sessionhttp

import identityhttp "github.com/faustbrian/go-identity/http"

// NewPreAuthFeature selects only original browser-flow initiation. It does not
// select session reads, logout or OTP operations. Omit this contribution to
// disable its route and metadata. Construction validates borrowed dependencies
// without IO; their concurrency and lifetime contracts remain unchanged.
func NewPreAuthFeature(c PreAuthConfig) (identityhttp.Feature, error) {
	return NewPreAuthFeatureWithMiddleware(c, nil)
}

// NewPreAuthFeatureWithMiddleware contributes the same real handler with its
// owned typed phases and concrete wire schema. Hooks cannot substitute original
// admission or manufacture cookie delivery. No global registration is used.
func NewPreAuthFeatureWithMiddleware(c PreAuthConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	h, err := NewPreAuthHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/session", OperationID: "identity.session.preauth-issue", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = preAuthWire()
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/session", Operations: []identityhttp.OperationDescriptor{op}})
}

// NewFeatureWithPreAuth explicitly combines session reads/logout with original
// flow initiation under their single canonical session owner. NewFeature remains
// unchanged. No owner dependency is optional when this combined profile is used.
func NewFeatureWithPreAuth(c SignOutConfig, p PreAuthConfig) (identityhttp.Feature, error) {
	return NewFeatureWithPreAuthAndMiddleware(c, p, nil)
}

// NewFeatureWithPreAuthAndMiddleware retains each operation's typed phases.
// Both profiles are validated before returning a contribution; construction
// performs no owner IO and never returns a partial selection on failure.
func NewFeatureWithPreAuthAndMiddleware(c SignOutConfig, p PreAuthConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	sessions, err := NewFeatureWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	start, err := NewPreAuthFeatureWithMiddleware(p, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/session", Operations: append(sessions.Operations(), start.Operations()...)})
}
