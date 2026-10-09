package sessionhttp

import (
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

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
	return preAuthFeature(h, false)
}

// NewPreAuthFeatureWithBrowserDevice selects original flow initiation with
// non-authenticating browser correlation. Omission disables both its route and
// metadata; the existing flow-only feature remains unchanged.
func NewPreAuthFeatureWithBrowserDevice(c PreAuthConfig, devices session.BrowserDeviceConfig) (identityhttp.Feature, error) {
	return NewPreAuthFeatureWithBrowserDeviceAndMiddleware(c, devices, nil)
}

// NewPreAuthFeatureWithBrowserDeviceAndMiddleware selects the protected real
// dual-cookie pipeline with typed hooks and accurate selected wire metadata.
func NewPreAuthFeatureWithBrowserDeviceAndMiddleware(c PreAuthConfig, devices session.BrowserDeviceConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	h, err := NewPreAuthHandlerWithBrowserDeviceAndMiddleware(c, devices, middleware)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	return preAuthFeature(h, true)
}

func preAuthFeature(h http.Handler, device bool) (identityhttp.Feature, error) {
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/session", OperationID: "identity.session.preauth-issue", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = preAuthWireProfile(device)
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
