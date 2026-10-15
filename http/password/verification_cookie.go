package passwordhttp

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// CookieVerificationConfig selects exclusive cookie-session verification through
// the distinct native protected port, never a bearer fallback. Sessions and
// Verification must share primary authority. Cookie is the original secure
// session policy; TrustedOrigins is an exact HTTPS allowlist without Referer
// fallback. Device must match the original browser initialization issuer; it
// supplies correlation, not authentication or MFA. Construction freezes policy
// without IO. Borrowed concurrent owners and prompt Now must outlive requests.
// Rate is the shared native atomic IP/subject profile. PolicyRevision is positive
// trusted startup policy; MaximumDuration is 1ms..30s and never extends deadlines.
type CookieVerificationConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Verification    password.CookieVerificationService
	Rate            *identityhttp.PasswordVerificationRateLimiter
	Cookie          session.CookiePolicy
	TrustedOrigins  []identityhttp.Origin
	Device          session.BrowserDeviceConfig
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed composition for every verb.
func (CookieVerificationConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.CookieVerificationConfig(redacted)")
}

// MarshalJSON denies implicit composition export.
func (CookieVerificationConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies text and map-key export.
func (CookieVerificationConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue returns only a fixed redacted marker.
func (CookieVerificationConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.CookieVerificationConfig(redacted)")
}

type cookieVerificationProfile struct {
	service password.CookieVerificationService
	name    string
	csrf    *identityhttp.CSRFDecoder
}

// NewCookieVerificationHandler constructs exact POST /v1/password/verify with
// original session cookie, exact Origin, sole X-CSRF-Token and signed device
// cookie. Closed JSON contains password/purpose/action/audience only. No key,
// credential alternative, issuance, renewal or automatic retry is accepted.
// Native primary fences remain authoritative; decoding grants no proof authority.
func NewCookieVerificationHandler(c CookieVerificationConfig) (http.Handler, error) {
	return NewCookieVerificationHandlerWithMiddleware(c, nil)
}

// NewCookieVerificationHandlerWithMiddleware retains the original custody and
// validity through trusted synchronous hooks, admission and one protected native
// call. Hooks cannot replace input or emit credentials. All exits destroy the
// handler-owned password. Only fresh error-free known commit delivers proof.
func NewCookieVerificationHandlerWithMiddleware(c CookieVerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilOwner(c.Verification) {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil || cookie.Name == "__Host-identity_device" {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	common := BearerVerificationConfig{Network: c.Network, Sessions: c.Sessions, Rate: c.Rate, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}
	return newVerificationHandler(common, middleware, devices, &cookieVerificationProfile{service: c.Verification, name: cookie.Name, csrf: csrf})
}

// NewCookieVerificationFeature selects only protected cookie verification and
// its actual wire contract. Omission exposes neither route nor metadata.
func NewCookieVerificationFeature(c CookieVerificationConfig) (identityhttp.Feature, error) {
	return NewCookieVerificationFeatureWithMiddleware(c, nil)
}

// NewCookieVerificationFeatureWithMiddleware contributes the existing typed
// owner phases without selecting browser initialization or a recovery endpoint.
func NewCookieVerificationFeatureWithMiddleware(c CookieVerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{CookieVerification: &c}, middleware)
}

func cookieVerificationOperation(c CookieVerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, err := NewCookieVerificationHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.verify", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = cookieVerificationWire(c)
	return op, nil
}
