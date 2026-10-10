package passwordhttp

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// BrowserDeviceBearerVerificationConfig explicitly adds signed auxiliary
// browser correlation to bearer verification. Authorization remains the sole
// session credential. Device must match the existing initialization issuer's
// namespace, retained keys and cookie policy. It is not authentication, hardware
// identity or MFA trust. Missing, invalid or expired custody denies; verification
// never issues a cookie or replacement device. Native Authentication risk
// requires this provenance; generic bearer verification supplies none.
type BrowserDeviceBearerVerificationConfig struct {
	Verification BearerVerificationConfig
	Device       session.BrowserDeviceConfig
}

// Format redacts borrowed composition.
func (BrowserDeviceBearerVerificationConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.BrowserDeviceBearerVerificationConfig(redacted)")
}

// MarshalJSON denies implicit composition export.
func (BrowserDeviceBearerVerificationConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit text and map-key export.
func (BrowserDeviceBearerVerificationConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue returns only a fixed redacted marker.
func (BrowserDeviceBearerVerificationConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.BrowserDeviceBearerVerificationConfig(redacted)")
}

// NewBrowserDeviceBearerVerificationHandler requires the original dedicated
// __Host-identity_device cookie in addition to strict bearer authentication.
// Other ambient cookies remain non-authoritative. Scope is the trusted current
// tenant/HTTPS origin; no client device ID or credential fallback is accepted.
// Construction freezes codec policy without IO; borrowed owners outlive calls.
func NewBrowserDeviceBearerVerificationHandler(c BrowserDeviceBearerVerificationConfig) (http.Handler, error) {
	return NewBrowserDeviceBearerVerificationHandlerWithMiddleware(c, nil)
}

// NewBrowserDeviceBearerVerificationHandlerWithMiddleware preserves original
// signed correlation and expiry through trusted synchronous hooks, rate and
// native work. It never renews custody or allows hooks to select another device.
func NewBrowserDeviceBearerVerificationHandlerWithMiddleware(c BrowserDeviceBearerVerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	return newBearerVerificationHandler(c.Verification, middleware, devices)
}

// NewBrowserDeviceBearerVerificationFeature selects only the explicit signed-
// device bearer profile and its wire contract. Omission exposes no capability.
func NewBrowserDeviceBearerVerificationFeature(c BrowserDeviceBearerVerificationConfig) (identityhttp.Feature, error) {
	return NewBrowserDeviceBearerVerificationFeatureWithMiddleware(c, nil)
}

// NewBrowserDeviceBearerVerificationFeatureWithMiddleware contributes typed
// verification phases, never cookie authentication or an initialization route.
func NewBrowserDeviceBearerVerificationFeatureWithMiddleware(c BrowserDeviceBearerVerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{BrowserDeviceBearerVerification: &c}, middleware)
}

func deviceVerificationOperation(c BrowserDeviceBearerVerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, err := NewBrowserDeviceBearerVerificationHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.verify", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = verificationWire(c.Verification, true)
	return op, nil
}
