package mfahttp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// OTPVerifyService borrows the native secondary-OTP login owner. Rate source
// authenticates original subject/continuation/lifetime without comparing a code
// or granting completion. Both calls are bounded, concurrent-safe and owned by
// the same service, which must outlive requests. No TOTP fallback is permitted.
type OTPVerifyService interface {
	OtpVerify(context.Context, mfa.OtpVerifyRequest) (mfa.OtpVerifyResult, error)
	OtpVerificationRateSource(context.Context, mfa.OtpVerifyRequest) (identity.UserID, string, time.Duration, error)
}

// OTPVerifyConfig explicitly selects password-origin secondary-OTP login.
// Network, original cookies, callback, audience and actor policy must match
// native issuance. Service/Rate and the prompt Now callback are borrowed and
// concurrent-safe. MaximumDuration is 1ms..30s; earlier inbound deadlines win.
// Construction performs no IO. Enrollment and active step-up are not selected
// by this profile and cannot be inferred from request input.
type OTPVerifyConfig struct {
	Network         identityhttp.NetworkConfig
	Service         OTPVerifyService
	Rate            *identityhttp.ChallengeVerificationRateLimiter
	Origin          identityhttp.Origin
	CallbackURL     string
	SessionCookie   session.CookiePolicy
	Device          session.BrowserDeviceConfig
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Audience        string
	Now             func() time.Time
	MaximumDuration time.Duration
}

// OTPVerifyResponse contains no-store outcome metadata, never code/proof/bearer
// or synchronizer material. SignedIn denotes fresh credential delivery only.
type OTPVerifyResponse = TOTPVerifyResponse

// NewOTPVerifyHandler selects POST /v1/mfa/otp-verify for password-origin login.
// Closed JSON contains commandID, preAuthID, continuationID, token, code,
// callbackURL and trustDevice. Native original-send custody selects the factor;
// caller identity, factor, challenge generation, recipient and remember-policy
// overrides are forbidden. Unsupported trusted-device requests deny natively.
func NewOTPVerifyHandler(c OTPVerifyConfig) (http.Handler, error) {
	return NewOTPVerifyHandlerWithMiddleware(c, nil)
}

// NewOTPVerifyHandlerWithMiddleware binds hooks to actual decode, IP/original-
// source admission, child admission and native verification phases. Hooks do
// not own input or credentials; final wire commitment checks freshness again.
func NewOTPVerifyHandlerWithMiddleware(c OTPVerifyConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newNativeCompletionHandler(TOTPVerifyConfig{PasswordPrimary: true, Network: c.Network, Rate: c.Rate, Origin: c.Origin, CallbackURL: c.CallbackURL, SessionCookie: c.SessionCookie, Device: c.Device, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Audience: c.Audience, Now: c.Now, MaximumDuration: c.MaximumDuration}, nil, c.Service, m)
}

// Format redacts borrowed owners, credentials and configuration.
func (OTPVerifyConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfahttp.OTPVerifyConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (OTPVerifyConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit text/map-key export.
func (OTPVerifyConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue emits only a fixed redacted marker.
func (OTPVerifyConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.OTPVerifyConfig(redacted)")
}
