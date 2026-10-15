package mfahttp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// RecoveryUseService authenticates the original continuation for rate admission
// and completes it through the same native owner. Rate-source metadata grants
// no factor authority. Both methods must be bounded and concurrent-safe.
type RecoveryUseService interface {
	RecoveryUse(context.Context, mfa.RecoveryUseRequest) (mfa.RecoveryUseResult, error)
	RecoveryVerificationRateSource(context.Context, mfa.RecoveryUseRequest) (identity.UserID, string, time.Duration, error)
}

// RecoveryUseConfig explicitly selects recovery-code login completion. Borrowed
// service/rate/clock owners must be concurrent-safe and outlive requests. Cookie,
// device, origin, audience and primary selection must match native issuance.
// Construction performs no IO. Earlier inbound deadlines win.
type RecoveryUseConfig struct {
	PasswordPrimary bool
	Network         identityhttp.NetworkConfig
	Service         RecoveryUseService
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

// NewRecoveryUseHandler selects POST /v1/mfa/recovery-use. Its closed input has
// original command/continuation/browser IDs, proof, recoveryCode and callback.
// No caller user, factor, set, remember policy, OTP or trust-device choice is
// accepted. Only fresh committed native session custody may be delivered.
func NewRecoveryUseHandler(c RecoveryUseConfig) (http.Handler, error) {
	return NewRecoveryUseHandlerWithMiddleware(c, nil)
}

// NewRecoveryUseHandlerWithMiddleware binds hooks to the shared guarded transport
// phases, not a TOTP fallback. Hooks cannot replace private recovery input or
// reveal credentials after denial, cancellation, replay or expired custody.
func NewRecoveryUseHandlerWithMiddleware(c RecoveryUseConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newCompletionHandler(TOTPVerifyConfig{PasswordPrimary: c.PasswordPrimary, Network: c.Network, Rate: c.Rate, Origin: c.Origin, CallbackURL: c.CallbackURL, SessionCookie: c.SessionCookie, Device: c.Device, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Audience: c.Audience, Now: c.Now, MaximumDuration: c.MaximumDuration}, c.Service, m)
}

// Format redacts borrowed owner and configuration custody.
func (RecoveryUseConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfahttp.RecoveryUseConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (RecoveryUseConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit text/map-key export.
func (RecoveryUseConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue emits only a fixed redacted marker.
func (RecoveryUseConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.RecoveryUseConfig(redacted)")
}
