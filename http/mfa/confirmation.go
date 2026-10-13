package mfahttp

import (
	"context"
	"fmt"
	"github.com/faustbrian/go-authorization"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// EnrollmentConfirmationService authenticates original enable/session custody
// for immutable enrollment quota/deadline metadata before code comparison.
// The source must not decrypt factor secrets, consume attempts or activate a
// factor. Native TotpVerify independently owns current fences and atomic effects.
type EnrollmentConfirmationService interface {
	mfa.TOTPCompletionService
	EnrollmentConfirmationRateSource(context.Context, mfa.TotpVerifyRequest) (time.Duration, time.Time, error)
}

// EnrollmentConfirmationConfig selects only authenticated pending-factor code
// confirmation. Cookie and exact origins are required. Owners are borrowed,
// bounded and concurrency-safe. Rate shares existing verification budgets.
// PolicyRevision and prompt Now are trusted; MaximumDuration is 1ms..30s.
type EnrollmentConfirmationConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Service         EnrollmentConfirmationService
	Rate            *identityhttp.ChallengeVerificationRateLimiter
	Cookie          session.CookiePolicy
	TrustedOrigins  []identityhttp.Origin
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format prevents diagnostic traversal of borrowed runtime custody.
func (EnrollmentConfirmationConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "mfahttp.EnrollmentConfirmationConfig(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (EnrollmentConfirmationConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit text export.
func (EnrollmentConfirmationConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// LogValue returns only a fixed redacted marker.
func (EnrollmentConfirmationConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.EnrollmentConfirmationConfig(redacted)")
}

// NewEnrollmentConfirmationHandler requires X-MFA-Variant: enrollment and
// closed JSON commandID, factorID and code. No login child, trust-device choice,
// subject, authority or session output is accepted. Original cookie/Origin/CSRF
// remains mandatory. It confirms a factor without silently upgrading a session.
func NewEnrollmentConfirmationHandler(c EnrollmentConfirmationConfig) (http.Handler, error) {
	return NewEnrollmentConfirmationHandlerWithMiddleware(c, nil)
}

// NewEnrollmentConfirmationHandlerWithMiddleware binds real cookie, native
// source, rate and protected confirmation phases, retaining original deadlines.
func NewEnrollmentConfirmationHandlerWithMiddleware(c EnrollmentConfirmationConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newPendingFactorHandler(URIConfig{Network: c.Network, Sessions: c.Sessions, Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}, &c, nil, m)
}
