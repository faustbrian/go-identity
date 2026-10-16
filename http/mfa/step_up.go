package mfahttp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// ActiveStepUpService authenticates real session/CSRF and active-factor custody
// before returning fixed native quota policy and the original observation's
// exclusive deadline. The read must not compare codes, decrypt factor secrets,
// debit attempts or issue proof. TotpVerify owns protected verification/effects.
type ActiveStepUpService interface {
	mfa.TOTPCompletionService
	ActiveStepUpRateSource(context.Context, mfa.TotpVerifyRequest) (time.Duration, time.Time, error)
}

// ActiveStepUpConfig selects only authenticated TOTP proof issuance for recovery
// regeneration. Borrowed session/service/rate owners must be bounded and safe
// for concurrent use. Cookie/exact origins/revision/Now are trusted startup
// policy. MaximumDuration is 1ms..30s; earlier caller deadlines win.
type ActiveStepUpConfig struct {
	// Purposes selects exact native management targets (at most four).
	// Empty preserves recovery regeneration. Non-default targets require an
	// explicit body purpose; unselected actions deny, never fall back.
	Purposes        []auth.Purpose
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Service         ActiveStepUpService
	Rate            *identityhttp.ChallengeVerificationRateLimiter
	Cookie          session.CookiePolicy
	TrustedOrigins  []identityhttp.Origin
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed runtime custody and deployment policy.
func (ActiveStepUpConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "mfahttp.ActiveStepUpConfig(redacted)")
}

// MarshalJSON rejects implicit configuration export.
func (ActiveStepUpConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit configuration export.
func (ActiveStepUpConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue returns only a fixed redacted marker.
func (ActiveStepUpConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.ActiveStepUpConfig(redacted)")
}

// NewActiveStepUpHandler owns the singleton X-MFA-Variant: step-up arm of POST
// /v1/mfa/totp-verify without registering it. Closed JSON accepts commandID,
// factorID and code. Original cookie/Origin/CSRF are required; no login proof,
// method/purpose override, trust-device choice or session output is accepted.
// Only a fresh known commit returns the original proofID, never on replay.
func NewActiveStepUpHandler(c ActiveStepUpConfig) (http.Handler, error) {
	return NewActiveStepUpHandlerWithMiddleware(c, nil)
}

// NewActiveStepUpHandlerWithMiddleware binds hooks to actual cookie, native
// custody, quota and verification phases while preserving original deadlines.
func NewActiveStepUpHandlerWithMiddleware(c ActiveStepUpConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if len(c.Purposes) == 0 {
		c.Purposes = []auth.Purpose{"identity.mfa.recovery-regenerate"}
	}
	if len(c.Purposes) > 4 {
		return nil, identityhttp.ErrInvalidInput
	}
	c.Purposes = slices.Clone(c.Purposes)
	for i, purpose := range c.Purposes {
		if purpose != "identity.mfa.recovery-regenerate" && purpose != "identity.mfa.factor-update" && purpose != "identity.mfa.disable" && purpose != "identity.email.change-request" || slices.Contains(c.Purposes[:i], purpose) {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	return newPendingFactorHandler(URIConfig{Network: c.Network, Sessions: c.Sessions, Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}, nil, &c, m)
}
