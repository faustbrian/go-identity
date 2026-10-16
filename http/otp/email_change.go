package otphttp

import (
	"fmt"
	"net/http"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// EmailChangeConfig explicitly selects new-address OTP change through the
// native service's selected replacement or first-primary profile.
// The native original change owns already-consumed fresh-password admission;
// HTTP cannot invent or renew it. RequestRate enforces canonical keyed
// rate.secret, while VerificationRate owns IP/challenge verification budgets.
// Cookie/Origin/stored CSRF/device configuration is trusted and immutable.
// Owners are borrowed, concurrency-safe and bounded; construction performs no
// IO. This profile issues no session or MFA fallback. First-primary establishment
// additionally requires the native opt-in and original sole-verified policy;
// transport selection alone cannot enable it.
type EmailChangeConfig struct {
	Network          identityhttp.NetworkConfig
	Service          otp.EmailChangeService
	Source           otp.EmailChangeRateSource
	RequestRate      *identityhttp.KeyedSecretRateLimiter
	VerificationRate *identityhttp.ChallengeVerificationRateLimiter
	Cookie           session.CookiePolicy
	Origin           identityhttp.Origin
	CSRFKeys         []session.CSRFKey
	Device           session.BrowserDeviceConfig
	PolicyRevision   authorization.Revision
	Now              func() time.Time
	MaximumDuration  time.Duration
}

// Format redacts deployment owners and keys.
func (EmailChangeConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otphttp.EmailChangeConfig(redacted)"))
}

// MarshalJSON rejects implicit deployment export.
func (EmailChangeConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText rejects implicit deployment export.
func (EmailChangeConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// EmailChangeRecovery carries only original code-free consuming correlation.
// Sharing wire fields with other OTP profiles grants no interchangeability.
type EmailChangeRecovery SigninRecovery

// EmailChangeResponse is never an authentication response. Changed is true
// only for a fresh, verified-primary successor; recovery discloses no address.
// Unknown/committed durability is conserved after subsequent disclosure errors.
type EmailChangeResponse struct {
	Accepted       bool                  `json:"accepted"`
	Changed        bool                  `json:"changed"`
	CommandID      identity.CommandID    `json:"commandID,omitempty"`
	CommitOutcome  string                `json:"commitOutcome"`
	AddressID      identity.IdentifierID `json:"addressID,omitempty"`
	AddressVersion uint64                `json:"addressVersion,omitempty"`
	Recovery       *EmailChangeRecovery  `json:"recovery,omitempty"`
	Error          string                `json:"error,omitempty"`
}

// Only common transport configuration enters the shared pipeline. No old
// verification owner is fabricated or called for a primary-change request.
func (c EmailChangeConfig) transport() EmailVerificationConfig {
	return EmailVerificationConfig{Network: c.Network, VerificationRate: c.VerificationRate, Cookie: c.Cookie, Origin: c.Origin, CSRFKeys: c.CSRFKeys, Device: c.Device, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}
}

// NewEmailChangeRequestHandler constructs POST /v1/otp/email-change-request
// with exact flowID/originCommandID/addressID, one Idempotency-Key and actual
// cookie/Origin/stored synchronizer/device. No mailbox or identity override.
func NewEmailChangeRequestHandler(c EmailChangeConfig) (http.Handler, error) {
	return newEmailOTPHandler(c.transport(), &c, 0, nil)
}

// NewEmailChangeConfirmHandler constructs POST /v1/otp/email-change-confirm
// with exact flowID/sendCommandID/code. Every submission is a new attempt;
// Idempotency-Key, Authorization and caller-selected command IDs are forbidden.
func NewEmailChangeConfirmHandler(c EmailChangeConfig) (http.Handler, error) {
	return newEmailOTPHandler(c.transport(), &c, 1, nil)
}

// NewEmailChangeRecoveryHandler constructs code-free POST
// /v1/otp/email-change-confirm/recover. It requires original possession/CSRF
// and current disclosure permission, not renewed executable session authority.
func NewEmailChangeRecoveryHandler(c EmailChangeConfig) (http.Handler, error) {
	return newEmailOTPHandler(c.transport(), &c, 2, nil)
}
