package otphttp

import (
	"fmt"
	"net/http"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
)

// PhoneSigninSendConfig selects original-flow existing-account SMS signin
// issuance, never enrollment or authentication. Service is the genuine native
// phone workflow, and Policy is its same immutable canonical-number profile.
// Owners and clock are borrowed, concurrent-safe and bounded; construction does
// no IO. Device and flow cookies must match trusted original initiation. No
// field selects a user, challenge, purpose, target or replacement remember policy.
type PhoneSigninSendConfig struct {
	Network         identityhttp.NetworkConfig
	Service         phone.SigninService
	Policy          *phone.NumberPolicy
	Rate            *identityhttp.AuthRateLimiter
	Origin          identityhttp.Origin
	FlowCookie      session.CookiePolicy
	Device          session.BrowserDeviceConfig
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed runtime owners and deployment custody.
func (PhoneSigninSendConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otphttp.PhoneSigninSendConfig(redacted)"))
}

// MarshalJSON denies implicit deployment configuration export.
func (PhoneSigninSendConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit deployment configuration export and map-key use.
func (PhoneSigninSendConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

type phoneSigninSendProfile struct {
	owner  phone.SigninService
	policy *phone.NumberPolicy
}

// NewPhoneSigninSendHandler constructs only POST /v1/phone/send-signin. Closed
// JSON requires flowID and number; one header Idempotency-Key, exact HTTPS
// tenant/Origin, original flow and existing signed browser-device possession
// are mandatory. Phone owns normalization and native original-target admission;
// shared delivery budgets precede one SendSignin call. Accepted includes native
// suppression, never delivery or verified ownership. No credential is returned.
// Status, response guarding, cancellation and unknown-outcome semantics match
// NewEmailSigninSendHandler. Construction selects no route or feature metadata.
func NewPhoneSigninSendHandler(c PhoneSigninSendConfig) (http.Handler, error) {
	return NewPhoneSigninSendHandlerWithMiddleware(c, nil)
}

// NewPhoneSigninSendHandlerWithMiddleware preserves the existing real typed
// issuance pipeline, with a closed phone path/action and no email fallback.
func NewPhoneSigninSendHandlerWithMiddleware(c PhoneSigninSendConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilOwner(c.Service) || c.Policy == nil || c.Policy.Profile() != phone.CurrentNumberProfile() {
		return nil, identityhttp.ErrInvalidInput
	}
	policy := *c.Policy
	return newSigninSendHandler(EmailSigninSendConfig{Network: c.Network, Rate: c.Rate, Origin: c.Origin, FlowCookie: c.FlowCookie, Device: c.Device, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, TargetID: "identity.phone.signin", Now: c.Now, MaximumDuration: c.MaximumDuration}, m, &phoneSigninSendProfile{owner: c.Service, policy: &policy})
}
