package reference

import (
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/session"
)

// HTTPEmailOTPVerificationConfiguration explicitly selects authenticated self
// pending-email OTP Send/verification/recovery. Native Email.OTPVerification,
// sessions and strong HTTP rate storage are required, not their HTTP routes or
// OTP signin. Device is the explicit existing browser-device deployment profile;
// no missing device is minted by Send. Another HTTP OTP Send profile conflicts
// rather than silently selecting one. Nil exposes no route or metadata.
type HTTPEmailOTPVerificationConfiguration struct {
	Origin         string
	Device         session.BrowserDeviceConfig
	PolicyRevision authorization.Revision
}

func (HTTPEmailOTPVerificationConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPEmailOTPVerificationConfiguration(redacted)"))
}
func (HTTPEmailOTPVerificationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (HTTPEmailOTPVerificationConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type emailOTPVerificationHTTPState struct {
	origin   identityhttp.Origin
	device   session.BrowserDeviceConfig
	csrf     []session.CSRFKey
	revision authorization.Revision
	now      func() time.Time
	rate     *identityhttp.ChallengeVerificationRateLimiter
}

func composeEmailOTPVerificationHTTP(c StoreConfiguration, owner *emailState, sessions *sessionState, shared *httpRateState) (*emailOTPVerificationHTTPState, error) {
	if c.HTTPEmailOTPVerification == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_email_otp"}
	if c.HTTPEmailSignin != nil || owner == nil || owner.otpVerification == nil || c.Email == nil || c.Email.OTPVerification == nil {
		return nil, invalid
	}
	p := *c.HTTPEmailOTPVerification
	return composeEmailOTPHTTPState(c, p, c.Email.OTPVerification.RequestKeys.Policy.PolicyVersion, sessions, shared)
}

// Shared cookie/Origin/device/rate composition selects no workflow or route.
func composeEmailOTPHTTPState(c StoreConfiguration, p HTTPEmailOTPVerificationConfiguration, revision uint64, sessions *sessionState, shared *httpRateState) (*emailOTPVerificationHTTPState, error) {
	invalid := identity.InvalidInputError{Field: "reference_http_email_otp"}
	if sessions == nil || sessions.reader == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || shared == nil || c.HTTPRate == nil || p.PolicyRevision == 0 || uint64(p.PolicyRevision) != revision {
		return nil, invalid
	}
	u, err := url.Parse(p.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != p.Origin {
		return nil, invalid
	}
	if _, err := session.NewBrowserDeviceCodec(p.Device); err != nil {
		return nil, invalid
	}
	if len(c.Session.CSRFKeys) == 0 {
		return nil, invalid
	}
	rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: shared.backend, Namespace: c.HTTPRate.Namespace, Key: c.HTTPRate.IdentifierKey, Now: c.Session.Native.Execution.Clock.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	p.Device.Keys = slices.Clone(p.Device.Keys)
	return &emailOTPVerificationHTTPState{origin: identityhttp.Origin(p.Origin), device: p.Device, csrf: slices.Clone(c.Session.CSRFKeys), revision: p.PolicyRevision, now: c.Session.Native.Execution.Clock.Now, rate: rate}, nil
}

func (s *Server) emailOTPVerificationFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpEmailOTPVerification
	if h == nil {
		return nil, nil
	}
	// Closed original recovery includes a 32-element digest and nested attempt.
	if network.Limits.MaximumFields < 44 || network.Limits.MaximumDepth < 3 {
		return nil, identity.InvalidInputError{Field: "reference_http_email_otp"}
	}
	owner, err := f.EmailOTPVerification()
	if err != nil {
		return nil, err
	}
	feature, err := otphttp.NewEmailVerificationFeature(otphttp.EmailVerificationConfig{Network: network, Service: owner, Source: owner, DeliveryRate: s.state.httpRate.limiter, VerificationRate: h.rate, Cookie: s.state.features.session.config.Cookie, Origin: h.origin, CSRFKeys: h.csrf, Device: h.device, PolicyRevision: h.revision, Now: h.now, MaximumDuration: s.state.features.timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}
