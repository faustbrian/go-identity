package reference

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/session"
)

// HTTPEmailOTPChangeConfiguration independently selects genuine-primary OTP
// request/confirmation/recovery with the same explicit Origin/device/revision
// fields as HTTPEmailOTPVerificationConfiguration. Native Email.OTPChange,
// original change/notice, sessions and strong HTTPRate storage are required,
// not password/link/signin HTTP routes. Nil exposes no route or metadata.
type HTTPEmailOTPChangeConfiguration HTTPEmailOTPVerificationConfiguration

// Format redacts deployment details and device keys.
func (HTTPEmailOTPChangeConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPEmailOTPChangeConfiguration(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (HTTPEmailOTPChangeConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit configuration export.
func (HTTPEmailOTPChangeConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type emailOTPChangeHTTPState struct {
	transport *emailOTPVerificationHTTPState
	request   *identityhttp.KeyedSecretRateLimiter
}

func (h *emailOTPChangeHTTPState) close() { h.transport.rate.Close(); h.request.Close() }

func composeEmailOTPChangeHTTP(c StoreConfiguration, owner *emailState, sessions *sessionState, shared *httpRateState) (*emailOTPChangeHTTPState, error) {
	if c.HTTPEmailOTPChange == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_email_otp_change"}
	if owner == nil || owner.otpChange == nil || c.Email == nil || c.Email.OTPChange == nil {
		return nil, invalid
	}
	h, err := composeEmailOTPHTTPState(c, HTTPEmailOTPVerificationConfiguration(*c.HTTPEmailOTPChange), c.Email.OTPChange.RequestKeys.Policy.PolicyVersion, sessions, shared)
	if err != nil {
		return nil, err
	}
	request, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: shared.backend, Namespace: c.HTTPRate.Namespace, Key: c.HTTPRate.IdentifierKey, Now: h.now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		h.rate.Close()
		return nil, invalid
	}
	return &emailOTPChangeHTTPState{transport: h, request: request}, nil
}

func (s *Server) emailOTPChangeFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpEmailOTPChange
	if h == nil {
		return nil, nil
	}
	if network.Limits.MaximumFields < 44 || network.Limits.MaximumDepth < 3 {
		return nil, identity.InvalidInputError{Field: "reference_http_email_otp_change"}
	}
	owner, err := f.EmailOTPChange()
	if err != nil {
		return nil, err
	}
	p := h.transport
	feature, err := otphttp.NewEmailChangeFeature(otphttp.EmailChangeConfig{Network: network, Service: owner, Source: owner, RequestRate: h.request, VerificationRate: p.rate, Cookie: s.state.features.session.config.Cookie, Origin: p.origin, CSRFKeys: p.csrf, Device: p.device, PolicyRevision: p.revision, Now: p.now, MaximumDuration: s.state.features.timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}
