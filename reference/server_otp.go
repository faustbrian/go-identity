package reference

import (
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/session"
)

// HTTPEmailSigninConfiguration explicitly selects email OTP Send, consuming
// signin and original outcome recovery. Nil selects no OTP routes or metadata.
// Native OTP signin, HTTP original-flow initiation, its dedicated browser-device
// profile and strong HTTP rate storage are required. Address is owned email
// normalization policy; ActorID, PolicyRevision and TargetID are trusted
// deployment values, not request-controlled authority. The revision must match
// the native Send and signin query policies, with one exact authorization handle.
// Audience and session cookie are taken from the selected native issuer.
type HTTPEmailSigninConfiguration struct {
	Address        email.AddressPolicy
	ActorID        identity.ActorID
	PolicyRevision authorization.Revision
	TargetID       string
}

// Format redacts deployment and normalization policy.
func (HTTPEmailSigninConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPEmailSigninConfiguration(redacted)")
}

// MarshalJSON rejects implicit runtime configuration export.
func (HTTPEmailSigninConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// MarshalText rejects implicit runtime configuration export.
func (HTTPEmailSigninConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

type emailSigninHTTPState struct {
	config        HTTPEmailSigninConfiguration
	sessionCookie session.CookiePolicy
	audience      string
}

func composeEmailSigninHTTP(c StoreConfiguration, preauth *preAuthHTTPState) (*emailSigninHTTPState, error) {
	if c.HTTPEmailSignin == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_email_signin"}
	if c.OTP == nil || c.OTP.Signin == nil || preauth == nil || preauth.device == nil || c.HTTPRate == nil || c.OTP.Signin.Coordinator.QueryPolicy == nil {
		return nil, invalid
	}
	p := *c.HTTPEmailSignin
	query := c.OTP.Signin.Coordinator.QueryPolicy
	if p.PolicyRevision == 0 || uint64(p.PolicyRevision) != c.OTP.RequestKeys.Policy.PolicyVersion || uint64(p.PolicyRevision) != query.PolicyVersion || !sameServerAuthorization(c.OTP.RequestKeys.Policy.Authorization, query.Authorization) {
		return nil, invalid
	}
	if _, err := email.NewAddressParser(p.Address); err != nil {
		return nil, invalid
	}
	return &emailSigninHTTPState{config: p, sessionCookie: c.OTP.Signin.Issuer.Cookie, audience: c.OTP.Signin.Profile.Audience}, nil
}

func (s *Server) emailSigninFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpEmailSignin
	if h == nil {
		return nil, nil
	}
	// Recovery's native envelope contains 12 object members and a 32-byte
	// digest array. The shared decoder counts both members and array elements;
	// Recovery's nested attempt and digest require depth three. Smaller limits
	// would advertise a route that cannot accept any recovery.
	if network.Limits.MaximumFields < 44 || network.Limits.MaximumDepth < 3 {
		return nil, identity.InvalidInputError{Field: "reference_http_email_signin"}
	}
	p := s.state.features.httpPreAuth
	owner, err := f.OTP()
	if err != nil {
		return nil, err
	}
	signin, err := f.OTPSignin()
	if err != nil {
		return nil, err
	}
	source, err := f.OTPSigninSource()
	if err != nil {
		return nil, err
	}
	common := h.config
	rate := s.state.httpRate.limiter
	origin := identityhttp.Origin(p.deployment.Origin)
	timeout := s.state.features.timeout
	feature, err := otphttp.NewEmailSigninFeature(
		otphttp.EmailSigninSendConfig{Network: network, Service: owner, Rate: rate, Origin: origin, FlowCookie: p.deployment.Cookie, Device: *p.device, Address: common.Address, ActorID: common.ActorID, PolicyRevision: common.PolicyRevision, TargetID: common.TargetID, Now: time.Now, MaximumDuration: timeout},
		otphttp.SigninConfig{Network: network, Service: signin, Source: source, Rate: rate, Origin: origin, FlowCookie: p.deployment.Cookie, SessionCookie: h.sessionCookie, ActorID: common.ActorID, PolicyRevision: common.PolicyRevision, Audience: h.audience, Now: time.Now, MaximumDuration: timeout},
		otphttp.SigninRecoveryConfig{Network: network, Service: signin, Rate: rate, Origin: origin, FlowCookie: p.deployment.Cookie, ActorID: common.ActorID, PolicyRevision: common.PolicyRevision, MaximumDuration: timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}
