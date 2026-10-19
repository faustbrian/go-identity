package reference

import (
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
)

// HTTPPhoneOTPSigninConfiguration explicitly selects existing-account SMS-code
// request, signin and original code-free recovery. Native phone OTP, HTTPPreAuth
// with signed browser-device custody, HTTPRate and Session are required. ActorID
// and PolicyRevision are trusted deployment authority, never client input. The
// revision and authorization owner must match native send/query policy. Cookies,
// audience and original-flow policy come from those actual selected owners.
type HTTPPhoneOTPSigninConfiguration struct {
	ActorID        identity.ActorID
	PolicyRevision authorization.Revision
}

// Format redacts deployment authority.
func (HTTPPhoneOTPSigninConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPPhoneOTPSigninConfiguration(redacted)"))
}

// MarshalJSON denies implicit runtime configuration export.
func (HTTPPhoneOTPSigninConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// MarshalText denies implicit runtime configuration export.
func (HTTPPhoneOTPSigninConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

type phoneOTPSigninHTTPState struct {
	config HTTPPhoneOTPSigninConfiguration
	common emailSigninHTTPState
}

func composePhoneOTPSigninHTTP(c StoreConfiguration, native *phoneOTPSigninState, original *preAuthHTTPState) (*phoneOTPSigninHTTPState, error) {
	if c.HTTPPhoneOTPSignin == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_phone_otp_signin"}
	if native == nil || c.OTP == nil || c.OTP.Signin == nil || c.OTP.PreAuth == nil || original == nil || original.device == nil || c.HTTPRate == nil || c.OTP.Signin.Coordinator.QueryPolicy == nil {
		return nil, invalid
	}
	p := *c.HTTPPhoneOTPSignin
	query := c.OTP.Signin.Coordinator.QueryPolicy
	if p.PolicyRevision == 0 || uint64(p.PolicyRevision) != c.PhoneOTPSignin.RequestKeys.Policy.PolicyVersion || uint64(p.PolicyRevision) != query.PolicyVersion || !sameServerAuthorization(c.PhoneOTPSignin.RequestKeys.Policy.Authorization, query.Authorization) {
		return nil, invalid
	}
	return &phoneOTPSigninHTTPState{config: p, common: emailSigninHTTPState{sessionCookie: c.OTP.Signin.Issuer.Cookie, audience: c.OTP.Signin.Profile.Audience}}, nil
}

func (s *Server) phoneOTPSigninFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpPhoneOTPSignin
	if h == nil {
		return nil, nil
	}
	// The unchanged native recovery envelope needs twelve members and its
	// 32-element fingerprint at depth three, as in the email OTP profile.
	if network.Limits.MaximumFields < 44 || network.Limits.MaximumDepth < 3 {
		return nil, identity.InvalidInputError{Field: "reference_http_phone_otp_signin"}
	}
	p := s.state.features.httpPreAuth
	owner, err := f.PhoneOTPSignin()
	if err != nil {
		return nil, err
	}
	rate, origin, timeout := s.state.httpRate.limiter, identityhttp.Origin(p.deployment.Origin), s.state.features.timeout
	feature, err := otphttp.NewPhoneSigninFeature(
		otphttp.PhoneSigninSendConfig{Network: network, Service: owner, Policy: s.state.features.phoneOTPSignin.policy, Rate: rate, Origin: origin, FlowCookie: p.deployment.Cookie, Device: *p.device, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Now: time.Now, MaximumDuration: timeout},
		otphttp.SigninConfig{Network: network, Service: owner, Source: owner, Rate: rate, Origin: origin, FlowCookie: p.deployment.Cookie, SessionCookie: h.common.sessionCookie, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Audience: h.common.audience, Now: time.Now, MaximumDuration: timeout},
		otphttp.SigninRecoveryConfig{Network: network, Service: owner, Rate: rate, Origin: origin, FlowCookie: p.deployment.Cookie, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, MaximumDuration: timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}
