package reference

import (
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
)

func composePhoneSigninHTTP(c StoreConfiguration, native *phoneSigninState, original *preAuthHTTPState) (*passwordSigninHTTPState, error) {
	if c.HTTPPhoneSignin == nil {
		return nil, nil
	}
	if c.PhoneSignin == nil || native == nil || native.owner == nil || native.preauth == nil || c.PasswordSignin == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_phone_signin"}
	}
	selected, profile := c, *c.PasswordSignin
	profile.MFA, profile.TOTP, profile.Recovery, profile.OTP = nil, nil, nil, nil
	selected.PasswordSignin = &profile
	selected.HTTPPasswordSignin = c.HTTPPhoneSignin
	return composePasswordSigninHTTP(selected, original)
}

func (s *Server) phoneSigninFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpPhoneSignin
	if h == nil {
		return nil, nil
	}
	p := s.state.features.httpPreAuth
	if p == nil || p.device == nil || s.state.httpRate == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_phone_signin"}
	}
	owner, err := f.PhoneSignin()
	if err != nil {
		return nil, err
	}
	// Only FeatureSet constructs this guarded handle; its native instance owns
	// the phone profile, despite sharing the transport-neutral forwarding type.
	feature, err := passwordhttp.NewPhoneSigninFeature(passwordhttp.SigninConfig{Network: network, Service: owner.(composedIdentifierSignin), Rate: s.state.httpRate.limiter, Origin: identityhttp.Origin(h.preauth.Origin), CallbackURL: h.preauth.CallbackURL, Lifetime: p.lifetime, FlowCookie: h.preauth.Cookie, SessionCookie: h.sessionCookie, Device: *p.device, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Audience: h.audience, Now: time.Now, MaximumDuration: s.state.features.timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}
