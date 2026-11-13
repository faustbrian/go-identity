package reference

import (
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
)

func (s *Server) socialOAuthFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	f := s.state.features
	if f == nil || f.socialOAuth == nil || f.socialOAuth.http == nil {
		return nil, nil
	}
	n := f.socialOAuth
	if f.session == nil || s.state.httpRate == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_social_oauth"}
	}
	config := oauthhttp.Config{Network: network, Provider: n.profile, Start: n.owner, Callback: n.owner, Sessions: f.session.reader, Rate: s.state.httpRate.limiter, Cookie: f.session.config.Cookie, Origin: identityhttp.Origin(n.origin), CallbackAllowlist: n.callbacks, PolicyRevision: n.version, Now: time.Now, MaximumDuration: n.duration}
	if n.signin != nil && n.http.Callback {
		if f.httpPreAuth == nil || f.httpPreAuth.device == nil {
			return nil, identity.InvalidInputError{Field: "reference_http_social_signin"}
		}
		config.Signin = &oauthhttp.SigninCallbackConfig{Operations: n.owner, Source: n.signin.start, Complete: n.signin.complete, FlowCookie: n.signin.flowCookie, Device: *f.httpPreAuth.device, CSRFCookie: n.signin.csrfCookie, Audience: n.signin.audience}
	}
	var selection oauthhttp.FeatureConfig
	if n.http.LinkStart {
		selection.LinkStart = &config
	}
	if n.http.Callback {
		selection.Callback = &config
	}
	if n.http.SigninStart {
		if n.signin == nil || f.httpPreAuth == nil || f.httpPreAuth.device == nil {
			return nil, identity.InvalidInputError{Field: "reference_http_social_signin"}
		}
		selection.SigninStart = &oauthhttp.SigninStartConfig{Network: network, Provider: n.profile, Start: n.signin.start, Rate: s.state.httpRate.limiter, FlowCookie: n.signin.flowCookie, Device: *f.httpPreAuth.device, Origin: identityhttp.Origin(n.origin), CallbackAllowlist: n.callbacks, Lifetime: f.httpPreAuth.lifetime, ActorID: n.signin.actor, PolicyRevision: n.version, Now: time.Now, MaximumDuration: n.duration}
	}
	feature, err := oauthhttp.NewFeature(selection)
	if err != nil {
		return nil, err
	}
	ops := feature.Operations()
	for i := range ops {
		ops[i].Handler = s.guardSessionLifetime(ops[i].Handler)
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/oauth", Operations: ops})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}
