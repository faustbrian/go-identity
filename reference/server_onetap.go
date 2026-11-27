package reference

import (
	"context"
	"net/http"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	"github.com/faustbrian/go-identity/session"
)

func (s *Server) oneTapFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, []identityhttp.CORSRoutePolicy, error) {
	f := s.state.features
	if f == nil {
		return nil, nil, nil
	}
	n := f.oneTap
	if n == nil || !n.http.EnableStart && !n.http.EnableCallback {
		return nil, nil, nil
	}
	if f.httpPreAuth == nil || f.httpPreAuth.device == nil || s.state.httpRate == nil {
		return nil, nil, identity.InvalidInputError{Field: oneTapReferenceField}
	}
	origin := identityhttp.Origin(n.issuance.Origin)
	var operations []identityhttp.OperationDescriptor
	var navigation []identityhttp.CORSRoutePolicy
	if n.redirect {
		var err error
		operations, navigation, err = s.oneTapRedirectOperations(network, n)
		if err != nil {
			return nil, nil, err
		}
	} else if n.http.EnableStart {
		start := func(ctx context.Context, req onetap.BrowserStartRequest) (oauthhttp.OneTapStartHTTPResult, error) {
			result, err := n.start.Start(ctx, req)
			projection := oauthhttp.OneTapStartHTTPResult{CommandID: result.CommandID, Outcome: result.Outcome, Replayed: result.Replayed}
			if browser, ok := result.Browser(); ok && err == nil {
				projection.FlowID, projection.ClientID, projection.Nonce, projection.Origin = browser.FlowID, browser.ClientID, browser.Nonce, browser.Origin
				projection.ExpiresAt, projection.Options, projection.Cookie, projection.Token = browser.ExpiresAt, browser.Options, browser.Cookie, browser.Token
			}
			return projection, err
		}
		feature, err := oauthhttp.NewOneTapStartFeature(oauthhttp.OneTapStartConfig{Network: network,
			ProviderID: n.profile.ID, ClientID: n.profile.ClientID, Start: start, Rate: s.state.httpRate.limiter,
			FlowCookie: n.issuance.Cookie, Device: *f.httpPreAuth.device, Origin: origin, Lifetime: f.httpPreAuth.lifetime,
			Now: n.issuance.Clock.Now, MaximumDuration: n.duration})
		if err != nil {
			return nil, nil, err
		}
		operations = append(operations, feature.Operations()...)
	}
	if !n.redirect && n.http.EnableCallback {
		if n.complete == nil {
			return nil, nil, identity.InvalidInputError{Field: oneTapReferenceField}
		}
		complete := func(ctx context.Context, req oauthhttp.OneTapCallbackHTTPInput) (oauthhttp.OneTapCallbackHTTPResult, error) {
			result, err := n.complete.Callback(ctx, oauthpg.OneTapCallbackRequest{FlowID: req.FlowID, FlowCookie: req.FlowCookie,
				Callback: req.Callback, Network: req.Network, Device: req.Device})
			return oauthhttp.OneTapCallbackHTTPResult{Session: result.Session, CSRF: result.CSRF}, err
		}
		feature, err := oauthhttp.NewOneTapCallbackFeature(oauthhttp.OneTapCallbackConfig{Network: network, Provider: n.profile,
			Complete: complete, Rate: s.state.httpRate.limiter, Cookie: n.finalCookie, FlowCookie: n.issuance.Cookie,
			Device: *f.httpPreAuth.device, CSRFCookie: n.csrfCookie, Origin: origin, TenantID: n.tenant, Audience: n.audience,
			Now: n.issuance.Clock.Now, MaximumDuration: n.duration})
		if err != nil {
			return nil, nil, err
		}
		operations = append(operations, feature.Operations()...)
	}
	for i := range operations {
		operations[i].Handler = s.guardSessionLifetime(operations[i].Handler)
	}
	feature, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/oauth/onetap", Operations: operations})
	if err != nil {
		return nil, nil, err
	}
	return &feature, navigation, nil
}

func (s *Server) oneTapRedirectOperations(network identityhttp.NetworkConfig, n *oneTapState) ([]identityhttp.OperationDescriptor, []identityhttp.CORSRoutePolicy, error) {
	preauth := s.state.features.httpPreAuth
	origin, endpoint := identityhttp.Origin(n.issuance.Origin), n.issuance.CallbackURL
	var operations []identityhttp.OperationDescriptor
	if n.http.EnableStart {
		start := func(ctx context.Context, req onetap.BrowserRedirectStartRequest) (oauthhttp.OneTapRedirectStartHTTPResult, error) {
			result, err := n.start.StartRedirect(ctx, req)
			projection := oauthhttp.OneTapRedirectStartHTTPResult{CommandID: result.CommandID, Outcome: result.Outcome, Replayed: result.Replayed}
			if browser, ok := result.RedirectBrowser(); ok && err == nil {
				projection.Projection, projection.Cookie, projection.Token = browser.Projection, browser.Cookie, browser.Token
			}
			return projection, err
		}
		feature, err := oauthhttp.NewOneTapRedirectStartFeature(oauthhttp.OneTapRedirectStartConfig{Network: network, ProviderID: n.profile.ID, ClientID: n.profile.ClientID,
			CallbackURL: endpoint, Start: start, Rate: s.state.httpRate.limiter, Device: *preauth.device, Origin: origin, Lifetime: preauth.lifetime,
			Now: n.issuance.Clock.Now, MaximumDuration: n.duration})
		if err != nil {
			return nil, nil, err
		}
		operations = append(operations, feature.Operations()...)
	}
	if !n.http.EnableCallback {
		return operations, nil, nil
	}
	if n.complete == nil {
		return nil, nil, identity.InvalidInputError{Field: oneTapReferenceField}
	}
	frontchannel, err := session.NewOneTapRedirectFrontchannelCookiePolicy(string(origin), endpoint)
	if err != nil {
		return nil, nil, err
	}
	complete := func(ctx context.Context, req oauthhttp.OneTapRedirectCallbackHTTPInput) (oauthhttp.OneTapCallbackHTTPResult, error) {
		result, err := n.complete.RedirectCallback(ctx, oauthpg.OneTapRedirectCallbackRequest{FlowID: req.FlowID, FlowCookie: req.FlowCookie,
			Callback: req.Callback, Network: req.Network})
		return oauthhttp.OneTapCallbackHTTPResult{Session: result.Session, CSRF: result.CSRF}, err
	}
	feature, err := oauthhttp.NewOneTapRedirectCallbackFeature(oauthhttp.OneTapRedirectCallbackConfig{Network: network, Provider: n.profile,
		Complete: complete, Rate: s.state.httpRate.limiter, Cookie: n.finalCookie, FrontchannelCookie: frontchannel, CSRFCookie: n.csrfCookie,
		Origin: origin, TenantID: n.tenant, Audience: n.audience, CallbackURL: endpoint, Now: n.issuance.Clock.Now, MaximumDuration: n.duration})
	if err != nil {
		return nil, nil, err
	}
	operations = append(operations, feature.Operations()...)
	return operations, []identityhttp.CORSRoutePolicy{{Method: http.MethodPost, Path: oneTapCallbackPath,
		Credentials: identityhttp.CORSOneTapRedirectNavigation, Origins: []identityhttp.Origin{origin}}}, nil
}
