package reference

import (
	"context"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	ssohttp "github.com/faustbrian/go-identity/http/sso"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func (s *Server) enterpriseOIDCFeatures(network identityhttp.NetworkConfig) ([]identityhttp.Feature, error) {
	f := s.state.features
	n := f.enterpriseOIDC
	oauth2 := f.enterpriseOAuth2
	if n == nil || n.preauth == nil {
		return s.enterpriseOAuth2OnlyFeatures(network)
	}
	if f.session == nil || f.httpPreAuth == nil || f.httpPreAuth.device == nil || s.state.httpRate == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_enterprise_oidc"}
	}
	protocol, err := n.completion.SigninProtocolProfile(n.profile.OrganizationID, n.profile.ProviderID)
	if err != nil {
		return nil, err
	}
	browser := ssohttp.SigninBrowserConfig{Network: network, TenantID: n.tenant, Origin: identityhttp.Origin(n.origin), FlowCookie: f.httpPreAuth.deployment.Cookie,
		Device: *f.httpPreAuth.device, Rate: s.state.httpRate.limiter, Now: time.Now, MaximumDuration: n.duration}
	owner := enterpriseOIDCHTTP{native: n}
	provider := string(n.profile.ProviderID)
	startConfig := ssohttp.SigninStartConfig{Browser: browser, ProviderID: provider, AuthorizationEndpoint: protocol.AuthorizationEndpoint,
		CallbackAllowlist: n.callbacks, Lifetime: f.httpPreAuth.lifetime, Start: owner}
	callbackConfig := ssohttp.SigninCallbackConfig{Browser: browser, Provider: protocol, CallbackAllowlist: n.callbacks, Audience: n.audience,
		Cookie: f.session.config.Cookie, CSRFCookie: n.csrfCookie, Callback: owner}
	var start, callback identityhttp.Feature
	if oauth2 != nil && oauth2.preauth != nil {
		var link *ssohttp.MemberLinkStartConfig
		if n.memberLink {
			link = &ssohttp.MemberLinkStartConfig{Cookie: callbackConfig.Cookie, Start: owner}
		}
		startConfig.Browser.MaximumDuration = min(startConfig.Browser.MaximumDuration, oauth2.duration)
		start, err = ssohttp.NewSigninStartFeatureWithOAuth2(startConfig, oauth2.httpStartConfig(), link)
	} else if n.memberLink {
		start, err = ssohttp.NewSigninStartFeatureWithLink(startConfig, ssohttp.MemberLinkStartConfig{Cookie: callbackConfig.Cookie, Start: owner})
	} else {
		start, err = ssohttp.NewSigninStartFeature(startConfig)
	}
	if err != nil {
		return nil, err
	}
	if n.memberLink {
		callback, err = ssohttp.NewSigninCallbackFeatureWithLink(provider, callbackConfig, owner)
	} else {
		callback, err = ssohttp.NewSigninCallbackFeatureForProvider(provider, callbackConfig)
	}
	if err != nil {
		return nil, err
	}
	features := []identityhttp.Feature{start, callback}
	if oauth2 != nil && oauth2.preauth != nil {
		plain, err := s.enterpriseOAuth2HTTPCallback(network)
		if err != nil {
			return nil, err
		}
		features = append(features, plain)
	}
	return s.guardEnterpriseFeatures(features)
}

func (s *Server) guardEnterpriseFeatures(features []identityhttp.Feature) ([]identityhttp.Feature, error) {
	for i, feature := range features {
		ops := feature.Operations()
		for j := range ops {
			ops[j].Handler = s.guardSessionLifetime(ops[j].Handler)
		}
		protected, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: feature.ID(), Operations: ops})
		if err != nil {
			return nil, err
		}
		features[i] = protected
	}
	return features, nil
}

type enterpriseOIDCHTTP struct{ native *enterpriseOIDCState }

func (a enterpriseOIDCHTTP) StartSSOOIDC(ctx context.Context, tenant identity.TenantID, request sso.SigninStartRequest, browser ssohttp.SigninBrowser) (sso.SigninStartResult, error) {
	if tenant != a.native.tenant {
		return sso.SigninStartResult{}, sso.ErrForbidden
	}
	return a.native.start.SigninStart(ctx, request, enterpriseBrowser(browser))
}

func (a enterpriseOIDCHTTP) StartSSOOIDCLink(ctx context.Context, tenant identity.TenantID, request sso.SigninStartRequest, browser ssohttp.SigninBrowser,
	cookie authentication.BearerCredential, csrf session.CSRFToken,
) (sso.SigninStartResult, error) {
	if !a.native.memberLink || tenant != a.native.tenant {
		return sso.SigninStartResult{}, sso.ErrForbidden
	}
	return a.native.start.LinkStart(ctx, request, ssopg.ProviderLinkBrowser{Session: cookie, CSRF: csrf, Origin: browser.Origin, Network: browser.Network, Device: browser.Device})
}

func (a enterpriseOIDCHTTP) CallbackRateSource(ctx context.Context, request ssohttp.SigninCallbackRequest) (ssohttp.SigninCallbackRateContext, error) {
	out, err := a.native.completion.SigninCallbackRateSource(ctx, request.TenantID, enterpriseCallback(request))
	if err != nil {
		return ssohttp.SigninCallbackRateContext{}, err
	}
	return enterpriseCallbackRate(out), nil
}

func (a enterpriseOIDCHTTP) SharedCallbackRateSource(ctx context.Context, request ssohttp.SigninCallbackRequest, cookie authentication.BearerCredential) (ssohttp.SharedCallbackRateContext, error) {
	if !a.native.memberLink {
		return ssohttp.SharedCallbackRateContext{}, sso.ErrForbidden
	}
	out, err := a.native.completion.SharedCallbackRateSource(ctx, request.TenantID, enterpriseCallback(request), cookie)
	if err != nil {
		return ssohttp.SharedCallbackRateContext{}, err
	}
	return ssohttp.SharedCallbackRateContext{SigninCallbackRateContext: enterpriseCallbackRate(out.ProviderLoginCallbackRateContext), MemberLink: out.MemberLink}, nil
}

func enterpriseCallbackRate(in ssopg.ProviderLoginCallbackRateContext) ssohttp.SigninCallbackRateContext {
	return ssohttp.SigninCallbackRateContext{ProviderID: string(in.ProviderID), FlowID: in.FlowID, TransactionID: in.TransactionID, Lifetime: in.Lifetime}
}

func (a enterpriseOIDCHTTP) CompleteSSOOIDC(ctx context.Context, request ssohttp.SigninCallbackRequest) (ssohttp.SigninCallbackResult, error) {
	if request.TenantID != a.native.tenant {
		return ssohttp.SigninCallbackResult{}, sso.ErrForbidden
	}
	out, err := a.native.completion.SigninCallback(ctx, enterpriseCallback(request))
	if err != nil {
		return ssohttp.SigninCallbackResult{}, err
	}
	return ssohttp.SigninCallbackResult{Completion: out.Completion, Issuance: out.Issuance, CSRF: out.CSRF, RedirectURI: out.RedirectURI}, nil
}

func (a enterpriseOIDCHTTP) CompleteSSOOIDCLink(ctx context.Context, request ssohttp.SigninCallbackRequest, cookie authentication.BearerCredential) (ssohttp.MemberLinkCallbackResult, error) {
	if !a.native.memberLink || request.TenantID != a.native.tenant {
		return ssohttp.MemberLinkCallbackResult{}, sso.ErrForbidden
	}
	browser := request.Browser
	out, err := a.native.completion.LinkCallback(ctx, ssopg.ProviderLinkCallbackRequest{Session: cookie, Input: request.Input,
		ReceivedRedirectURI: request.ReceivedRedirectURI, Origin: browser.Origin, Network: browser.Network, Device: browser.Device})
	if err != nil {
		return ssohttp.MemberLinkCallbackResult{}, err
	}
	return ssohttp.MemberLinkCallbackResult{CommandID: out.Completion.Binding.CommandID, RedirectURI: out.RedirectURI}, nil
}

func enterpriseBrowser(browser ssohttp.SigninBrowser) ssopg.ProviderLoginBrowser {
	return ssopg.ProviderLoginBrowser{FlowID: browser.FlowID, FlowCookie: browser.FlowCookie, Origin: browser.Origin, Network: browser.Network, Device: browser.Device}
}

func enterpriseCallback(request ssohttp.SigninCallbackRequest) ssopg.ProviderLoginCallbackRequest {
	return ssopg.ProviderLoginCallbackRequest{Input: request.Input, Browser: enterpriseBrowser(request.Browser), ReceivedRedirectURI: request.ReceivedRedirectURI}
}
