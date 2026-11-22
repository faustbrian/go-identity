package reference

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	ssohttp "github.com/faustbrian/go-identity/http/sso"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func (s *Server) enterpriseOAuth2OnlyFeatures(network identityhttp.NetworkConfig) ([]identityhttp.Feature, error) {
	f := s.state.features
	n := f.enterpriseOAuth2
	if n == nil || n.preauth == nil {
		return nil, nil
	}
	browser, err := s.enterpriseOAuth2HTTPBrowser(network)
	if err != nil {
		return nil, err
	}
	start, err := ssohttp.NewOAuth2SigninStartFeature(browser, f.httpPreAuth.lifetime, n.httpStartConfig())
	if err != nil {
		return nil, err
	}
	callback, err := s.enterpriseOAuth2HTTPCallback(network)
	if err != nil {
		return nil, err
	}
	return s.guardEnterpriseFeatures([]identityhttp.Feature{start, callback})
}

func (s *Server) enterpriseOAuth2HTTPBrowser(network identityhttp.NetworkConfig) (ssohttp.SigninBrowserConfig, error) {
	f := s.state.features
	n := f.enterpriseOAuth2
	if n == nil || n.preauth == nil || f.session == nil || f.httpPreAuth == nil || f.httpPreAuth.device == nil || s.state.httpRate == nil {
		return ssohttp.SigninBrowserConfig{}, identity.InvalidInputError{Field: "reference_http_enterprise_oauth2"}
	}
	return ssohttp.SigninBrowserConfig{Network: network, TenantID: n.tenant, Origin: identityhttp.Origin(n.origin), FlowCookie: f.httpPreAuth.deployment.Cookie,
		Device: *f.httpPreAuth.device, Rate: s.state.httpRate.limiter, Now: time.Now, MaximumDuration: n.duration}, nil
}

func (n *enterpriseOAuth2State) httpStartConfig() ssohttp.OAuth2SigninStartConfig {
	return ssohttp.OAuth2SigninStartConfig{ProviderID: string(n.profile.ProviderID), AuthorizationEndpoint: n.authorization,
		CallbackAllowlist: n.callbacks, Start: enterpriseOAuth2HTTP{native: n}}
}

func (s *Server) enterpriseOAuth2HTTPCallback(network identityhttp.NetworkConfig) (identityhttp.Feature, error) {
	browser, err := s.enterpriseOAuth2HTTPBrowser(network)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	n := s.state.features.enterpriseOAuth2
	return ssohttp.NewOAuth2SigninCallbackFeature(ssohttp.OAuth2SigninCallbackConfig{
		Browser: browser, ProviderID: string(n.profile.ProviderID), CallbackAllowlist: n.callbacks, Audience: n.audience,
		Cookie: s.state.features.session.config.Cookie, CSRFCookie: n.csrfCookie, Callback: enterpriseOAuth2HTTP{native: n},
	})
}

type enterpriseOAuth2HTTP struct{ native *enterpriseOAuth2State }

func (a enterpriseOAuth2HTTP) StartSSOOAuth2(ctx context.Context, tenant identity.TenantID, request sso.SigninStartRequest, browser ssohttp.SigninBrowser) (sso.SigninStartResult, error) {
	if tenant != a.native.tenant {
		return sso.SigninStartResult{}, sso.ErrForbidden
	}
	return a.native.start.SigninStartOAuth2(ctx, request, enterpriseBrowser(browser))
}

func (a enterpriseOAuth2HTTP) OAuth2CallbackRateSource(ctx context.Context, request ssohttp.OAuth2SigninCallbackRequest) (ssohttp.SigninCallbackRateContext, error) {
	out, err := a.native.completion.SigninCallbackRateSource(ctx, request.TenantID, enterpriseOAuth2Callback(request))
	if err != nil {
		return ssohttp.SigninCallbackRateContext{}, err
	}
	return enterpriseCallbackRate(out), nil
}

func (a enterpriseOAuth2HTTP) CompleteSSOOAuth2(ctx context.Context, request ssohttp.OAuth2SigninCallbackRequest) (ssohttp.SigninCallbackResult, error) {
	if request.TenantID != a.native.tenant {
		return ssohttp.SigninCallbackResult{}, sso.ErrForbidden
	}
	out, err := a.native.completion.SigninCallbackOAuth2(ctx, enterpriseOAuth2Callback(request))
	if err != nil {
		return ssohttp.SigninCallbackResult{}, err
	}
	return ssohttp.SigninCallbackResult{Completion: out.Completion, Issuance: out.Issuance, CSRF: out.CSRF, RedirectURI: out.RedirectURI}, nil
}

func enterpriseOAuth2Callback(request ssohttp.OAuth2SigninCallbackRequest) ssopg.ProviderOAuth2LoginCallbackRequest {
	return ssopg.ProviderOAuth2LoginCallbackRequest{RawQuery: request.RawQuery, Browser: enterpriseBrowser(request.Browser), ReceivedRedirectURI: request.ReceivedRedirectURI}
}
