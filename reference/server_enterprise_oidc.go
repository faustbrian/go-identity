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

func (s *Server) enterpriseOIDCFeatures(network identityhttp.NetworkConfig) ([]identityhttp.Feature, error) {
	f := s.state.features
	n := f.enterpriseOIDC
	if n == nil || n.preauth == nil {
		return nil, nil
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
	start, err := ssohttp.NewSigninStartFeature(ssohttp.SigninStartConfig{Browser: browser, ProviderID: provider, AuthorizationEndpoint: protocol.AuthorizationEndpoint,
		CallbackAllowlist: n.callbacks, Lifetime: f.httpPreAuth.lifetime, Start: owner})
	if err != nil {
		return nil, err
	}
	callback, err := ssohttp.NewSigninCallbackFeatureForProvider(provider, ssohttp.SigninCallbackConfig{Browser: browser, Provider: protocol,
		CallbackAllowlist: n.callbacks, Audience: n.audience, Cookie: f.session.config.Cookie, CSRFCookie: n.csrfCookie, Callback: owner})
	if err != nil {
		return nil, err
	}
	features := []identityhttp.Feature{start, callback}
	for i, feature := range features {
		ops := feature.Operations()
		for j := range ops {
			ops[j].Handler = s.guardSessionLifetime(ops[j].Handler)
		}
		features[i], err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: feature.ID(), Operations: ops})
		if err != nil {
			return nil, err
		}
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

func (a enterpriseOIDCHTTP) CallbackRateSource(ctx context.Context, request ssohttp.SigninCallbackRequest) (ssohttp.SigninCallbackRateContext, error) {
	out, err := a.native.completion.SigninCallbackRateSource(ctx, request.TenantID, enterpriseCallback(request))
	if err != nil {
		return ssohttp.SigninCallbackRateContext{}, err
	}
	return ssohttp.SigninCallbackRateContext{ProviderID: string(out.ProviderID), FlowID: out.FlowID, TransactionID: out.TransactionID, Lifetime: out.Lifetime}, nil
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

func enterpriseBrowser(browser ssohttp.SigninBrowser) ssopg.ProviderLoginBrowser {
	return ssopg.ProviderLoginBrowser{FlowID: browser.FlowID, FlowCookie: browser.FlowCookie, Origin: browser.Origin, Network: browser.Network, Device: browser.Device}
}

func enterpriseCallback(request ssohttp.SigninCallbackRequest) ssopg.ProviderLoginCallbackRequest {
	return ssopg.ProviderLoginCallbackRequest{Input: request.Input, Browser: enterpriseBrowser(request.Browser), ReceivedRedirectURI: request.ReceivedRedirectURI}
}
