package reference

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	ssohttp "github.com/faustbrian/go-identity/http/sso"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/faustbrian/go-sso/saml"
)

func (s *Server) enterpriseSAMLFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, identityhttp.CORSRoutePolicy, error) {
	f := s.state.features
	n := f.enterpriseSAML
	if n == nil || n.http == nil {
		return nil, identityhttp.CORSRoutePolicy{}, nil
	}
	if n.preauth == nil || f.session == nil || s.state.httpRate == nil {
		return nil, identityhttp.CORSRoutePolicy{}, identity.InvalidInputError{Field: "reference_http_enterprise_saml"}
	}
	h := n.http
	owner := enterpriseSAMLHTTP{native: n}
	c := ssohttp.SAMLSigninConfig{Network: network, TenantID: n.tenant, Origin: identityhttp.Origin(n.origin), IdentityProviderOrigin: h.IdentityProviderOrigin,
		ProviderID: string(n.profile.ProviderID), AuthorizationEndpoint: h.AuthorizationEndpoint, SuccessCallback: h.SuccessCallback, ErrorCallback: h.ErrorCallback,
		CallbackAllowlist: n.callbacks, Audience: n.audience, Cookie: f.session.config.Cookie, CSRFCookie: h.CSRFCookie,
		Frontchannel: n.preauth, FlowSignalKey: h.FlowSignalKey, Lifetime: h.Lifetime,
		Rate: s.state.httpRate.limiter, Now: time.Now, MaximumDuration: n.duration, Start: owner, Callback: owner}
	var feature identityhttp.Feature
	var err error
	if h.Metadata {
		if n.metadata == nil || f.httpSession == nil || !f.httpSession.rate.Configured() {
			return nil, identityhttp.CORSRoutePolicy{}, identity.InvalidInputError{Field: "reference_http_enterprise_saml_metadata"}
		}
		feature, err = ssohttp.NewSAMLSigninFeatureWithMetadata(c, f.httpSession.rate, owner)
	} else {
		feature, err = ssohttp.NewSAMLSigninFeature(c)
	}
	if err != nil {
		return nil, identityhttp.CORSRoutePolicy{}, err
	}
	guarded, err := s.guardEnterpriseFeatures([]identityhttp.Feature{feature})
	if err != nil {
		return nil, identityhttp.CORSRoutePolicy{}, err
	}
	return &guarded[0], c.ACSNavigationPolicy(), nil
}

type enterpriseSAMLHTTP struct{ native *enterpriseSAMLState }

func (a enterpriseSAMLHTTP) ReadSAMLMetadata(ctx context.Context, tenant identity.TenantID, provider string) (ssohttp.SAMLMetadataDocument, error) {
	if a.native == nil || a.native.metadata == nil || tenant != a.native.tenant || provider != string(a.native.profile.ProviderID) {
		return ssohttp.SAMLMetadataDocument{}, sso.ErrForbidden
	}
	installed, err := a.native.metadata.Read(ctx, tenant, sso.ProviderID(provider))
	if err != nil {
		return ssohttp.SAMLMetadataDocument{}, err
	}
	document, err := saml.ExportSPMetadata(saml.SPMetadataConfig{EntityID: installed.EntityID,
		AssertionConsumerURL: installed.AssertionConsumerURL, SigningCertificates: [][]byte{installed.SigningCertificate}})
	if err != nil || ctx.Err() != nil {
		return ssohttp.SAMLMetadataDocument{}, sso.ErrUnavailable
	}
	return ssohttp.SAMLMetadataDocument{XML: document, ValidUntil: installed.ValidUntil}, nil
}

func (a enterpriseSAMLHTTP) StartSSOSAML(ctx context.Context, request ssohttp.SAMLSigninStartRequest) (sso.SigninStartResult, error) {
	provider := sso.ProviderID(request.ProviderID)
	if request.TenantID != a.native.tenant || provider != a.native.profile.ProviderID {
		return sso.SigninStartResult{}, sso.ErrForbidden
	}
	return a.native.start.SigninStartSAML(ctx, ssopg.SAMLSigninStartRequest{ProviderID: provider, SuccessCallback: request.SuccessCallback,
		ErrorCallback: request.ErrorCallback, LoginIntent: request.LoginIntent, IdempotencyKey: request.IdempotencyKey}, enterpriseBrowser(request.Browser))
}

func (a enterpriseSAMLHTTP) SAMLCallbackRateSource(ctx context.Context, request ssohttp.SAMLSigninCallbackRequest) (ssohttp.SigninCallbackRateContext, error) {
	if request.TenantID != a.native.tenant || request.ProviderID != string(a.native.profile.ProviderID) {
		return ssohttp.SigninCallbackRateContext{}, sso.ErrForbidden
	}
	out, err := a.native.completion.SigninCallbackRateSource(ctx, request.TenantID, enterpriseSAMLCallback(request))
	if err != nil {
		return ssohttp.SigninCallbackRateContext{}, err
	}
	return enterpriseCallbackRate(out), nil
}

func (a enterpriseSAMLHTTP) CompleteSSOSAML(ctx context.Context, request ssohttp.SAMLSigninCallbackRequest) (ssohttp.SigninCallbackResult, error) {
	if request.TenantID != a.native.tenant || request.ProviderID != string(a.native.profile.ProviderID) {
		return ssohttp.SigninCallbackResult{}, sso.ErrForbidden
	}
	out, err := a.native.completion.SigninCallback(ctx, enterpriseSAMLCallback(request))
	if err != nil {
		return ssohttp.SigninCallbackResult{}, err
	}
	return ssohttp.SigninCallbackResult{Completion: out.Completion, Issuance: out.Issuance, CSRF: out.CSRF, RedirectURI: out.RedirectURI}, nil
}

func enterpriseSAMLCallback(request ssohttp.SAMLSigninCallbackRequest) ssopg.SAMLSigninCallbackRequest {
	return ssopg.SAMLSigninCallbackRequest{ProviderID: sso.ProviderID(request.ProviderID), ReceivedAssertionConsumerURL: request.ReceivedAssertionConsumerURL,
		RelayState: request.RelayState, SAMLResponse: request.SAMLResponse, Browser: enterpriseBrowser(request.Browser)}
}
