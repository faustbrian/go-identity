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

func (s *Server) enterpriseSAMLFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, []identityhttp.CORSRoutePolicy, error) {
	f := s.state.features
	n := f.enterpriseSAML
	if n == nil || n.http == nil {
		return nil, nil, nil
	}
	if n.preauth == nil || f.session == nil || s.state.httpRate == nil {
		return nil, nil, identity.InvalidInputError{Field: "reference_http_enterprise_saml"}
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
			return nil, nil, identity.InvalidInputError{Field: "reference_http_enterprise_saml_metadata"}
		}
		feature, err = ssohttp.NewSAMLSigninFeatureWithMetadata(c, f.httpSession.rate, owner)
	} else {
		feature, err = ssohttp.NewSAMLSigninFeature(c)
	}
	if err != nil {
		return nil, nil, err
	}
	navigation := []identityhttp.CORSRoutePolicy{c.ACSNavigationPolicy()}
	operations := feature.Operations()
	if n.idp != nil {
		config := ssohttp.SAMLIDPSigninConfig{Network: network, TenantID: n.tenant, Origin: c.Origin, IdentityProviderOrigin: h.IdentityProviderOrigin,
			ProviderID: c.ProviderID, SuccessCallback: h.SuccessCallback, Audience: n.audience, Cookie: c.Cookie, CSRFCookie: h.CSRFCookie,
			Rate: c.Rate, Now: c.Now, MaximumDuration: n.duration, Owner: owner}
		op, err := ssohttp.NewSAMLIDPInitiatedOperation(config)
		if err != nil {
			return nil, nil, err
		}
		operations = append(operations, op)
		navigation = append(navigation, config.NavigationPolicy())
	}
	if h.Logout {
		if n.logout == nil {
			return nil, nil, identity.InvalidInputError{Field: "reference_http_enterprise_saml_logout"}
		}
		config := ssohttp.SAMLLogoutConfig{
			Network: network, TenantID: n.tenant, Origin: c.Origin, IdentityProviderOrigin: h.IdentityProviderOrigin,
			ProviderID: c.ProviderID, ResponseEndpoint: n.logout.responseEndpoint, Rate: c.Rate,
			MaximumDuration: n.duration,
		}
		if n.logoutStart != nil && n.logoutStart.remote != nil {
			config.Owner, config.FinalRedirectAllowlist = owner, n.logoutStart.final
		} else {
			config.RequestOnlyOwner = owner
		}
		op, err := ssohttp.NewSAMLLogoutOperation(config)
		if err != nil {
			return nil, nil, err
		}
		operations = append(operations, op)
		navigation = append(navigation, config.NavigationPolicy())
	}
	if h.LogoutStart {
		if n.logoutStart == nil {
			return nil, nil, identity.InvalidInputError{Field: "reference_http_enterprise_saml_logout_start"}
		}
		op, err := ssohttp.NewSAMLLogoutStartOperation(ssohttp.SAMLLogoutStartConfig{
			Network: network, TenantID: n.tenant, Origin: c.Origin, ProviderID: c.ProviderID,
			RedirectEndpoint: n.logoutStart.endpoint, FinalRedirectAllowlist: n.logoutStart.final,
			Rate: c.Rate, MaximumDuration: n.duration, Cookie: c.Cookie, CSRFCookie: h.CSRFCookie, Owner: owner,
		})
		if err != nil {
			return nil, nil, err
		}
		operations = append(operations, op)
	}
	if h.IDPInitiated || h.Logout || h.LogoutStart {
		feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: feature.ID(), Operations: operations})
		if err != nil {
			return nil, nil, err
		}
	}
	guarded, err := s.guardEnterpriseFeatures([]identityhttp.Feature{feature})
	if err != nil {
		return nil, nil, err
	}
	return &guarded[0], navigation, nil
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
	config := saml.SPMetadataConfig{EntityID: installed.EntityID, AssertionConsumerURL: installed.AssertionConsumerURL,
		SigningCertificates: [][]byte{installed.SigningCertificate}}
	document, err := saml.ExportSPMetadataWithEndpoints(config, saml.SPMetadataEndpoints{
		IDPInitiatedACS: a.native.idp != nil, SingleLogout: a.native.http != nil && a.native.http.Logout && a.native.logout != nil,
	})
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
