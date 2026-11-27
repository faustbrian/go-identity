package reference

import (
	"context"
	"fmt"
	"io"
	"net/http"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// OAuthProxyProductionConfiguration selects one native production deployment,
// an authenticated preview registration, and a provider. Start supplies the
// only allowed preview target and provider for both initiation and callback.
// Native is a production-only coordinator configuration, never a copy of the
// ordinary session graph's policy or authentication owners. HTTP is optional.
// Callers own the provider, codec, clock and pool for the full service lifetime
// and must not mutate selected inputs during construction.
type OAuthProxyProductionConfiguration struct {
	Native             oauthpg.ProxyForwardConfig
	Start              oauthpg.ProxyStartConfig
	Codec              *oauth.ProxyOIDCEvidenceCodec
	Clock              oauth.Clock
	RevocationEndpoint string
	HTTP               *HTTPOAuthProxyProductionConfiguration
}

// HTTPOAuthProxyProductionConfiguration opts into the canonical provider GET.
// Borrow the shared provider rate owner and a counted, audited evaluator made
// with Policy.WithOAuthProxyForward. Startup never consumes either allowance.
type HTTPOAuthProxyProductionConfiguration struct {
	Network identityhttp.NetworkConfig
	Origin  identityhttp.Origin
	Rate    *identityhttp.AuthRateLimiter
	Risk    risk.Evaluator
}

// OAuthProxyProduction owns only the production side of the two-origin OAuth
// workflow. It has no identity mutation, account linking, or session service.
// It does not close borrowed resources and can serve concurrent requests.
type OAuthProxyProduction struct {
	start                *oauthpg.ProxyStartService
	handler              http.Handler
	document             identityhttp.OpenAPIDocument
	pool                 *database.Pool
	provider             oauth.ProviderProfile
	productionDeployment string
	previewTarget        oauthproxy.PreviewTarget
	tenant               identity.TenantID
}

// NewOAuthProxyProduction assembles native Start and the acknowledged command
// callback against the dedicated production pool. It performs no database or
// provider IO. Use NewOAuthProxyProductionMigrations to install the selected
// native histories before invoking Start or mounting the handler.
func NewOAuthProxyProduction(pool *database.Pool, c OAuthProxyProductionConfiguration) (*OAuthProxyProduction, error) {
	invalid := identity.InvalidInputError{Field: "reference_oauth_proxy_production"}
	if c.Codec == nil || nilServerDependency(c.Clock) {
		return nil, invalid
	}
	forward, err := oauthpg.NewProxyForwardService(pool, c.Native)
	if err != nil {
		return nil, invalid
	}
	start, err := oauthpg.NewProxyStartService(forward, c.Start)
	if err != nil {
		return nil, invalid
	}
	exchange, err := oauth.NewOIDCProxyExchange(c.Start.Provider, c.RevocationEndpoint)
	if err != nil {
		return nil, invalid
	}
	target := c.Start.Preview.Target
	callback, err := oauthproxy.NewProductionCommandCallback(oauthproxy.ProductionCallbackConfig{
		ProductionDeployment: c.Native.ProductionDeployment, Provider: exchange,
		Codec: c.Codec, Clock: c.Clock, Targets: []oauthproxy.PreviewTarget{target},
	}, forward)
	if err != nil {
		return nil, invalid
	}
	result := &OAuthProxyProduction{start: start, pool: pool, provider: exchange.Profile(),
		productionDeployment: c.Native.ProductionDeployment, previewTarget: target, tenant: c.Start.Preview.TenantID}
	if c.HTTP == nil {
		return result, nil
	}
	h := c.HTTP
	if h.Risk == (risk.Evaluator{}) {
		return nil, invalid
	}
	feature, err := oauthhttp.NewProxyForwardFeature(oauthhttp.ProxyForwardConfig{
		Network: h.Network, Origin: h.Origin, TenantID: c.Start.Preview.TenantID,
		Provider: result.provider, ProductionDeployment: c.Native.ProductionDeployment,
		Callback: callback, RateSource: forward, Rate: h.Rate, Risk: h.Risk,
		AllowedTargets: []string{target.Redirect}, Now: c.Clock.Now, MaximumDuration: c.Native.MaximumDuration,
	})
	if err != nil {
		return nil, invalid
	}
	result.handler, result.document, err = identityhttp.NewDocumentedHandler(context.Background(),
		identityhttp.DocumentConfig{Title: "OAuth preview forwarding", Version: "1"},
		identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		return nil, redactedRouterFailure(err)
	}
	return result, nil
}

// Start admits a trusted preview request and commits its original production
// state. The preview must acknowledge its own browser binding before exposing
// the returned provider authorization. No historical result returns the URL.
func (p *OAuthProxyProduction) Start(ctx context.Context, request oauthproxy.InitiationRequest) (oauthpg.ProxyStartResult, error) {
	if p == nil || p.start == nil {
		return oauthpg.ProxyStartResult{}, oauthproxy.InitiationInvalid
	}
	return p.start.Start(ctx, request)
}

// Handler exposes only the explicitly configured provider GET, or a 404
// handler when HTTP is not selected. It never mounts a preview or session route.
func (p *OAuthProxyProduction) Handler() http.Handler {
	if p == nil || p.handler == nil {
		return http.NotFoundHandler()
	}
	return p.handler
}

// OpenAPI returns the immutable selected production document. A deployment
// without HTTP selection advertises no operations.
func (p *OAuthProxyProduction) OpenAPI() identityhttp.OpenAPIDocument {
	if p == nil {
		return identityhttp.OpenAPIDocument{}
	}
	return p.document
}

// Format prevents deployment configuration and borrowed owners being logged.
func (OAuthProxyProductionConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.OAuthProxyProductionConfiguration(redacted)")
}

// MarshalJSON rejects exporting deployment configuration and key custody.
func (OAuthProxyProductionConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText rejects exporting deployment configuration and key custody.
func (OAuthProxyProductionConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// Format prevents logging internal routing handlers or native owners.
func (*OAuthProxyProduction) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.OAuthProxyProduction(redacted)")
}
