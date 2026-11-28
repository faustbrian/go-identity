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
	forward              *oauthpg.ProxyForwardService
	handler              http.Handler
	document             identityhttp.OpenAPIDocument
	pool                 *database.Pool
	provider             oauth.ProviderProfile
	productionDeployment string
	previewTarget        oauthproxy.PreviewTarget
	tenant               identity.TenantID
	providerAuthority    *oauthpg.ProviderAuthority
	retirement           *oauthpg.ProxyRetirementAuthority
	maintenanceSchema    string
}

// NewOAuthProxyProduction assembles native Start and the acknowledged command
// callback against the dedicated production pool. It performs no database or
// provider IO. Use NewOAuthProxyProductionMigrations to install the selected
// native histories before invoking Start or mounting the handler.
func NewOAuthProxyProduction(pool *database.Pool, c OAuthProxyProductionConfiguration) (*OAuthProxyProduction, error) {
	return newOAuthProxyProduction(pool, c, nil, nil, false)
}

// NewOAuthProxyProductionWithProviderAuthority selects the live provider
// profile for Start and forwarding. Borrow the shared primary reader via a
// separate pool from production transaction work. The caller owns both pools.
func NewOAuthProxyProductionWithProviderAuthority(pool *database.Pool, c OAuthProxyProductionConfiguration, a *oauthpg.ProviderAuthority) (*OAuthProxyProduction, error) {
	if a == nil {
		return nil, identity.InvalidInputError{Field: "reference_oauth_proxy_production"}
	}
	return newOAuthProxyProduction(pool, c, a, nil, false)
}

// NewOAuthProxyProductionWithRetirement selects live provider checks and
// direct-Go retirement for this production deployment. Install the selected
// retirement migration history first. Borrow the trusted audit reader for the
// lifetime of the owner; this does not grant audit access to the callback pool
// or install an HTTP route.
func NewOAuthProxyProductionWithRetirement(pool *database.Pool, c OAuthProxyProductionConfiguration, a *oauthpg.ProviderAuthority, retirement *oauthpg.ProxyRetirementAuthority) (*OAuthProxyProduction, error) {
	if a == nil || retirement == nil {
		return nil, identity.InvalidInputError{Field: "reference_oauth_proxy_production_retirement"}
	}
	return newOAuthProxyProduction(pool, c, a, retirement, false)
}

// NewOAuthProxyProductionWithMaintenance selects the live fenced Start
// writer. Use the matching maintenance expansion before serving this writer,
// and activate fences only once all writers have switched. Callback routing
// and opt-in HTTP behavior are unchanged.
func NewOAuthProxyProductionWithMaintenance(pool *database.Pool, c OAuthProxyProductionConfiguration, a *oauthpg.ProviderAuthority) (*OAuthProxyProduction, error) {
	if a == nil {
		return nil, invalidOAuthProxyMaintenance()
	}
	return newOAuthProxyProduction(pool, c, a, nil, true)
}

func newOAuthProxyProduction(pool *database.Pool, c OAuthProxyProductionConfiguration, a *oauthpg.ProviderAuthority,
	retirement *oauthpg.ProxyRetirementAuthority, fenced bool) (*OAuthProxyProduction, error) {
	invalid := identity.InvalidInputError{Field: "reference_oauth_proxy_production"}
	if c.Codec == nil || nilServerDependency(c.Clock) {
		return nil, invalid
	}
	var forward *oauthpg.ProxyForwardService
	var err error
	if a == nil {
		forward, err = oauthpg.NewProxyForwardService(pool, c.Native)
	} else {
		forward, err = oauthpg.NewProxyForwardServiceWithProviderAuthority(pool, c.Native, a)
	}
	if err != nil {
		return nil, invalid
	}
	var start *oauthpg.ProxyStartService
	if fenced {
		start, err = oauthpg.NewProxyStartServiceWithCustodyFence(forward, c.Start)
	} else {
		start, err = oauthpg.NewProxyStartService(forward, c.Start)
	}
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
	result := &OAuthProxyProduction{start: start, forward: forward, pool: pool, provider: exchange.Profile(),
		productionDeployment: c.Native.ProductionDeployment, previewTarget: target, tenant: c.Start.Preview.TenantID,
		providerAuthority: a, retirement: retirement}
	if fenced {
		result.maintenanceSchema = c.Native.Schema
	}
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

// RetireDisabledProviderOrigin retires one exact configured production origin.
// A committed result is local only: it proves neither preview cleanup nor
// completion of a provider-wide cascade. Ambiguous results retain the original
// command for retry. No HTTP endpoint invokes this method.
func (p *OAuthProxyProduction) RetireDisabledProviderOrigin(ctx context.Context, request oauthpg.ProxyOriginRetirementRequest) (identity.CommandResult, error) {
	if p == nil || p.forward == nil || p.retirement == nil || request.Disable.Key.TenantID != p.tenant || request.Disable.Key.ProviderID != p.provider.ID {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	return p.forward.RetireDisabledProviderOrigin(ctx, p.retirement, request)
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
