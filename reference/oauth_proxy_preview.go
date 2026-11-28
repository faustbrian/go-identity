package reference

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// OAuthProxyPreviewPath is the exact configured browser handoff endpoint for
// the Reference preview, distinct from the provider's production callback.
const OAuthProxyPreviewPath = identityhttp.OAuthPreviewRelayPath

// OAuthProxyPreviewConfiguration selects the existing linked-account preview
// session owner and its separately enrolled production deployment. Nil HTTP
// keeps browser completion and the named HTTP preauth method disabled.
type OAuthProxyPreviewConfiguration struct {
	Native oauthpg.ProxyPreviewConfig
	HTTP   *HTTPOAuthProxyPreviewConfiguration
}

// HTTPOAuthProxyPreviewConfiguration opts into the exact landing and
// completion. SuccessURL is a distinct configured HTTPS path at the preview
// origin. Only a completed browser POST may navigate there.
type HTTPOAuthProxyPreviewConfiguration struct{ SuccessURL string }

// OAuthProxyPreviewStartRequest carries the original browser and trusted
// invocation for the in-process deployment bridge. Network and Device must
// come from the trusted preview transport; never accept them from browser JSON.
type OAuthProxyPreviewStartRequest struct {
	Initiation      oauthproxy.InitiationRequest
	FlowCookie      auth.BearerCredential
	Network, Device string
}

type oauthProxyPreviewState struct {
	owner     *oauthpg.ProxyPreviewService
	config    oauthpg.ProxyPreviewConfig
	provider  oauth.ProviderProfile
	http      *HTTPOAuthProxyPreviewConfiguration
	signin    *socialSigninState
	duration  time.Duration
	authority *oauthpg.ProviderAuthority
}

func composeOAuthProxyPreview(c StoreConfiguration, social *socialOAuthState, a *oauthpg.ProviderAuthority) (*oauthProxyPreviewState, error) {
	if c.OAuthProxyPreview == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_oauth_proxy_preview"}
	n := *c.OAuthProxyPreview
	if social == nil || social.signin == nil || c.SocialOAuth == nil || len(c.SocialOAuth.Providers) != 1 ||
		n.Native.ActorID != social.signin.actor || n.Native.Target.Redirect != social.signin.callback || nilServerDependency(n.Native.Clock) {
		return nil, invalid
	}
	if n.HTTP != nil {
		if c.OTP == nil || c.OTP.PreAuth == nil || c.OTP.PreAuth.Origin != social.origin || c.SocialOAuth.Signin.FlowTTL != 5*time.Minute ||
			c.HTTPPreAuth == nil || c.HTTPPreAuth.Device == nil || c.HTTPSession == nil || c.HTTPSession.Transport != session.CredentialCookie ||
			!slices.Contains(c.HTTPSession.TrustedOrigins, identityhttp.Origin(social.origin)) ||
			c.HTTPRate == nil || n.Native.Target.Redirect != social.origin+OAuthProxyPreviewPath ||
			c.HTTPSocialOAuth != nil && c.HTTPSocialOAuth.SigninStart {
			return nil, invalid
		}
		flow, flowErr := social.signin.flowCookie.DeletionAttributes()
		preauth, preauthErr := c.OTP.PreAuth.Cookie.DeletionAttributes()
		if flowErr != nil || preauthErr != nil || flow.String() != preauth.String() {
			return nil, invalid
		}
		if _, err := oauthhttp.NewProxyHandoffLanding(n.Native.Target.Redirect, n.HTTP.SuccessURL); err != nil {
			return nil, invalid
		}
		selection := *n.HTTP
		n.HTTP = &selection
	}
	provider := c.SocialOAuth.Providers[0].Profile()
	if provider.ValidateQueryCallback() != nil {
		return nil, invalid
	}
	var owner *oauthpg.ProxyPreviewService
	var err error
	if a == nil {
		owner, err = oauthpg.NewProxyPreviewService(social.signin.complete, n.Native)
	} else {
		owner, err = oauthpg.NewProxyPreviewServiceWithProviderAuthority(social.signin.complete, n.Native, a)
	}
	if err != nil {
		return nil, invalid
	}
	return &oauthProxyPreviewState{owner: owner, config: n.Native, provider: provider, http: n.HTTP, signin: social.signin, duration: min(social.duration, 20*time.Second), authority: a}, nil
}

// StartOAuthProxyPreview commits the authenticated production Start, then
// acknowledges the original preview browser binding before releasing the
// provider authorization. Errors and ambiguous commits never disclose the URL
// and do not retry production. This direct Go bridge is not a remote protocol.
func (f FeatureSet) StartOAuthProxyPreview(ctx context.Context, production *OAuthProxyProduction, request OAuthProxyPreviewStartRequest) (oauth.AuthorizationRequest, error) {
	if f.state == nil || production == nil || production.start == nil {
		return oauth.AuthorizationRequest{}, oauthproxy.CompletionInvalid
	}
	work, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return oauth.AuthorizationRequest{}, oauthproxy.CompletionUnavailable
	}
	defer done()
	preview := f.state.features.oauthProxyPreview
	if preview == nil || sameProxyDatabase(f.state.pool, production.pool) || !matchingProxyProduction(preview, production) {
		return oauth.AuthorizationRequest{}, oauthproxy.CompletionDenied
	}
	peer, peerErr := netip.ParseAddr(request.Network)
	if peerErr != nil || peer.Zone() != "" || peer.IsUnspecified() || peer.IsMulticast() || peer.Unmap().String() != request.Network ||
		len(request.Device) == 0 || len(request.Device) > 128 || strings.IndexFunc(request.Device, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return oauth.AuthorizationRequest{}, oauthproxy.CompletionInvalid
	}
	if _, err := session.ParseToken(request.FlowCookie.Token()); err != nil {
		return oauth.AuthorizationRequest{}, oauthproxy.CompletionInvalid
	}
	started, err := production.Start(work, request.Initiation)
	if err != nil {
		return oauth.AuthorizationRequest{}, err
	}
	binding, bound := started.Binding()
	authorization, issuable := started.Authorization()
	if !bound || !issuable {
		return oauth.AuthorizationRequest{}, oauthproxy.CompletionUnavailable
	}
	if err := preview.owner.Bind(work, oauthpg.ProxyPreviewBindRequest{
		Binding: binding, FlowCookie: request.FlowCookie, Origin: preview.config.Target.Origin,
		Network: request.Network, Device: request.Device,
	}); err != nil {
		if work.Err() != nil {
			return oauth.AuthorizationRequest{}, oauthproxy.CompletionUnavailable
		}
		return oauth.AuthorizationRequest{}, err
	}
	if work.Err() != nil || !preview.config.Clock.Now().Before(binding.ExpiresAt) {
		return oauth.AuthorizationRequest{}, oauthproxy.CompletionUnavailable
	}
	return authorization, nil
}

// RetireDisabledOAuthProxyPreviewOrigin retires one original preview binding
// using the selected shared disable evidence. It opens no production work and
// creates or revokes no session. A committed result acknowledges this origin
// only; retry the exact request after an ambiguous result.
func (f FeatureSet) RetireDisabledOAuthProxyPreviewOrigin(ctx context.Context, request oauthpg.ProxyOriginRetirementRequest) (identity.CommandResult, error) {
	if f.state == nil || f.state.proxyPreviewRetirement == nil {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	work, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	preview := f.state.features.oauthProxyPreview
	if preview == nil || preview.owner == nil || request.Disable.Key.ProviderID != preview.provider.ID {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	return preview.owner.RetireDisabledProviderOrigin(work, f.state.proxyPreviewRetirement, request)
}

func sameProxyDatabase(preview, production *database.Pool) bool {
	if preview == nil || production == nil || preview.Raw() == nil || production.Raw() == nil || preview.Raw() == production.Raw() {
		return true
	}
	a, b := preview.Raw().Config().ConnConfig, production.Raw().Config().ConnConfig
	return a.Host == b.Host && a.Port == b.Port && a.Database == b.Database
}

func matchingProxyProduction(preview *oauthProxyPreviewState, production *OAuthProxyProduction) bool {
	p, n := production.provider, preview.provider
	// This is an in-process bridge: reject mismatched live mode or readers
	// before either deployment consumes Start. Static pairs both use nil.
	return production.providerAuthority == preview.authority && production.productionDeployment == preview.config.ProductionDeployment &&
		production.previewTarget == preview.config.Target &&
		production.tenant == preview.config.TenantID && p.ID == n.ID && p.Version == n.Version && p.Issuer == n.Issuer && p.ClientID == n.ClientID
}

func (s *Server) oauthProxyPreviewHandler(network *identityhttp.NetworkResolver) (http.Handler, error) {
	p := s.state.features.oauthProxyPreview
	if p == nil || p.http == nil {
		return nil, nil
	}
	f := s.state.features
	if f.httpPreAuth == nil || f.httpPreAuth.device == nil || f.session == nil || f.httpSession == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_oauth_proxy_preview"}
	}
	selected, err := oauthhttp.NewProxyPreviewBrowserHandler(oauthhttp.ProxyPreviewConfig{
		Endpoint: p.config.Target.Redirect, TenantID: p.config.TenantID, ProviderID: p.provider.ID,
		Audience: p.signin.audience, Network: network, FlowCookie: p.signin.flowCookie, Cookie: f.session.config.Cookie,
		Device: *f.httpPreAuth.device, CSRFCookie: p.signin.csrfCookie, Now: p.config.Clock.Now, MaximumDuration: p.duration,
		Complete: func(ctx context.Context, id identity.PreAuthTransactionID, handoff oauthproxy.PreviewCompletionRequest, peer, device string) (oauth.SigninCallbackResult, error) {
			return p.owner.Complete(ctx, oauthpg.ProxyPreviewCallbackRequest{FlowID: id, Handoff: handoff, Network: peer, Device: device})
		},
	}, p.http.SuccessURL)
	if err != nil {
		return nil, err
	}
	return s.guardTenant(network, s.guardSessionLifetime(selected)), nil
}

func (OAuthProxyPreviewStartRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.OAuthProxyPreviewStartRequest(redacted)")
}

func (OAuthProxyPreviewStartRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (OAuthProxyPreviewStartRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
