package ssohttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
)

const (
	providerLogoutStart        = "identity.sso.oidc-logout"
	providerLogoutComplete     = "identity.sso.oidc-logout-complete"
	providerLogoutPrefix       = "/sso/oidc/"
	providerLogoutStartSuffix  = "/logout"
	providerLogoutReturnSuffix = "/logout/callback"
)

// ProviderLogoutStartRequest borrows the original browser credentials. Only
// the native owner authenticates the cookie/CSRF and performs revocation.
type ProviderLogoutStartRequest struct {
	TenantID              identity.TenantID
	ProviderID            string
	IdempotencyKey        identity.IdempotencyKey
	FinalRedirect, Origin string
	Session               authentication.BearerCredential
	CSRF                  session.CSRFToken
}

func (ProviderLogoutStartRequest) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.ProviderLogoutStartRequest(redacted)")
}
func (ProviderLogoutStartRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (ProviderLogoutStartRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// ProviderLogoutCompleteRequest borrows the raw browser return. CallbackURI
// contains the exact trusted HTTPS receiving URI, without the query.
type ProviderLogoutCompleteRequest struct {
	TenantID                          identity.TenantID
	ProviderID, CallbackURI, RawQuery string
}

func (ProviderLogoutCompleteRequest) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.ProviderLogoutCompleteRequest(redacted)")
}
func (ProviderLogoutCompleteRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (ProviderLogoutCompleteRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// ProviderLogoutRateContext is the native owner's non-consuming observation of
// the original provider, transaction and initial lifetime. It is not authority.
type ProviderLogoutRateContext struct {
	ProviderID, TransactionID string
	Lifetime                  time.Duration
}

// ProviderLogoutOwner owns durable logout independently of HTTP. The rate
// observation cannot reserve or consume state; Complete repeats admission.
type ProviderLogoutOwner interface {
	StartSSOOIDCLogout(context.Context, ProviderLogoutStartRequest) (oidc.LogoutStartResult, error)
	SSOOIDCLogoutRateSource(context.Context, ProviderLogoutCompleteRequest) (ProviderLogoutRateContext, error)
	CompleteSSOOIDCLogout(context.Context, ProviderLogoutCompleteRequest) (oidc.LogoutCompleteResult, error)
}

// ProviderLogoutRoute selects an exact installed provider. Empty endpoint
// selects local-only start; it does not expose that provider's callback.
type ProviderLogoutRoute struct {
	ProviderID, EndSessionEndpoint string
}

// ProviderLogoutConfig opts one HTTPS tenant into the selected provider
// routes. Session and CSRF cookies are cleared only after confirmed local
// revocation. Owner and shared Rate must outlive the selected feature.
type ProviderLogoutConfig struct {
	Network                identityhttp.NetworkConfig
	TenantID               identity.TenantID
	Origin                 identityhttp.Origin
	Rate                   *identityhttp.AuthRateLimiter
	MaximumDuration        time.Duration
	Cookie                 session.CookiePolicy
	CSRFCookie             session.CSRFCookiePolicy
	Providers              []ProviderLogoutRoute
	FinalRedirectAllowlist []string
	Owner                  ProviderLogoutOwner
}

type providerLogoutHTTP struct {
	tenant                 identity.TenantID
	origin                 identityhttp.Origin
	network                *identityhttp.NetworkResolver
	decoder                *identityhttp.RequestDecoder
	origins                *identityhttp.OriginGuard
	csrf                   *identityhttp.CSRFDecoder
	rate                   *identityhttp.AuthRateLimiter
	owner                  ProviderLogoutOwner
	authDelete, csrfDelete http.Cookie
	endpoints              map[string]string
	final                  map[string]bool
}

// NewProviderLogoutFeature selects only the explicitly configured provider
// paths. It doesn't enable discovery, sign-in, generic signout or issuance.
func NewProviderLogoutFeature(c ProviderLogoutConfig) (identityhttp.Feature, error) {
	p, starts, callbacks, err := newProviderLogoutHTTP(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	start, err := p.startHandler(c.MaximumDuration)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	const owner = "sso/oidc"
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: owner, OperationID: providerLogoutStart, Handler: start, ProviderPathIDs: starts,
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 8192,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = providerLogoutStartWire(p.authDelete.Name)
	operations := []identityhttp.OperationDescriptor{op}
	if len(callbacks) != 0 {
		complete, err := p.completeHandler(c.MaximumDuration)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err = identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
			Owner: owner, OperationID: providerLogoutComplete, Handler: complete, ProviderPathIDs: callbacks,
			CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
			MaximumSerializedBytes: 8192,
		})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = providerLogoutCompleteWire()
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: owner, Operations: operations})
}

func newProviderLogoutHTTP(c ProviderLogoutConfig) (providerLogoutHTTP, []string, []string, error) {
	invalid := func() (providerLogoutHTTP, []string, []string, error) {
		return providerLogoutHTTP{}, nil, nil, identityhttp.ErrInvalidInput
	}
	if c.TenantID == "" || !c.Rate.Configured() || !configuredOwner(c.Owner) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second ||
		len(c.Providers) == 0 || len(c.Providers) > 128 || len(c.FinalRedirectAllowlist) == 0 || len(c.FinalRedirectAllowlist) > 64 {
		return invalid()
	}
	origin, err := signinHTTPSURL(string(c.Origin))
	if err != nil || "https://"+origin.Host != string(c.Origin) {
		return invalid()
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return invalid()
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return invalid()
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return invalid()
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return invalid()
	}
	authDelete, authErr := c.Cookie.DeletionAttributes()
	csrfDelete, csrfErr := c.CSRFCookie.DeletionAttributes()
	if authErr != nil || csrfErr != nil || authDelete.Name == csrfDelete.Name {
		return invalid()
	}
	ends, finals := make(map[string]string, len(c.Providers)), make(map[string]bool, len(c.FinalRedirectAllowlist))
	starts, callbacks := make([]string, 0, len(c.Providers)), make([]string, 0, len(c.Providers))
	for _, route := range c.Providers {
		if _, found := ends[route.ProviderID]; found {
			return invalid()
		}
		if route.EndSessionEndpoint != "" {
			end, err := signinHTTPSURL(route.EndSessionEndpoint)
			if err != nil || end.RawQuery != "" || len(route.EndSessionEndpoint) > 2048 {
				return invalid()
			}
			callbacks = append(callbacks, route.ProviderID)
		}
		starts, ends[route.ProviderID] = append(starts, route.ProviderID), route.EndSessionEndpoint
	}
	for _, target := range c.FinalRedirectAllowlist {
		if _, err := signinHTTPSURL(target); err != nil || len(target) > 2048 || finals[target] {
			return invalid()
		}
		finals[target] = true
	}
	return providerLogoutHTTP{tenant: c.TenantID, origin: c.Origin, network: network, decoder: decoder, origins: origins, csrf: csrf,
		rate: c.Rate, owner: c.Owner, authDelete: authDelete, csrfDelete: csrfDelete, endpoints: ends, final: finals}, starts, callbacks, nil
}

func (p providerLogoutHTTP) requestPath(r *http.Request, method, suffix string) (identityhttp.NetworkFacts, string, error) {
	if r.URL == nil || r.Method != method || r.URL.RawPath != "" || r.URL.ForceQuery || len(r.Trailer) != 0 ||
		headerPresent(r.Header, "Authorization") || headerPresent(r.Header, "Proxy-Authorization") {
		return identityhttp.NetworkFacts{}, "", identityhttp.ErrInvalidInput
	}
	part, prefix := strings.CutPrefix(r.URL.Path, providerLogoutPrefix)
	provider, path := strings.CutSuffix(part, suffix)
	if _, selected := p.endpoints[provider]; !prefix || !path || !selected || method == http.MethodGet && p.endpoints[provider] == "" {
		return identityhttp.NetworkFacts{}, "", sso.ErrForbidden
	}
	facts, err := p.network.Resolve(r)
	if err != nil || facts.Realm() != identityhttp.RealmTenant || facts.TenantID() != p.tenant || facts.Origin() != string(p.origin) {
		return identityhttp.NetworkFacts{}, "", sso.ErrForbidden
	}
	return facts, provider, nil
}

type providerLogoutStartState struct {
	facts   identityhttp.NetworkFacts
	request ProviderLogoutStartRequest
}

func (p providerLogoutHTTP) startHandler(maximum time.Duration) (http.Handler, error) {
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[providerLogoutStartState]{
		MaximumDuration: maximum, Reject: writeSigninError,
		Decode: func(r *http.Request) (s providerLogoutStartState, err error) {
			facts, provider, err := p.requestPath(r, http.MethodPost, providerLogoutStartSuffix)
			if err != nil {
				return s, err
			}
			if r.URL.RawQuery != "" {
				return s, identityhttp.ErrInvalidInput
			}
			key, _, err := p.decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			cookie, _, err := p.decoder.CookieBearer(r, p.authDelete.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, sso.ErrForbidden
			}
			csrf, _, err := identityhttp.DecodeCSRF(p.csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, sso.ErrForbidden
			}
			body, err := identityhttp.DecodeJSON[map[string]string](p.decoder, r)
			if err != nil || len(body) != 1 || body["finalRedirect"] == "" {
				return s, identityhttp.ErrInvalidInput
			}
			if !p.final[body["finalRedirect"]] {
				return s, sso.ErrForbidden
			}
			return providerLogoutStartState{facts, ProviderLogoutStartRequest{facts.TenantID(), provider, key, body["finalRedirect"], facts.Origin(), cookie, csrf}}, nil
		},
		Authenticate: func(r *http.Request, s providerLogoutStartState) (providerLogoutStartState, error) {
			return s, admitSigninIP(r.Context(), p.rate, s.facts, providerLogoutStart, s.request.ProviderID)
		},
		Admit: func(*http.Request, providerLogoutStartState) error { return nil },
		Handle: func(w http.ResponseWriter, r *http.Request, s providerLogoutStartState) {
			out, err := p.owner.StartSSOOIDCLogout(r.Context(), s.request)
			if err != nil {
				writeSigninError(w, r, err)
				return
			}
			p.deliverStart(w, r, s.request, out)
		},
	})
}

type providerLogoutCompleteState struct {
	facts   identityhttp.NetworkFacts
	request ProviderLogoutCompleteRequest
	source  ProviderLogoutRateContext
}

func (p providerLogoutHTTP) completeHandler(maximum time.Duration) (http.Handler, error) {
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[providerLogoutCompleteState]{
		MaximumDuration: maximum, Reject: writeSigninError,
		Decode: func(r *http.Request) (s providerLogoutCompleteState, err error) {
			facts, provider, err := p.requestPath(r, http.MethodGet, providerLogoutReturnSuffix)
			if err != nil {
				return s, err
			}
			if r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody || headerPresent(r.Header, "X-CSRF-Token") {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := p.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if headerPresent(r.Header, "Origin") {
				if _, err := p.origins.CheckBound(r, p.origin); err != nil {
					return s, sso.ErrForbidden
				}
			}
			if _, err := oidc.ParseRPLogoutCallback(r.URL.RawQuery); err != nil {
				return s, err
			}
			s.facts = facts
			s.request = ProviderLogoutCompleteRequest{facts.TenantID(), provider, facts.Origin() + r.URL.Path, r.URL.RawQuery}
			return s, nil
		},
		Authenticate: func(r *http.Request, s providerLogoutCompleteState) (providerLogoutCompleteState, error) {
			ctx := r.Context()
			if err := admitSigninIP(ctx, p.rate, s.facts, providerLogoutComplete, s.request.ProviderID); err != nil {
				return s, err
			}
			source, err := p.owner.SSOOIDCLogoutRateSource(ctx, s.request)
			if err != nil {
				return s, err
			}
			_, err = identity.ParseCommandID(source.TransactionID)
			if err != nil || source.ProviderID != s.request.ProviderID {
				return s, sso.ErrForbidden
			}
			s.source = source
			return s, nil
		},
		Admit: func(r *http.Request, s providerLogoutCompleteState) error {
			decision, err := p.rate.AdmitProviderTransaction(r.Context(), s.facts, providerLogoutComplete, s.source.ProviderID, s.source.TransactionID, s.source.Lifetime)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return discoveryRateDenial{retry: decision.RetryAfter}
			}
			if err != nil || !decision.Allowed {
				return identityhttp.ErrRateUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s providerLogoutCompleteState) {
			out, err := p.owner.CompleteSSOOIDCLogout(r.Context(), s.request)
			if err != nil {
				writeSigninError(w, r, err)
				return
			}
			p.deliverComplete(w, r, s.request, out)
		},
	})
}

func (p providerLogoutHTTP) deliverStart(w http.ResponseWriter, r *http.Request, request ProviderLogoutStartRequest, out oidc.LogoutStartResult) {
	result, err := out.Completion()
	if err != nil || result.Binding.TenantID != request.TenantID {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	switch out.Outcome() {
	case oidc.OIDCLogoutUnknownReconciliation:
		writeLogoutOutcome(w, http.StatusServiceUnavailable, "unknown-reconciliation")
	case oidc.OIDCLogoutLocalOnly:
		clearSigninHeaders(w)
		p.deleteCookies(w)
		writeDiscoveryJSON(w, http.StatusOK, logoutOutcomeBody{"local-only"})
	case oidc.OIDCLogoutRedirect:
		target, ok := out.RedirectURI()
		if !ok || !p.validProviderRedirect(target, request.ProviderID) {
			writeSigninError(w, r, identityhttp.ErrUnavailable)
			return
		}
		clearSigninHeaders(w)
		p.deleteCookies(w)
		writeLogoutRedirect(w, target.String())
	default:
		writeSigninError(w, r, identityhttp.ErrUnavailable)
	}
}

func (p providerLogoutHTTP) validProviderRedirect(target url.URL, provider string) bool {
	query, err := url.ParseQuery(target.RawQuery)
	if err != nil || len(query) != 3 || len(query["client_id"]) != 1 || query.Get("client_id") == "" ||
		len(query["post_logout_redirect_uri"]) != 1 || query.Get("post_logout_redirect_uri") != string(p.origin)+providerLogoutPrefix+provider+providerLogoutReturnSuffix ||
		len(query["state"]) != 1 || target.ForceQuery {
		return false
	}
	if _, err := oidc.ParseRPLogoutCallback("state=" + url.QueryEscape(query.Get("state"))); err != nil {
		return false
	}
	target.RawQuery = ""
	return target.String() == p.endpoints[provider]
}

func (p providerLogoutHTTP) deleteCookies(w http.ResponseWriter) {
	auth, csrf := p.authDelete, p.csrfDelete
	http.SetCookie(w, &auth)
	http.SetCookie(w, &csrf)
}

func (p providerLogoutHTTP) deliverComplete(w http.ResponseWriter, r *http.Request, request ProviderLogoutCompleteRequest, out oidc.LogoutCompleteResult) {
	result, err := out.Completion()
	if err != nil || result.Binding.TenantID != request.TenantID {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	switch out.Outcome() {
	case oidc.OIDCLogoutRedirect:
		target, ok := out.RedirectURI()
		if !ok || !p.final[target.String()] {
			writeSigninError(w, r, identityhttp.ErrUnavailable)
			return
		}
		clearSigninHeaders(w)
		writeLogoutRedirect(w, target.String())
	case oidc.OIDCLogoutLocalOnly:
		writeLogoutOutcome(w, http.StatusOK, "local-only")
	case oidc.OIDCLogoutProviderComplete:
		writeLogoutOutcome(w, http.StatusOK, "provider-complete")
	case oidc.OIDCLogoutProviderError:
		writeLogoutOutcome(w, http.StatusOK, "provider-error")
	case oidc.OIDCLogoutTimeout:
		writeLogoutOutcome(w, http.StatusOK, "timeout")
	case oidc.OIDCLogoutUnknownReconciliation:
		writeLogoutOutcome(w, http.StatusServiceUnavailable, "unknown-reconciliation")
	default:
		writeSigninError(w, r, identityhttp.ErrUnavailable)
	}
}

type logoutOutcomeBody struct {
	Outcome string `json:"outcome"`
}

func writeLogoutOutcome(w http.ResponseWriter, status int, outcome string) {
	clearSigninHeaders(w)
	writeDiscoveryJSON(w, status, logoutOutcomeBody{outcome})
}

func writeLogoutRedirect(w http.ResponseWriter, destination string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Location", destination)
	// Do not duplicate provider state in an HTML redirect body.
	w.WriteHeader(http.StatusSeeOther)
}
