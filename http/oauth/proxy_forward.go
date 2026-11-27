package oauthhttp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/risk"
)

// ProxyForwardPath is the fixed production provider return, not a preview route.
const ProxyForwardPath = "/oauth2/callback/proxy"

const proxyForwardOperation = "identity.oauth.proxy-forward"

// ProxyForwardCallback borrows the bounded original query synchronously. Lookup
// parses it under the native owner's frozen provider/deployment configuration
// without reservation or provider work. Handle independently authenticates,
// reserves and settles original state before releasing an encrypted handoff.
// Implementations must support concurrent requests and retain no query custody.
type ProxyForwardCallback interface {
	Lookup(context.Context, string, string) (oauthproxy.CallbackLookup, error)
	Handle(context.Context, string, string) (oauthproxy.CallbackResult, error)
}

// ProxyCallbackRateSource authenticates original transaction attribution without
// reservation, exchange or side effects. Tenant is trusted network configuration;
// lookup is an exact bound native parser result, never a request-selected ID.
type ProxyCallbackRateSource interface {
	ProxyCallbackRateSource(context.Context, identity.TenantID, oauthproxy.CallbackLookup) (oauth.CallbackRateContext, error)
}

// ProxyForwardConfig freezes one production tenant/provider/deployment and its
// exact registered HTTPS preview return URLs. Network and slices are copied;
// Callback, RateSource, Rate and Risk are borrowed concurrency-safe owners. Risk
// must support counted, audited Authentication admission for this exact action
// using only trusted network and authenticated original transaction dimensions.
// Now must be prompt and concurrency-safe. MaximumDuration is 1ms..30s; earlier
// caller deadlines win. No session, cookie, identity store or resource is owned.
type ProxyForwardConfig struct {
	Network              identityhttp.NetworkConfig
	Origin               identityhttp.Origin
	TenantID             identity.TenantID
	Provider             oauth.ProviderProfile
	ProductionDeployment string
	Callback             ProxyForwardCallback
	RateSource           ProxyCallbackRateSource
	Rate                 *identityhttp.AuthRateLimiter
	Risk                 risk.Evaluator
	AllowedTargets       []string
	Now                  func() time.Time
	MaximumDuration      time.Duration
}

// Format redacts runtime composition and private deployment registrations.
func (ProxyForwardConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.ProxyForwardConfig(redacted)"))
}

// MarshalJSON rejects implicit runtime composition export.
func (ProxyForwardConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText rejects implicit runtime composition export.
func (ProxyForwardConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

type proxyForwardState struct {
	facts    identityhttp.NetworkFacts
	expected oauthproxy.CallbackLookup
	source   oauth.CallbackRateContext
}

func (proxyForwardState) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.proxyForwardState(redacted)"))
}

// NewProxyForwardHandler accepts exact HTTPS GET /oauth2/callback/proxy with a
// valid provider query and no body, trailer, retry key or bearer alternative.
// An absent Origin permits provider navigation; a present Origin must exactly
// match production, with no Referer fallback. Cookies are never inspected.
// Ordered shared IP and authenticated original-transaction budgets precede a
// counted, audited risk Allow and native completion; all failures deny without
// retry. Only an acknowledged, unexpired, exact-target native result produces
// 303 with an opaque fragment handoff and an empty body. No cookies or provider
// credentials are emitted. Callers own request/response streaming lifetimes.
func NewProxyForwardHandler(c ProxyForwardConfig) (http.Handler, error) {
	if missing(c.Callback) || missing(c.RateSource) || !c.Rate.Configured() || c.Now == nil ||
		c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second ||
		!proxyForwardDeployment(c.ProductionDeployment) || c.Provider.ValidateQueryCallback() != nil ||
		c.Provider.RedirectURI != string(c.Origin)+ProxyForwardPath {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := identity.ParseIdentifierID(string(c.TenantID)); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	c.Provider.Scopes, c.Provider.Algorithms = slices.Clone(c.Provider.Scopes), slices.Clone(c.Provider.Algorithms)
	c.AllowedTargets = slices.Clone(c.AllowedTargets)
	if len(c.AllowedTargets) == 0 || len(c.AllowedTargets) > 64 {
		return nil, identityhttp.ErrInvalidInput
	}
	for index, target := range c.AllowedTargets {
		endpoint, err := proxyHandoffEndpoint(target)
		if err != nil || endpoint.Path == "/" || slices.Contains(c.AllowedTargets[:index], target) {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[proxyForwardState]{
		MaximumDuration: c.MaximumDuration,
		Reject:          proxyForwardReject,
		Decode: func(r *http.Request) (s proxyForwardState, err error) {
			if r.Method != http.MethodGet || r.URL.Path != ProxyForwardPath || r.URL.RawPath != "" || r.URL.ForceQuery ||
				r.URL.RawQuery == "" || r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody ||
				len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant || s.facts.TenantID() != c.TenantID ||
				s.facts.Scheme() != "https" || s.facts.Origin() != string(c.Origin) {
				return s, identity.ForbiddenError{}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if callbackOriginPresent(r) {
				if _, err := origins.CheckBound(r, c.Origin); err != nil {
					return s, identity.ForbiddenError{}
				}
			}
			s.expected, err = proxyForwardParsedLookup(r.Context(), c, r.URL.RawQuery)
			return s, err
		},
		Authenticate: func(r *http.Request, s proxyForwardState) (proxyForwardState, error) {
			admitted, err := c.Rate.AdmitProviderIP(r.Context(), s.facts, proxyForwardOperation, c.Provider.ID)
			if err := proxyForwardRateError(admitted, err); err != nil {
				return s, err
			}
			lookup, err := c.Callback.Lookup(r.Context(), c.Provider.RedirectURI, r.URL.RawQuery)
			if err != nil {
				return s, err
			}
			if lookup != s.expected {
				return s, identity.ForbiddenError{}
			}
			s.source, err = c.RateSource.ProxyCallbackRateSource(r.Context(), c.TenantID, lookup)
			if err != nil {
				return s, err
			}
			if s.source.ProviderID != c.Provider.ID {
				return s, identity.ForbiddenError{}
			}
			if _, err := identity.ParsePreAuthTransactionID(s.source.TransactionID); err != nil {
				return s, identity.ForbiddenError{}
			}
			return s, nil
		},
		Admit: func(r *http.Request, s proxyForwardState) error {
			admitted, err := c.Rate.AdmitProviderTransaction(r.Context(), s.facts, proxyForwardOperation, s.source.ProviderID, s.source.TransactionID, s.source.Lifetime)
			if err := proxyForwardRateError(admitted, err); err != nil {
				return err
			}
			return proxyForwardRisk(r.Context(), c.Risk, c.TenantID, s.facts, s.source.TransactionID)
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s proxyForwardState) {
			result, err := c.Callback.Handle(r.Context(), c.Provider.RedirectURI, r.URL.RawQuery)
			if err != nil {
				proxyForwardReject(w, r, err)
				return
			}
			flow, cutoff, ok := result.Continuation()
			if !ok || string(flow) != s.source.TransactionID || !slices.Contains(c.AllowedTargets, result.Destination()) {
				proxyForwardReject(w, r, identityhttp.ErrUnavailable)
				return
			}
			envelope := result.Envelope()
			defer clear(envelope)
			location, err := proxyHandoffLocation(result.Destination(), flow, envelope)
			if err != nil || r.Context().Err() != nil {
				proxyForwardReject(w, r, identityhttp.ErrUnavailable)
				return
			}
			// Keep the native original cutoff at the last write boundary. Building
			// the Location must not turn it into a renewed transport lifetime.
			now := c.Now()
			if now.IsZero() || !now.Before(cutoff) || r.Context().Err() != nil {
				proxyForwardReject(w, r, identityhttp.ErrUnavailable)
				return
			}
			proxyForwardHeaders(w)
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusSeeOther)
		},
	})
}

func proxyForwardParsedLookup(ctx context.Context, c ProxyForwardConfig, rawQuery string) (oauthproxy.CallbackLookup, error) {
	query, err := oauth.ParseQueryCallback(ctx, rawQuery, c.Provider)
	if err != nil {
		return oauthproxy.CallbackLookup{}, identityhttp.ErrInvalidInput
	}
	defer query.Destroy()
	var digest [32]byte
	hash := func(_ context.Context, state []byte) error {
		digest = sha256.Sum256(state)
		return nil
	}
	if query.Denied() {
		err = query.UseDeniedState(ctx, hash)
	} else if input, ok := query.Input(); ok {
		err = input.Use(ctx, func(ctx context.Context, _, state []byte) error { return hash(ctx, state) })
	} else {
		err = identityhttp.ErrInvalidInput
	}
	if err != nil {
		return oauthproxy.CallbackLookup{}, identityhttp.ErrInvalidInput
	}
	return oauthproxy.CallbackLookup{StateDigest: digest, ProductionDeployment: c.ProductionDeployment,
		ProductionCallback: c.Provider.RedirectURI, ProviderID: c.Provider.ID, ProviderVersion: c.Provider.Version,
		Issuer: c.Provider.Issuer, ClientID: c.Provider.ClientID, ProviderDenied: query.Denied()}, nil
}

func proxyForwardRisk(ctx context.Context, evaluator risk.Evaluator, tenant identity.TenantID, facts identityhttp.NetworkFacts, transaction string) error {
	attempt, err := identity.NewCommandID()
	if err != nil {
		return identityhttp.ErrUnavailable
	}
	scope := risk.Context{Tenant: string(tenant), Operation: risk.Action(proxyForwardOperation), Attempt: string(attempt)}
	subject := risk.Subject{Network: facts.ClientIP().String(), Resource: transaction}
	result, err := evaluator.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Subject: subject, Phase: risk.NonIssuing,
		Attribution: &risk.DecisionAttribution{CommandID: attempt, CorrelationID: attempt,
			Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(attempt)}})
	if err != nil {
		return identityhttp.ErrUnavailable
	}
	if err := evaluator.RequireAuthenticationAdmission(ctx, result, scope, subject); err != nil {
		if result.Decision.Action == risk.Throttle {
			return providerRateFailure{retry: result.Decision.RetryAfter}
		}
		if result.Decision.Action == risk.Deny || result.Decision.Action == risk.StepUp {
			return identity.ForbiddenError{}
		}
		return identityhttp.ErrUnavailable
	}
	return nil
}

func proxyForwardRateError(result identityhttp.AuthRateResult, err error) error {
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return providerRateFailure{retry: result.RetryAfter}
	}
	if err != nil || !result.Allowed {
		return identityhttp.ErrUnavailable
	}
	return nil
}

func proxyForwardDeployment(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, b := range []byte(value) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

func proxyForwardHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Del("Set-Cookie")
}

func proxyForwardReject(w http.ResponseWriter, _ *http.Request, cause error) {
	status, code := http.StatusServiceUnavailable, "unavailable"
	var limited providerRateFailure
	var forbidden identity.ForbiddenError
	switch {
	case errors.As(cause, &limited):
		status, code = http.StatusTooManyRequests, "rate_limited"
		retry := min(max(limited.retry, time.Second), time.Hour)
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
	case errors.Is(cause, identityhttp.ErrInvalidInput), errors.Is(cause, oauthproxy.CallbackInvalid):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.As(cause, &forbidden), errors.Is(cause, oauthproxy.CallbackDenied), errors.Is(cause, oauthproxy.ErrOriginalUnavailable):
		status, code = http.StatusForbidden, "denied"
	}
	proxyForwardHeaders(w)
	w.Header().Del("Location")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{code})
}
