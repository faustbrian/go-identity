package oauthhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

// SigninStartConfig selects native existing-account OIDC initiation, not account
// linking or signup. Start and Rate are borrowed concurrency-safe owners and
// must honor bounded contexts. Construction performs no IO and snapshots slices.
// FlowCookie and Device must match original preauth initialization and use Lax
// cookies for the provider's top-level GET callback. Lifetime resolves the same
// original Remember policy; the native owner verifies that binding. ActorID and
// PolicyRevision identify the trusted login service, never an inbound user.
// No current-session reader, provider engine or state store is required.
type SigninStartConfig struct {
	Network           identityhttp.NetworkConfig
	Provider          oauth.ProviderProfile
	Start             oauth.SigninStarter
	Rate              *identityhttp.AuthRateLimiter
	FlowCookie        session.CookiePolicy
	Device            session.BrowserDeviceConfig
	Origin            identityhttp.Origin
	CallbackAllowlist []string
	Lifetime          session.LifetimeConfig
	ActorID           identity.ActorID
	PolicyRevision    authorization.Revision
	Now               func() time.Time
	MaximumDuration   time.Duration
}

type signinStartState struct {
	facts   identityhttp.NetworkFacts
	request oauth.SigninStartRequest
	device  session.BrowserDevice
}

type providerRateFailure struct{ retry time.Duration }

func (providerRateFailure) Error() string { return "identity.http.rate_limited" }

// NewSigninStartHandler selects only POST /v1/oauth/signin-start. It requires
// exact HTTPS tenant/Origin, original flow and signed device cookies, one
// Idempotency-Key and closed bounded JSON. The body requires flowID, provider,
// callback, errorCallback, scopes and signupDisabled:true; remember is optional.
// Provider/IP admission precedes one native call. That owner authenticates
// original preauth intent and issues durable state/S256; transport never looks
// up a current user/session, retries, issues cookies or accepts other variants.
// Success is an explicit no-store authorization-URL/transaction/expiry projection,
// never implicit serialization of native custody. MaximumDuration is 1ms..30s;
// earlier deadlines win. Now must be prompt and concurrency-safe.
func NewSigninStartHandler(c SigninStartConfig) (http.Handler, error) {
	if missing(c.Start) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	c.Provider.Scopes, c.Provider.Algorithms = slices.Clone(c.Provider.Scopes), slices.Clone(c.Provider.Algorithms)
	c.CallbackAllowlist = slices.Clone(c.CallbackAllowlist)
	if c.Provider.ValidateQueryCallback() != nil || c.Provider.RedirectURI != string(c.Origin)+"/v1/oauth/callback" || len(c.CallbackAllowlist) == 0 {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := oauth.NewValidatedCallbackURL(c.CallbackAllowlist[0], c.CallbackAllowlist); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := session.ResolveRememberPolicy(session.RememberDefault, c.Lifetime); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	flow, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flow.Name != "__Host-identity_flow" || flow.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	deviceCookie, err := c.Device.Cookie.DeletionAttributes()
	if err != nil || deviceCookie.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
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
	caller := func(tenant identity.TenantID, flowID identity.PreAuthTransactionID) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.oauth.signin-start", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flowID)}}}
	}
	if caller("configuration", "configuration").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, _ *http.Request, cause error) {
		status, code := http.StatusServiceUnavailable, "unavailable"
		var invalid identity.InvalidInputError
		var forbidden identity.ForbiddenError
		var conflict identity.ConflictError
		var native *oauth.Error
		var limited providerRateFailure
		switch {
		case errors.As(cause, &limited):
			status, code = http.StatusTooManyRequests, "rate_limited"
			retry := min(max(limited.retry, time.Second), time.Hour)
			w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
		case errors.Is(cause, identityhttp.ErrInvalidInput), errors.As(cause, &invalid):
			status, code = http.StatusBadRequest, "invalid_request"
		case errors.As(cause, &forbidden):
			status, code = http.StatusForbidden, "denied"
		case errors.As(cause, &conflict):
			status, code = http.StatusConflict, "conflict"
		case errors.As(cause, &native):
			if native.Kind() == oauth.InvalidInput {
				status, code = http.StatusBadRequest, "invalid_request"
			} else if native.Kind() == oauth.InvalidProof || native.Kind() == oauth.Refused {
				status, code = http.StatusForbidden, "denied"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{code})
	}
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[signinStartState]{MaximumDuration: c.MaximumDuration, Reject: reject,
		Decode: func(r *http.Request) (s signinStartState, err error) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth/signin-start" || r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant || s.facts.Scheme() != "https" || s.facts.Origin() != string(c.Origin) {
				return s, identity.ForbiddenError{}
			}
			if _, err := origins.CheckBound(r, c.Origin); err != nil {
				return s, identity.ForbiddenError{}
			}
			for name := range r.Header {
				if strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			key, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			bearer, _, err := decoder.CookieBearer(r, flow.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(bearer.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			device, _, err := decoder.CookieBearer(r, deviceCookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(r.Context(), c.Now(), s.facts.TenantID(), s.facts.Origin(), device.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) < 6 || len(body) > 7 {
				return s, identityhttp.ErrInvalidInput
			}
			var flowID string
			var wire wireStart
			for name, target := range map[string]any{"flowID": &flowID, "provider": &wire.Provider, "callback": &wire.Callback, "errorCallback": &wire.ErrorCallback, "scopes": &wire.Scopes, "signupDisabled": &wire.SignupDisabled} {
				raw, exists := body[name]
				if !exists || string(raw) == "null" || json.Unmarshal(raw, target) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			choice := session.RememberDefault
			if raw, exists := body["remember"]; exists {
				var remember bool
				if string(raw) == "null" || json.Unmarshal(raw, &remember) != nil {
					return s, identityhttp.ErrInvalidInput
				}
				choice = session.BrowserSession
				if remember {
					choice = session.PersistentSession
				}
			} else if len(body) != 6 {
				return s, identityhttp.ErrInvalidInput
			}
			id, err := identity.ParsePreAuthTransactionID(flowID)
			if err != nil || wire.Provider != c.Provider.ID || !wire.SignupDisabled {
				return s, identityhttp.ErrInvalidInput
			}
			success, err := oauth.NewValidatedCallbackURL(wire.Callback, c.CallbackAllowlist)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			failure, err := oauth.NewValidatedCallbackURL(wire.ErrorCallback, c.CallbackAllowlist)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			scopes, err := oauth.NewScopeSet(wire.Scopes)
			if err != nil || !slices.Equal(scopes.Values(), c.Provider.Scopes) {
				return s, identityhttp.ErrInvalidInput
			}
			remember, err := session.ResolveRememberPolicy(choice, c.Lifetime)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.request = oauth.SigninStartRequest{TenantID: s.facts.TenantID(), Provider: oauth.ProviderID(wire.Provider), Callback: success, ErrorCallback: failure, Scopes: scopes, SignupDisabled: true, IdempotencyKey: key, FlowID: id, FlowCookie: bearer, Remember: remember, Caller: caller(s.facts.TenantID(), id), Origin: string(c.Origin), Network: s.facts.ClientIP().String(), Device: s.device.DeviceID()}
			return s, s.request.Validate()
		},
		Authenticate: func(r *http.Request, s signinStartState) (signinStartState, error) {
			out, err := c.Rate.AdmitProviderIP(r.Context(), s.facts, "identity.oauth.signin-start", c.Provider.ID)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return s, providerRateFailure{retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed {
				return s, identityhttp.ErrRateUnavailable
			}
			return s, nil
		},
		Admit: func(_ *http.Request, s signinStartState) error {
			if !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s signinStartState) {
			if !s.device.ExpiresAt().After(c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out, err := c.Start.SigninStart(r.Context(), s.request)
			if err != nil {
				reject(w, r, err)
				return
			}
			if r.Context().Err() != nil || !validSigninStartProjection(out, c.Provider, c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			wire, err := json.Marshal(struct {
				RedirectURI   string    `json:"redirectURI"`
				TransactionID string    `json:"transactionID"`
				ExpiresAt     time.Time `json:"expiresAt"`
			}{out.RedirectURI.String(), out.TransactionID, out.ExpiresAt})
			if err != nil || len(wire) > 16384 {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write(wire)
		},
	})
}

// Native state/nonce/PKCE generation remains the provider owner's contract.
// This projection guard only prevents malformed native output from selecting a
// different redirect destination or exporting an unrelated credential field.
func validSigninStartProjection(out oauth.SigninStartResult, profile oauth.ProviderProfile, now time.Time) bool {
	if _, err := identity.ParseCommandID(out.TransactionID); err != nil || now.IsZero() || !out.ExpiresAt.After(now) {
		return false
	}
	u := out.RedirectURI
	endpoint, err := url.Parse(profile.AuthorizationEndpoint)
	if err != nil || u.Scheme != endpoint.Scheme || u.Host != endpoint.Host || u.Path != endpoint.Path || u.EscapedPath() != endpoint.EscapedPath() || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" || u.ForceQuery || len(u.String()) > 16384 {
		return false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) != 9 {
		return false
	}
	for name, values := range query {
		if len(values) != 1 || values[0] == "" {
			return false
		}
		switch name {
		case "response_type", "response_mode", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method":
		default:
			return false
		}
	}
	return query.Get("response_type") == "code" && query.Get("response_mode") == "query" && query.Get("client_id") == profile.ClientID && query.Get("redirect_uri") == profile.RedirectURI && query.Get("scope") == strings.Join(profile.Scopes, " ") && query.Get("code_challenge_method") == "S256"
}

// Format prevents implicit export of retained runtime composition.
func (SigninStartConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.SigninStartConfig(redacted)"))
}

// MarshalJSON rejects implicit runtime export.
func (SigninStartConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText rejects implicit runtime export.
func (SigninStartConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }
