// Package oauthhttp provides opt-in query/S256 relying-party transport. It owns
// no state, account, session, provider protocol or transaction engine.
package oauthhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

// CallbackService resolves authenticated original rate attribution separately
// from the protected callback. The native owner must reserve state before
// releasing PKCE/exchanging and commit link effects through its sole root owner.
// Neither method may trust an inbound actor or treat attribution as authority.
type CallbackService interface {
	CallbackRateSource(context.Context, oauth.CallbackRequest) (oauth.CallbackRateContext, error)
	Callback(context.Context, oauth.CallbackRequest) (oauth.CallbackResult, error)
}

// SessionReader is the existing current session boundary used only at link
// initiation. Callback retries must not require a newly valid session epoch.
type SessionReader interface {
	Get(context.Context, session.GetRequest) (session.GetResult, error)
}

// Config selects one explicitly configured OIDC/query provider at its exact
// callback URL, not a provider selected by inbound issuer/host. This finite
// profile supports cookie explicit-self linking, with existing-account signin
// callback only when Signin is explicitly configured. Popup, direct-token,
// hybrid and form-post are not enabled. Compose each chosen operation
// explicitly with NewFeature. All services/clock/limiter are borrowed and must
// be prompt, bounded and concurrency-safe. Construction performs no IO.
type Config struct {
	Network           identityhttp.NetworkConfig
	Provider          oauth.ProviderProfile
	Start             oauth.LinkStarter
	Callback          CallbackService
	Sessions          SessionReader
	Rate              *identityhttp.AuthRateLimiter
	Cookie            session.CookiePolicy
	Origin            identityhttp.Origin
	CallbackAllowlist []string
	PolicyRevision    authorization.Revision
	Now               func() time.Time
	MaximumDuration   time.Duration
	// Signin explicitly adds existing-account native signin to the shared
	// callback URL. Nil preserves the original linking-only callback unchanged.
	Signin *SigninCallbackConfig
}

// FeatureConfig selects operations independently; nil advertises no operation.
// Empty selection is invalid. Compose selected operations with the same rate
// owner. SigninStart does not implicitly enable a callback or account linking.
type FeatureConfig struct {
	LinkStart, Callback *Config
	SigninStart         *SigninStartConfig
}

// NewFeature contributes only actual selected handlers and their wire contracts.
func NewFeature(c FeatureConfig) (identityhttp.Feature, error) {
	if c.LinkStart == nil && c.Callback == nil && c.SigninStart == nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	var operations []identityhttp.OperationDescriptor
	for _, selected := range []struct {
		config   *Config
		callback bool
	}{{c.LinkStart, false}, {c.Callback, true}} {
		if selected.config == nil {
			continue
		}
		handler, err := newHandler(*selected.config, selected.callback)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		action := "identity.account.link-start"
		csrf := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
		if selected.callback {
			action = "identity.oauth.callback"
			csrf = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/oauth", OperationID: action, Handler: handler, CSRF: csrf, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = wireOperation(*selected.config, selected.callback)
		operations = append(operations, op)
	}
	if c.SigninStart != nil {
		handler, err := NewSigninStartHandler(*c.SigninStart)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/oauth", OperationID: "identity.oauth.signin-start", Handler: handler, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = wireSigninStart(*c.SigninStart)
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/oauth", Operations: operations})
}

// NewCallbackHandler acquires exact parsed state and the original browser; the
// native owner resolves its actor. All parsed custody is destroyed on return,
// including parsing/admission failures and middleware short circuits.
func NewCallbackHandler(c Config) (http.Handler, error) { return newHandler(c, true) }

// NewLinkStartHandler selects the cookie/fresh-self keyed initiation operation.
func NewLinkStartHandler(c Config) (http.Handler, error) { return newHandler(c, false) }

type callbackKey struct{}
type callbackOwner struct{ parsed oauth.Callback }
type requestState struct {
	facts    identityhttp.NetworkFacts
	start    oauth.LinkStartRequest
	callback oauth.CallbackRequest
	source   oauth.CallbackRateContext
}
type wireStart struct {
	Provider       string   `json:"provider"`
	Callback       string   `json:"callback"`
	ErrorCallback  string   `json:"errorCallback"`
	Scopes         []string `json:"scopes"`
	SignupDisabled bool     `json:"signupDisabled"`
}

func missing(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	return (r.Kind() == reflect.Pointer || r.Kind() == reflect.Func || r.Kind() == reflect.Interface) && r.IsNil()
}

func newHandler(c Config, callback bool) (http.Handler, error) {
	if callback && c.Signin != nil {
		return newSigninCallbackHandler(c)
	}
	if !c.Rate.Configured() || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || callback && missing(c.Callback) || !callback && (missing(c.Start) || missing(c.Sessions) || c.PolicyRevision == 0 || c.Now == nil || len(c.CallbackAllowlist) == 0) {
		return nil, identityhttp.ErrInvalidInput
	}
	c.Provider.Scopes, c.Provider.Algorithms = slices.Clone(c.Provider.Scopes), slices.Clone(c.Provider.Algorithms)
	c.CallbackAllowlist = slices.Clone(c.CallbackAllowlist)
	cookie, err := c.Cookie.DeletionAttributes()
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
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origin, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	redirect, err := url.Parse(c.Provider.RedirectURI)
	if err != nil || redirect.String() != string(c.Origin)+"/v1/oauth/callback" || c.Provider.ID == "" {
		return nil, identityhttp.ErrInvalidInput
	}
	if err := c.Provider.ValidateQueryCallback(); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	path, action := "/v1/account/link-start", "identity.account.link-start"
	if callback {
		path, action = "/v1/oauth/callback", "identity.oauth.callback"
	}
	reject := func(w http.ResponseWriter, _ *http.Request, cause error) {
		status, code := http.StatusServiceUnavailable, "unavailable"
		var invalid identity.InvalidInputError
		var forbidden identity.ForbiddenError
		var conflict identity.ConflictError
		var oauthError *oauth.Error
		switch {
		case errors.As(cause, &invalid), errors.Is(cause, identityhttp.ErrInvalidInput):
			status, code = 400, "invalid_request"
		case errors.As(cause, &forbidden):
			status, code = 403, "denied"
		case errors.As(cause, &conflict):
			status, code = 409, "conflict"
		case errors.Is(cause, identityhttp.ErrRateLimited):
			status, code = 429, "rate_limited"
		case errors.As(cause, &oauthError):
			if oauthError.Kind() == oauth.InvalidInput {
				status, code = 400, "invalid_request"
			} else if oauthError.Kind() == oauth.InvalidProof || oauthError.Kind() == oauth.Refused {
				status, code = 403, "denied"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{code})
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[requestState]{MaximumDuration: c.MaximumDuration, Reject: reject,
		Decode: func(r *http.Request) (s requestState, err error) {
			if r.URL.Path != path || r.URL.EscapedPath() != path || r.URL.ForceQuery || len(r.Trailer) != 0 || callback && r.Method != http.MethodGet || !callback && r.Method != http.MethodPost || callback && r.ContentLength != 0 || !callback && r.URL.RawQuery != "" {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant || s.facts.Scheme() != "https" || s.facts.Origin() != string(c.Origin) {
				return s, identity.ForbiddenError{}
			}
			bearer, present, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(bearer.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			keyPolicy := identityhttp.HeaderRequired
			if callback {
				keyPolicy = identityhttp.HeaderForbidden
			}
			key, _, err := decoder.IdempotencyKey(r, keyPolicy)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if callback {
				// Top-level provider GET navigation normally has no Origin. Any
				// present origin is still checked, never used to choose authority.
				if callbackOriginPresent(r) {
					if _, err := origin.CheckBound(r, c.Origin); err != nil {
						return s, identity.ForbiddenError{}
					}
				}
				parsed, err := oauth.ParseQueryCallback(r.Context(), r.URL.RawQuery, c.Provider)
				if err != nil {
					return s, err
				}
				r.Context().Value(callbackKey{}).(*callbackOwner).parsed = parsed
				s.callback = oauth.CallbackRequest{Callback: parsed, TenantID: s.facts.TenantID(), Session: bearer, Origin: string(c.Origin), Network: s.facts.ClientIP().String()}
				return s, s.callback.Validate()
			}
			csrfToken, _, err := identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, identity.ForbiddenError{}
			}
			body, err := identityhttp.DecodeJSON[wireStart](decoder, r)
			if err != nil || body.Provider != c.Provider.ID {
				return s, identityhttp.ErrInvalidInput
			}
			success, err := oauth.NewValidatedCallbackURL(body.Callback, c.CallbackAllowlist)
			if err != nil {
				return s, err
			}
			failure, err := oauth.NewValidatedCallbackURL(body.ErrorCallback, c.CallbackAllowlist)
			if err != nil {
				return s, err
			}
			scopes, err := oauth.NewScopeSet(body.Scopes)
			if err != nil || !slices.Equal(scopes.Values(), c.Provider.Scopes) {
				return s, identityhttp.ErrInvalidInput
			}
			s.start = oauth.LinkStartRequest{TenantID: s.facts.TenantID(), Provider: oauth.ProviderID(body.Provider), Callback: success, ErrorCallback: failure, Scopes: scopes, SignupDisabled: body.SignupDisabled, IdempotencyKey: key, Session: bearer, CSRFToken: csrfToken, Origin: string(c.Origin), Network: s.facts.ClientIP().String()}
			return s, nil
		},
		Authenticate: func(r *http.Request, s requestState) (requestState, error) {
			out, err := c.Rate.AdmitProviderIP(r.Context(), s.facts, action, c.Provider.ID)
			if err != nil || !out.Allowed {
				if err == nil {
					err = identityhttp.ErrRateUnavailable
				}
				return s, err
			}
			if callback {
				s.source, err = c.Callback.CallbackRateSource(r.Context(), s.callback)
				return s, err
			}
			token, err := session.ParseToken(s.start.Session.Token())
			if err != nil {
				return s, err
			}
			credential, err := session.NewCredential(session.CredentialCookie, token)
			if err != nil {
				return s, err
			}
			current, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.start.TenantID, Credential: credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !current.Authenticated || current.ValidateAt(c.Now()) != nil {
				return s, identity.ForbiddenError{}
			}
			original, err := current.Session.Bindings()
			if err != nil || original.TenantID != s.start.TenantID {
				return s, identity.ForbiddenError{}
			}
			s.start.Caller = authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(s.start.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(original.UserID)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(original.UserID)}, Environment: authorization.Environment{Time: c.Now()}}}
			return s, s.start.Validate()
		},
		Admit: func(r *http.Request, s requestState) error {
			if !callback {
				return s.start.Validate()
			}
			if s.source.ProviderID != c.Provider.ID {
				return identity.ForbiddenError{}
			}
			out, err := c.Rate.AdmitProviderTransaction(r.Context(), s.facts, action, s.source.ProviderID, s.source.TransactionID, s.source.Lifetime)
			if err == nil && !out.Allowed {
				return identityhttp.ErrRateUnavailable
			}
			return err
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s requestState) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if callback {
				out, err := c.Callback.Callback(r.Context(), s.callback)
				if err != nil {
					reject(w, r, err)
					return
				}
				redirect, ok := out.Outcome.RedirectURI()
				if !ok {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
				return
			}
			out, err := c.Start.LinkStart(r.Context(), s.start)
			if err != nil {
				reject(w, r, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				RedirectURI   string    `json:"redirectURI"`
				TransactionID string    `json:"transactionID"`
				ExpiresAt     time.Time `json:"expiresAt"`
			}{out.RedirectURI.String(), out.TransactionID, out.ExpiresAt})
		},
	})
	if err != nil {
		return nil, err
	}
	return &custodyHandler{next: pipeline}, nil
}

// Custody must enclose the real pipeline, including any trusted middleware
// short circuit; binding cannot replace cleanup with an opaque outer wrapper.
type custodyHandler struct{ next http.Handler }

func (h *custodyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		h.next.ServeHTTP(w, r)
		return
	}
	owner := &callbackOwner{}
	defer func() { owner.parsed.Destroy() }()
	h.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callbackKey{}, owner)))
}

func (h *custodyHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.next == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	next, err := identityhttp.WithOperationMiddleware(h.next, m)
	if err != nil {
		return nil, err
	}
	return &custodyHandler{next: next}, nil
}

// Format excludes borrowed resources, token custody and provider configuration.
func (Config) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("oauthhttp.Config(redacted)")) }
func (Config) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }
func (Config) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }
