package oauthhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	"github.com/felixge/httpsnoop"
)

// CallbackOperationSource resolves routing metadata from original native state,
// never from ambient cookie presence or a request-selected mode. It grants no
// browser or provider authority. The selected callback must repeat its own
// original-browser/current-authority admission before any protected effect.
type CallbackOperationSource interface {
	CallbackOperation(context.Context, identity.TenantID, oauth.Callback) (string, error)
}

// SigninCallbackSource authenticates original native signin attribution without
// reservation or exchange. Complete repeats its own original fences afterward.
type SigninCallbackSource interface {
	SigninCallbackRateSource(context.Context, oauth.SigninCallbackRequest) (oauth.CallbackRateContext, error)
}

// SigninCallbackService is the bounded native existing-account completion owner.
// Only a new exact commit may return bearer/CSRF custody; historical outcomes
// must not recreate it. The transport owns destroying the borrowed callback.
type SigninCallbackService interface {
	Callback(context.Context, oauth.SigninCallbackRequest) (oauth.SigninCallbackResult, error)
}

// SigninCallbackConfig explicitly selects native signin at the shared callback.
// Operations, Source and Complete are borrowed concurrency-safe native owners.
// FlowCookie/Device match original issuance and use Lax for provider navigation.
// CSRFCookie is distinct from every credential/correlation cookie and delivers
// only the newly committed synchronizer token to same-origin browser code.
// Config's callbacks must therefore be same-origin for this browser profile.
// No account, provider, session, replay or transaction engine is supplied here.
type SigninCallbackConfig struct {
	Operations CallbackOperationSource
	Source     SigninCallbackSource
	Complete   SigninCallbackService
	FlowCookie session.CookiePolicy
	Device     session.BrowserDeviceConfig
	CSRFCookie session.CSRFCookiePolicy
	Audience   string
}

// Format redacts borrowed owners and browser-device custody.
func (SigninCallbackConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.SigninCallbackConfig(redacted)"))
}

// MarshalJSON rejects implicit runtime composition export.
func (SigninCallbackConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit runtime composition export.
func (SigninCallbackConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

type sharedCallbackState struct {
	facts     identityhttp.NetworkFacts
	parsed    oauth.Callback
	operation string
	link      oauth.CallbackRequest
	signin    oauth.SigninCallbackRequest
	source    oauth.CallbackRateContext
	device    session.BrowserDevice
}

func (sharedCallbackState) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.sharedCallbackState(redacted)"))
}

func newSigninCallbackHandler(c Config) (http.Handler, error) {
	selected := *c.Signin
	c.Signin = &selected
	if missing(selected.Operations) || missing(selected.Source) || missing(selected.Complete) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || selected.Audience == "" {
		return nil, identityhttp.ErrInvalidInput
	}
	c.Provider.Scopes, c.Provider.Algorithms = slices.Clone(c.Provider.Scopes), slices.Clone(c.Provider.Algorithms)
	c.CallbackAllowlist = slices.Clone(c.CallbackAllowlist)
	if c.Provider.ValidateQueryCallback() != nil || c.Provider.RedirectURI != string(c.Origin)+"/v1/oauth/callback" || len(c.CallbackAllowlist) == 0 {
		return nil, identityhttp.ErrInvalidInput
	}
	for _, callback := range c.CallbackAllowlist {
		validated, err := oauth.NewValidatedCallbackURL(callback, c.CallbackAllowlist)
		if err != nil {
			return nil, identityhttp.ErrInvalidInput
		}
		u := validated.URL()
		if u.Scheme+"://"+u.Host != string(c.Origin) {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	authentication, err := c.Cookie.DeletionAttributes()
	if err != nil || !missing(c.Callback) && authentication.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	flow, err := selected.FlowCookie.DeletionAttributes()
	if err != nil || flow.Name != "__Host-identity_flow" || flow.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	deviceCookie, err := selected.Device.Cookie.DeletionAttributes()
	if err != nil || deviceCookie.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	csrf, err := selected.CSRFCookie.DeletionAttributes()
	if err != nil || csrf.Name == authentication.Name || csrf.Name == flow.Name || csrf.Name == deviceCookie.Name || authentication.Name == flow.Name || authentication.Name == deviceCookie.Name {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(selected.Device)
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
			status, code = 400, "invalid_request"
		case errors.As(cause, &forbidden):
			status, code = 403, "denied"
		case errors.As(cause, &conflict):
			status, code = 409, "conflict"
		case errors.Is(cause, identityhttp.ErrRateLimited):
			status, code = 429, "rate_limited"
		case errors.As(cause, &native):
			if native.Kind() == oauth.InvalidInput {
				status, code = 400, "invalid_request"
			} else if native.Kind() == oauth.InvalidProof || native.Kind() == oauth.Refused {
				status, code = 403, "denied"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{code})
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[sharedCallbackState]{MaximumDuration: c.MaximumDuration, Reject: reject,
		Decode: func(r *http.Request) (s sharedCallbackState, err error) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/oauth/callback" || r.URL.EscapedPath() != r.URL.Path || r.URL.ForceQuery || r.ContentLength != 0 || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant || s.facts.Scheme() != "https" || s.facts.Origin() != string(c.Origin) {
				return s, identity.ForbiddenError{}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if callbackOriginPresent(r) {
				if _, err := origins.CheckBound(r, c.Origin); err != nil {
					return s, identity.ForbiddenError{}
				}
			}
			s.parsed, err = oauth.ParseQueryCallback(r.Context(), r.URL.RawQuery, c.Provider)
			r.Context().Value(sharedCallbackKey{}).(*sharedCallbackDelivery).parsed = s.parsed
			return s, err
		},
		Authenticate: func(r *http.Request, s sharedCallbackState) (sharedCallbackState, error) {
			admission, err := c.Rate.AdmitProviderIP(r.Context(), s.facts, "identity.oauth.callback", c.Provider.ID)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return s, providerRateFailure{retry: admission.RetryAfter}
			}
			if err != nil {
				return s, err
			}
			if !admission.Allowed {
				return s, identityhttp.ErrRateUnavailable
			}
			s.operation, err = selected.Operations.CallbackOperation(r.Context(), s.facts.TenantID(), s.parsed)
			if err != nil {
				return s, err
			}
			switch s.operation {
			case "identity.account.link-start":
				if missing(c.Callback) {
					return s, identity.ForbiddenError{}
				}
				bearer, _, err := decoder.CookieBearer(r, authentication.Name, identityhttp.HeaderRequired)
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
				if _, err := session.ParseToken(bearer.Token()); err != nil {
					return s, identityhttp.ErrInvalidInput
				}
				s.link = oauth.CallbackRequest{Callback: s.parsed, TenantID: s.facts.TenantID(), Session: bearer, Origin: string(c.Origin), Network: s.facts.ClientIP().String()}
				if err := s.link.Validate(); err != nil {
					return s, err
				}
				s.source, err = c.Callback.CallbackRateSource(r.Context(), s.link)
				return s, err
			case "identity.oauth.signin-start":
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
					return s, identity.ForbiddenError{}
				}
				s.signin = oauth.SigninCallbackRequest{Callback: s.parsed, TenantID: s.facts.TenantID(), FlowCookie: bearer, Origin: string(c.Origin), Network: s.facts.ClientIP().String(), Device: s.device.DeviceID()}
				if err := s.signin.Validate(); err != nil {
					return s, err
				}
				s.source, err = selected.Source.SigninCallbackRateSource(r.Context(), s.signin)
				return s, err
			default:
				return s, identity.ForbiddenError{}
			}
		},
		Admit: func(r *http.Request, s sharedCallbackState) error {
			if s.source.ProviderID != c.Provider.ID {
				return identity.ForbiddenError{}
			}
			admission, err := c.Rate.AdmitProviderTransaction(r.Context(), s.facts, "identity.oauth.callback", s.source.ProviderID, s.source.TransactionID, s.source.Lifetime)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return providerRateFailure{retry: admission.RetryAfter}
			}
			if err == nil && !admission.Allowed {
				return identityhttp.ErrRateUnavailable
			}
			return err
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s sharedCallbackState) {
			// A middleware response has already ended transport admission. Do not
			// create a session whose original delivery can no longer be emitted.
			if r.Context().Value(sharedCallbackKey{}).(*sharedCallbackDelivery).responseCommitted {
				return
			}
			var outcome oauth.IdentityDeliveryResult
			var cookies []string
			var current func() bool
			if s.operation == "identity.account.link-start" {
				out, err := c.Callback.Callback(r.Context(), s.link)
				if err != nil {
					reject(w, r, err)
					return
				}
				outcome = out.Outcome
			} else {
				if !s.device.ExpiresAt().After(c.Now()) {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				out, err := selected.Complete.Callback(r.Context(), s.signin)
				if err != nil {
					reject(w, r, err)
					return
				}
				outcome = out.Outcome
				cookies, current, err = signinCallbackDelivery(c, selected, s.signin.TenantID, out)
				if err != nil {
					reject(w, r, err)
					return
				}
			}
			redirect, ok := outcome.RedirectURI()
			if _, err := oauth.NewValidatedCallbackURL(redirect.String(), c.CallbackAllowlist); err != nil || !ok || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			delivery := r.Context().Value(sharedCallbackKey{}).(*sharedCallbackDelivery)
			delivery.cookies, delivery.redirect, delivery.ctx, delivery.current = cookies, redirect.String(), r.Context(), current
			http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
		},
	})
	if err != nil {
		return nil, err
	}
	return &sharedCallbackHandler{pipeline: pipeline}, nil
}

func signinCallbackDelivery(c Config, selected SigninCallbackConfig, tenant identity.TenantID, out oauth.SigninCallbackResult) ([]string, func() bool, error) {
	deny := func() ([]string, func() bool, error) { return nil, nil, identityhttp.ErrUnavailable }
	if out.Outcome.Denied() || out.Session.Replayed {
		if out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
			return deny()
		}
		return nil, nil, nil
	}
	spec, err := out.Session.Session.Bindings()
	identityResult, ok := out.Outcome.Identity()
	if err != nil || !ok || out.Session.CommitOutcome != identity.CommitOutcomeCommitted || spec.TenantID != tenant || spec.UserID != identityResult.UserID || identityResult.ProviderID != c.Provider.ID || spec.Audience != selected.Audience || spec.Remember != identityResult.RememberPolicy || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "oauth" || spec.Authentication.Proof.ID != auth.ProofID(out.Session.CommandID) {
		return deny()
	}
	current := func() bool {
		now := c.Now()
		_, lifetimeErr := out.Session.Session.Lifetime(now)
		proofErr := spec.Authentication.Proof.Validate(auth.ProofUse{Tenant: string(tenant), Subject: string(spec.UserID), Purpose: "session-issue", Audience: selected.Audience, Now: now})
		return lifetimeErr == nil && proofErr == nil
	}
	if !current() {
		return deny()
	}
	csrfState, err := out.Session.Session.CSRFState().Bindings()
	if err != nil || csrfState.Binding != (session.CSRFBinding{TenantID: tenant, SessionID: spec.SessionID, SessionVersion: spec.Version}) {
		return deny()
	}
	now := c.Now()
	expires := spec.IssuedAt.Add(spec.Remember.AbsoluteTTL())
	authentication, err := c.Cookie.Attributes(spec.Remember, now, expires)
	issued := out.Session.Cookie
	if err != nil || issued.Value != "" || issued.Name != authentication.Name || issued.Path != authentication.Path || issued.Domain != "" || !issued.Secure || !issued.HttpOnly || issued.SameSite != authentication.SameSite || issued.Partitioned || issued.Quoted || issued.RawExpires != "" || (authentication.MaxAge == 0 && (issued.MaxAge != 0 || !issued.Expires.IsZero())) || (authentication.MaxAge > 0 && (issued.MaxAge <= 0 || issued.Expires.IsZero() || issued.Expires.After(expires))) {
		return deny()
	}
	csrf, err := selected.CSRFCookie.Attributes(spec.Remember, now, expires)
	if err != nil {
		return deny()
	}
	csrf.Value, err = out.CSRFToken.Reveal()
	if err != nil {
		return deny()
	}
	authentication.Value, err = out.Session.Token.Reveal()
	if err != nil {
		return deny()
	}
	if _, err := session.ParseToken(authentication.Value); err != nil {
		return deny()
	}
	return []string{authentication.String(), csrf.String()}, current, nil
}

type sharedCallbackKey struct{}

func callbackOriginPresent(r *http.Request) bool {
	for name := range r.Header {
		if strings.EqualFold(name, "Origin") {
			return true
		}
	}
	return false
}

type sharedCallbackDelivery struct {
	parsed            oauth.Callback
	cookies           []string
	redirect          string
	ctx               context.Context
	current           func() bool
	responseCommitted bool
}

func (*sharedCallbackDelivery) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.sharedCallbackDelivery(redacted)"))
}

type sharedCallbackHandler struct{ pipeline http.Handler }

func (h *sharedCallbackHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	bound, err := identityhttp.WithOperationMiddleware(h.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &sharedCallbackHandler{pipeline: bound}, nil
}

func (h *sharedCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	delivery := &sharedCallbackDelivery{}
	defer func() { delivery.parsed.Destroy() }()
	if r != nil {
		r = r.WithContext(context.WithValue(r.Context(), sharedCallbackKey{}, delivery))
	}
	refused, rendered, allowDelivery := false, false, false
	protect := func() {
		for name := range w.Header() {
			if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Trailer") || strings.HasPrefix(strings.ToLower(name), strings.ToLower(http.TrailerPrefix)) {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if allowDelivery && !refused && delivery.redirect != "" {
			w.Header().Set("Location", delivery.redirect)
			for _, cookie := range delivery.cookies {
				w.Header().Add("Set-Cookie", cookie)
			}
		}
	}
	commit := func(status int) int {
		if !delivery.responseCommitted && status >= 200 {
			delivery.responseCommitted = true
			if delivery.redirect != "" && (status != http.StatusSeeOther || delivery.ctx == nil || delivery.ctx.Err() != nil || delivery.current != nil && !delivery.current()) {
				refused = true
				status = http.StatusServiceUnavailable
				w.Header().Set("Content-Type", "application/json")
				w.Header().Del("Content-Length")
			}
			allowDelivery = !refused && status == http.StatusSeeOther && delivery.redirect != ""
		}
		protect()
		return status
	}
	protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) { next(commit(status)) }
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(body []byte) (int, error) {
				if !delivery.responseCommitted {
					w.WriteHeader(commit(http.StatusOK))
				}
				protect()
				if refused {
					if !rendered {
						rendered = true
						if _, err := next([]byte("{\"error\":\"unavailable\"}\n")); err != nil {
							return 0, err
						}
					}
					return len(body), nil
				}
				return next(body)
			}
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() {
				if !delivery.responseCommitted {
					w.WriteHeader(commit(http.StatusOK))
				}
				protect()
				next()
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(body io.Reader) (int64, error) {
				if !delivery.responseCommitted {
					w.WriteHeader(commit(http.StatusOK))
				}
				protect()
				if refused {
					if !rendered {
						rendered = true
						_, _ = w.Write([]byte("{\"error\":\"unavailable\"}\n"))
					}
					return 0, identityhttp.ErrUnavailable
				}
				return next(body)
			}
		},
	})
	h.pipeline.ServeHTTP(writer, r)
	protect()
}
