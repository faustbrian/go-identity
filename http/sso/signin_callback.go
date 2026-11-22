package ssohttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	"github.com/felixge/httpsnoop"
)

const signinCallbackPath = "/sso/oidc/callback"
const signinCallbackOperation = "identity.sso.oidc-callback"

// SigninCallbackRequest carries scoped transport facts and borrowed code
// custody. Input is destroyed when the bounded request returns. FlowID is
// empty during source lookup and populated only from authenticated native state.
type SigninCallbackRequest struct {
	TenantID            identity.TenantID
	Input               identity.OAuthCallbackInput
	Browser             SigninBrowser
	ReceivedRedirectURI string
}

func (SigninCallbackRequest) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "ssohttp.SigninCallbackRequest(redacted)")
}
func (SigninCallbackRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SigninCallbackRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SigninCallbackRateContext identifies the original native callback and browser
// flow. Lifetime is the immutable initial duration, never an updated expiry.
type SigninCallbackRateContext struct {
	ProviderID    string
	FlowID        identity.PreAuthTransactionID
	TransactionID string
	Lifetime      time.Duration
}

// SigninCallbackResult carries original durable acknowledgement and fresh
// issuance custody, not a provider token. Historical outcomes must omit it.
type SigninCallbackResult struct {
	Completion  identity.CommandResult
	Issuance    session.IssueResult
	CSRF        session.CSRFToken
	RedirectURI string
}

func (SigninCallbackResult) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "ssohttp.SigninCallbackResult(redacted)")
}
func (SigninCallbackResult) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (SigninCallbackResult) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// SigninCallbackOwner resolves authenticated original rate attribution and
// repeats all protected current checks when completing. Neither transport nor
// attribution reserves state, selects another provider or exchanges a code.
type SigninCallbackOwner interface {
	CallbackRateSource(context.Context, SigninCallbackRequest) (SigninCallbackRateContext, error)
	CompleteSSOOIDC(context.Context, SigninCallbackRequest) (SigninCallbackResult, error)
}

// SigninCallbackConfig selects one exact installed static provider. Query issuer
// and callback URL are from Provider, not inbound tenant/issuer selectors.
// Cookies, Audience and allowlist must match the native composition.
type SigninCallbackConfig struct {
	Browser           SigninBrowserConfig
	Provider          oauth.ProviderProfile
	CallbackAllowlist []string
	Audience          string
	Cookie            session.CookiePolicy
	CSRFCookie        session.CSRFCookiePolicy
	Callback          SigninCallbackOwner
}

// NewSigninCallbackFeature selects the fixed query callback, with no start,
// discovery, signup, linking, browser error redirects or form-post support.
func NewSigninCallbackFeature(c SigninCallbackConfig) (identityhttp.Feature, error) {
	if !configuredOwner(c.Callback) || c.Audience == "" || len(c.CallbackAllowlist) == 0 || len(c.CallbackAllowlist) > 64 ||
		c.Provider.RedirectURI != string(c.Browser.Origin)+signinCallbackPath || c.Provider.ValidateQueryCallback() != nil || c.Provider.MaxCodeBytes > 4096 || c.Provider.GoogleAccounts {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	c.CallbackAllowlist = slices.Clone(c.CallbackAllowlist)
	c.Provider.Scopes, c.Provider.Algorithms = slices.Clone(c.Provider.Scopes), slices.Clone(c.Provider.Algorithms)
	for _, callback := range c.CallbackAllowlist {
		u, err := signinHTTPSURL(callback)
		if err != nil || u.Scheme+"://"+u.Host != string(c.Browser.Origin) {
			return identityhttp.Feature{}, identityhttp.ErrInvalidInput
		}
	}
	browser, err := newSigninBrowserPolicy(c.Browser)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	authCookie, authErr := c.Cookie.DeletionAttributes()
	csrfCookie, csrfErr := c.CSRFCookie.DeletionAttributes()
	if authErr != nil || csrfErr != nil || authCookie.Name == csrfCookie.Name || authCookie.Name == browser.flowName || authCookie.Name == browser.deviceName || csrfCookie.Name == browser.flowName || csrfCookie.Name == browser.deviceName {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	handler, err := newSigninCallbackHandler(c, browser)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "sso/oidc", OperationID: signinCallbackOperation, Handler: handler, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 8192})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = signinCallbackWire()
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "sso/oidc", Operations: []identityhttp.OperationDescriptor{op}})
}

type signinCallbackState struct {
	facts    identityhttp.NetworkFacts
	device   session.BrowserDevice
	request  SigninCallbackRequest
	source   SigninCallbackRateContext
	command  identity.CommandID
	accepted bool
}

type signinDeliveryKey struct{}
type signinDelivery struct {
	parsed   oauth.QueryCallback
	redirect string
	cookies  [2]string
	current  func() bool
}

func (*signinDelivery) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "ssohttp.signinDelivery(redacted)")
}

func newSigninCallbackHandler(c SigninCallbackConfig, browser signinBrowserPolicy) (http.Handler, error) {
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[signinCallbackState]{
		MaximumDuration: c.Browser.MaximumDuration, Reject: writeSigninError,
		Decode: func(r *http.Request) (s signinCallbackState, err error) {
			if r.Method != http.MethodGet || r.URL.Path != signinCallbackPath || r.URL.EscapedPath() != signinCallbackPath || r.URL.ForceQuery || r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody || len(r.Trailer) != 0 || headerPresent(r.Header, "Authorization") || headerPresent(r.Header, "X-CSRF-Token") {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := browser.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			parsed, err := oauth.ParseQueryCallback(r.Context(), r.URL.RawQuery, c.Provider)
			if err != nil {
				if r.Context().Err() == nil {
					err = identityhttp.ErrInvalidInput
				}
				return s, err
			}
			r.Context().Value(signinDeliveryKey{}).(*signinDelivery).parsed = parsed
			input, accepted := parsed.Input()
			s.facts, s.request.Browser, s.device, err = browser.resolve(r, false)
			s.request.TenantID, s.request.Input, s.request.ReceivedRedirectURI = s.facts.TenantID(), input, c.Provider.RedirectURI
			s.accepted = accepted
			return s, err
		},
		Authenticate: func(r *http.Request, s signinCallbackState) (signinCallbackState, error) {
			ctx := r.Context()
			if err := admitSigninIP(ctx, c.Browser.Rate, s.facts, signinCallbackOperation, string(c.Provider.ID)); err != nil {
				return s, err
			}
			if !s.accepted {
				return s, identity.ForbiddenError{}
			}
			source, err := c.Callback.CallbackRateSource(ctx, s.request)
			if err != nil {
				return s, err
			}
			flow, flowErr := identity.ParsePreAuthTransactionID(string(source.FlowID))
			command, commandErr := identity.ParseCommandID(source.TransactionID)
			if source.ProviderID != string(c.Provider.ID) || flowErr != nil || commandErr != nil || !s.device.ExpiresAt().After(c.Browser.Now()) {
				return s, identity.ForbiddenError{}
			}
			s.source, s.command, s.request.Browser.FlowID = source, command, flow
			return s, nil
		},
		Admit: func(r *http.Request, s signinCallbackState) error {
			decision, err := c.Browser.Rate.AdmitProviderTransaction(r.Context(), s.facts, signinCallbackOperation, s.source.ProviderID, s.source.TransactionID, s.source.Lifetime)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return discoveryRateDenial{retry: decision.RetryAfter}
			}
			if err != nil || !decision.Allowed || !s.device.ExpiresAt().After(c.Browser.Now()) {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s signinCallbackState) {
			ctx := r.Context()
			out, err := c.Callback.CompleteSSOOIDC(ctx, s.request)
			if err != nil {
				writeSigninError(w, r, err)
				return
			}
			now := c.Browser.Now()
			auth, csrf, err := c.deliveryCookies(out, s.command, s.request.Browser.FlowID, now)
			if err != nil || ctx.Err() != nil || !s.device.ExpiresAt().After(now) {
				writeSigninError(w, r, identityhttp.ErrUnavailable)
				return
			}
			delivery := r.Context().Value(signinDeliveryKey{}).(*signinDelivery)
			delivery.redirect, delivery.cookies = out.RedirectURI, [2]string{auth.String(), csrf.String()}
			delivery.current = func() bool {
				now := c.Browser.Now()
				spec, err := out.Issuance.Session.Bindings()
				_, lifetimeErr := out.Issuance.Session.Lifetime(now)
				return err == nil && lifetimeErr == nil && ctx.Err() == nil && s.device.ExpiresAt().After(now) && spec.Authentication.Proof.ExpiresAt.After(now)
			}
			w.WriteHeader(http.StatusSeeOther)
		},
	})
	if err != nil {
		return nil, err
	}
	return &signinCallbackHandler{pipeline}, nil
}

type signinCallbackHandler struct{ pipeline http.Handler }

func (h *signinCallbackHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	pipeline, err := identityhttp.WithOperationMiddleware(h.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &signinCallbackHandler{pipeline}, nil
}

func (h *signinCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	delivery := &signinDelivery{}
	defer func() { delivery.parsed.Destroy() }()
	if r != nil {
		r = r.WithContext(context.WithValue(r.Context(), signinDeliveryKey{}, delivery))
	}
	// Scope cookies and redirects to the actual fresh write, not to mutable
	// middleware headers or a quoted/native response value.
	committed := false
	final := func(status int) int {
		if committed {
			return status
		}
		clearSigninHeaders(w)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if status < 200 {
			return status
		}
		committed = true
		if status != http.StatusSeeOther {
			return status
		}
		if delivery.current == nil || !delivery.current() {
			return http.StatusServiceUnavailable
		}
		w.Header().Set("Location", delivery.redirect)
		for _, wire := range delivery.cookies {
			w.Header().Add("Set-Cookie", wire)
		}
		return status
	}
	defer func() {
		if !committed {
			// net/http may send an implicit 200 when middleware returns without writing.
			final(http.StatusOK)
		}
	}()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) { next(final(status)) }
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(p []byte) (int, error) {
				if !committed {
					w.WriteHeader(final(http.StatusOK))
				}
				return next(p)
			}
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() {
				if !committed {
					w.WriteHeader(final(http.StatusOK))
				}
				next()
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(src io.Reader) (int64, error) {
				if !committed {
					w.WriteHeader(final(http.StatusOK))
				}
				return next(src)
			}
		},
	})
	h.pipeline.ServeHTTP(writer, r)
}

func (c SigninCallbackConfig) deliveryCookies(out SigninCallbackResult, command identity.CommandID, flow identity.PreAuthTransactionID, now time.Time) (http.Cookie, http.Cookie, error) {
	deny := func() (http.Cookie, http.Cookie, error) {
		return http.Cookie{}, http.Cookie{}, identityhttp.ErrUnavailable
	}
	b := out.Completion.Binding
	issued := out.Issuance
	if out.Completion.Validate() != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted || b.CommandID != command || b.TenantID != c.Browser.TenantID ||
		b.OperationID != signinCallbackOperation || b.AnonymousFlowID != string(flow) || issued.Replayed || issued.CommandID != command ||
		issued.CommitOutcome != identity.CommitOutcomeCommitted || !slices.Contains(c.CallbackAllowlist, out.RedirectURI) {
		return deny()
	}
	spec, err := issued.Session.Bindings()
	if err != nil || spec.TenantID != b.TenantID || spec.Audience != c.Audience || spec.Authentication.Kind != session.AuthenticationVerified ||
		spec.Authentication.Proof.Method != "sso-oidc" || spec.Authentication.Proof.ID != authentication.ProofID(command) {
		return deny()
	}
	if spec.Authentication.Proof.Validate(authentication.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: c.Audience, Now: now}) != nil {
		return deny()
	}
	if _, err := issued.Session.Lifetime(now); err != nil {
		return deny()
	}
	csrfState, err := issued.Session.CSRFState().Bindings()
	if err != nil || csrfState.Binding != (session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}) {
		return deny()
	}
	expires := spec.IssuedAt.Add(spec.Remember.AbsoluteTTL())
	auth, err := c.Cookie.Attributes(spec.Remember, now, expires)
	if err != nil || issued.Cookie.Name != auth.Name || issued.Cookie.Path != auth.Path || issued.Cookie.Value != "" || issued.Cookie.Domain != "" || !issued.Cookie.HttpOnly || !issued.Cookie.Secure || issued.Cookie.SameSite != auth.SameSite {
		return deny()
	}
	csrf, err := c.CSRFCookie.Attributes(spec.Remember, now, expires)
	if err != nil {
		return deny()
	}
	auth.Value, err = issued.Token.Reveal()
	if err != nil {
		return deny()
	}
	csrf.Value, err = out.CSRF.Reveal()
	if err != nil {
		return deny()
	}
	if auth.Valid() != nil || csrf.Valid() != nil {
		return deny()
	}
	return auth, csrf, nil
}
