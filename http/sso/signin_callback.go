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

// ParsedSigninCallbackOwner optionally completes with the already parsed
// callback. Callback and request share borrowed custody destroyed when the
// handler returns; neither may be retained. Its error never retries legacy
// completion, and the owner must still repeat all protected current checks.
type ParsedSigninCallbackOwner interface {
	SigninCallbackOwner
	CompleteParsedSSOOIDC(context.Context, SigninCallbackRequest, oauth.QueryCallback) (SigninCallbackResult, error)
}

// SharedCallbackRateContext carries the authenticated original profile; the
// transport does not select it from cookie presence or protocol query fields.
type SharedCallbackRateContext struct {
	SigninCallbackRateContext
	MemberLink bool
}

// MemberLinkCallbackResult acknowledges the original committed link. It has no
// session or token fields. The owner returns it only after commit is known.
type MemberLinkCallbackResult struct {
	CommandID   identity.CommandID
	RedirectURI string
}

// MemberLinkCallbackOwner selects and authenticates the original stored
// profile, and repeats all protected checks on member completion.
type MemberLinkCallbackOwner interface {
	SharedCallbackRateSource(context.Context, SigninCallbackRequest, authentication.BearerCredential) (SharedCallbackRateContext, error)
	CompleteSSOOIDCLink(context.Context, SigninCallbackRequest, authentication.BearerCredential) (MemberLinkCallbackResult, error)
}

// ParsedMemberLinkCallbackOwner optionally completes the admitted stored member
// profile with the already parsed callback. Callback and request share borrowed
// custody destroyed when the handler returns; neither may be retained. Its
// error never retries legacy completion or falls back to sign-in.
type ParsedMemberLinkCallbackOwner interface {
	MemberLinkCallbackOwner
	CompleteParsedSSOOIDCLink(context.Context, SigninCallbackRequest, authentication.BearerCredential, oauth.QueryCallback) (MemberLinkCallbackResult, error)
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
// Provider.ID identifies both the installed provider and the parser profile.
func NewSigninCallbackFeature(c SigninCallbackConfig) (identityhttp.Feature, error) {
	return NewSigninCallbackFeatureForProvider(c.Provider.ID, c)
}

// NewSigninCallbackFeatureForProvider selects the same callback for one exact
// installed provider whose case-sensitive ID differs from the OAuth parser's
// logical ID. It uses providerID for native attribution and provider quotas.
func NewSigninCallbackFeatureForProvider(providerID string, c SigninCallbackConfig) (identityhttp.Feature, error) {
	return newSigninCallbackFeature(providerID, c, nil)
}

// NewSigninCallbackFeatureWithLink selects the same provider callback and
// allows the native owner to dispatch an authenticated stored member profile.
// A member link never falls back to sign-in or writes browser credentials.
func NewSigninCallbackFeatureWithLink(providerID string, c SigninCallbackConfig, link MemberLinkCallbackOwner) (identityhttp.Feature, error) {
	if !configuredOwner(link) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newSigninCallbackFeature(providerID, c, link)
}

func newSigninCallbackFeature(providerID string, c SigninCallbackConfig, link MemberLinkCallbackOwner) (identityhttp.Feature, error) {
	if !validProviderID(providerID) || !configuredOwner(c.Callback) || c.Audience == "" || len(c.CallbackAllowlist) == 0 || len(c.CallbackAllowlist) > 64 ||
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
	if link != nil && authCookie.SameSite != http.SameSiteLaxMode {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	handler, err := newSigninCallbackHandler(c, browser, providerID, link, authCookie.Name)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "sso/oidc", OperationID: signinCallbackOperation, Handler: handler, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 8192})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = signinCallbackWire()
	if link != nil {
		op.Wire = memberSigninCallbackWire()
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "sso/oidc", Operations: []identityhttp.OperationDescriptor{op}})
}

type signinCallbackState struct {
	facts    identityhttp.NetworkFacts
	device   session.BrowserDevice
	request  SigninCallbackRequest
	source   SigninCallbackRateContext
	command  identity.CommandID
	accepted bool
	cookie   authentication.BearerCredential
	link     bool
}

type signinDeliveryKey struct{}
type signinDelivery struct {
	parsed       oauth.QueryCallback
	redirect     string
	cookies      []string
	current      func() bool
	confirmation *signinConfirmationPage
}

// Only the selected unsolicited SAML handler stages this non-session response.
type signinConfirmationPage struct {
	html, cookie string
	current      func() bool
}

func (*signinDelivery) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "ssohttp.signinDelivery(redacted)")
}

func newSigninCallbackHandler(c SigninCallbackConfig, browser signinBrowserPolicy, providerID string, link MemberLinkCallbackOwner, sessionCookie string) (http.Handler, error) {
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
			if link == nil {
				s.facts, s.request.Browser, s.device, err = browser.resolve(r, false)
			} else {
				s.facts, s.request.Browser, s.device, err = browser.resolveDevice(r, false)
				if err == nil {
					s.request.Browser.FlowCookie, err = browser.sessionCookie(r, browser.flowName, identityhttp.HeaderOptional)
				}
				if err == nil {
					s.cookie, err = browser.sessionCookie(r, sessionCookie, identityhttp.HeaderOptional)
				}
			}
			s.request.TenantID, s.request.Input, s.request.ReceivedRedirectURI = s.facts.TenantID(), input, c.Provider.RedirectURI
			s.accepted = accepted
			return s, err
		},
		Authenticate: func(r *http.Request, s signinCallbackState) (signinCallbackState, error) {
			ctx := r.Context()
			if err := admitSigninIP(ctx, c.Browser.Rate, s.facts, signinCallbackOperation, providerID); err != nil {
				return s, err
			}
			if !s.accepted {
				return s, identity.ForbiddenError{}
			}
			var source SigninCallbackRateContext
			var err error
			if link == nil {
				source, err = c.Callback.CallbackRateSource(ctx, s.request)
			} else {
				var shared SharedCallbackRateContext
				shared, err = link.SharedCallbackRateSource(ctx, s.request, s.cookie)
				source, s.link = shared.SigninCallbackRateContext, shared.MemberLink
			}
			if err != nil {
				return s, err
			}
			var flow identity.PreAuthTransactionID
			if s.link {
				if source.FlowID != "" || s.cookie.Token() == "" {
					return s, identity.ForbiddenError{}
				}
			} else {
				flow, err = identity.ParsePreAuthTransactionID(string(source.FlowID))
				if err != nil || s.request.Browser.FlowCookie.Token() == "" {
					return s, identity.ForbiddenError{}
				}
			}
			command, commandErr := identity.ParseCommandID(source.TransactionID)
			if source.ProviderID != providerID || commandErr != nil || !s.device.ExpiresAt().After(c.Browser.Now()) {
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
			delivery := ctx.Value(signinDeliveryKey{}).(*signinDelivery)
			if s.link {
				var out MemberLinkCallbackResult
				var err error
				if parsedOwner, ok := link.(ParsedMemberLinkCallbackOwner); ok {
					out, err = parsedOwner.CompleteParsedSSOOIDCLink(ctx, s.request, s.cookie, delivery.parsed)
				} else {
					out, err = link.CompleteSSOOIDCLink(ctx, s.request, s.cookie)
				}
				if err != nil {
					writeSigninError(w, r, err)
					return
				}
				current := func() bool { return ctx.Err() == nil && s.device.ExpiresAt().After(c.Browser.Now()) }
				if out.CommandID != s.command || !slices.Contains(c.CallbackAllowlist, out.RedirectURI) || !current() {
					writeSigninError(w, r, identityhttp.ErrUnavailable)
					return
				}
				delivery.redirect, delivery.current = out.RedirectURI, current
				w.WriteHeader(http.StatusSeeOther)
				return
			}
			var out SigninCallbackResult
			var err error
			if parsedOwner, ok := c.Callback.(ParsedSigninCallbackOwner); ok {
				out, err = parsedOwner.CompleteParsedSSOOIDC(ctx, s.request, delivery.parsed)
			} else {
				out, err = c.Callback.CompleteSSOOIDC(ctx, s.request)
			}
			if err != nil {
				writeSigninError(w, r, err)
				return
			}
			writeSigninDelivery(w, r, c, signinCallbackOperation, "sso-oidc", out, s.command, s.request.Browser.FlowID, s.device.ExpiresAt())
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
	var page string
	final := func(status int, explicit bool) int {
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
		if status == http.StatusOK && explicit && delivery.confirmation != nil {
			form := delivery.confirmation
			if form.current == nil || !form.current() {
				return http.StatusServiceUnavailable
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Del("Content-Encoding")
			w.Header().Del("Content-Disposition")
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Add("Set-Cookie", form.cookie)
			page = form.html
			return status
		}
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
			final(http.StatusOK, false)
		}
	}()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) {
				next(final(status, true))
				if page != "" {
					body := page
					page = ""
					_, _ = io.WriteString(w, body)
				}
			}
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(p []byte) (int, error) {
				if !committed {
					w.WriteHeader(final(http.StatusOK, false))
				}
				return next(p)
			}
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() {
				if !committed {
					w.WriteHeader(final(http.StatusOK, false))
				}
				next()
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(src io.Reader) (int64, error) {
				if !committed {
					w.WriteHeader(final(http.StatusOK, false))
				}
				return next(src)
			}
		},
	})
	h.pipeline.ServeHTTP(writer, r)
}

func writeSigninDelivery(w http.ResponseWriter, r *http.Request, c SigninCallbackConfig, operation, method string, out SigninCallbackResult, command identity.CommandID, flow identity.PreAuthTransactionID, deliveryExpires time.Time, clearCookies ...string) {
	ctx := r.Context()
	now := c.Browser.Now()
	auth, csrf, err := c.deliveryCookies(operation, method, out, command, flow, now)
	if err != nil || ctx.Err() != nil || !deliveryExpires.After(now) {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	delivery := ctx.Value(signinDeliveryKey{}).(*signinDelivery)
	delivery.redirect, delivery.cookies = out.RedirectURI, append([]string{auth.String(), csrf.String()}, clearCookies...)
	delivery.current = func() bool {
		now := c.Browser.Now()
		spec, err := out.Issuance.Session.Bindings()
		_, lifetimeErr := out.Issuance.Session.Lifetime(now)
		return err == nil && lifetimeErr == nil && ctx.Err() == nil && deliveryExpires.After(now) && spec.Authentication.Proof.ExpiresAt.After(now)
	}
	w.WriteHeader(http.StatusSeeOther)
}

func (c SigninCallbackConfig) deliveryCookies(operation, method string, out SigninCallbackResult, command identity.CommandID, flow identity.PreAuthTransactionID, now time.Time) (http.Cookie, http.Cookie, error) {
	deny := func() (http.Cookie, http.Cookie, error) {
		return http.Cookie{}, http.Cookie{}, identityhttp.ErrUnavailable
	}
	b := out.Completion.Binding
	issued := out.Issuance
	if out.Completion.Validate() != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted || b.CommandID != command || b.TenantID != c.Browser.TenantID ||
		b.OperationID != operation || b.AnonymousFlowID != string(flow) || issued.Replayed || issued.CommandID != command ||
		issued.CommitOutcome != identity.CommitOutcomeCommitted || !slices.Contains(c.CallbackAllowlist, out.RedirectURI) {
		return deny()
	}
	spec, err := issued.Session.Bindings()
	if err != nil || spec.TenantID != b.TenantID || spec.Audience != c.Audience || spec.Authentication.Kind != session.AuthenticationVerified ||
		spec.Authentication.Proof.Method != method || spec.Authentication.Proof.ID != authentication.ProofID(command) {
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
