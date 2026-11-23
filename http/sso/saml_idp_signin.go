package ssohttp

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

const samlIDPInitOperation = "identity.sso.saml-idp-init"

// SAMLIDPArrivalRequest contains the exact installed destination and the
// submitted SAML response. It carries no pre-auth or session credential.
type SAMLIDPArrivalRequest struct {
	TenantID                     identity.TenantID
	ProviderID                   string
	ReceivedAssertionConsumerURL string
	SAMLResponse                 string
}

// SAMLIDPArrivalResult lends the two independent values from a fresh native
// commit. Only BrowserCookie becomes a cookie; Synchronizer is a form value.
// Neither value is a normal session credential or safe to log or serialize.
type SAMLIDPArrivalResult struct {
	PendingID                   identity.CommandID
	BrowserCookie, Synchronizer authentication.BearerCredential
	ExpiresAt                   time.Time
}

// SAMLIDPConfirmationRequest carries the original pair received on separate
// browser channels. Origin, provider and tenant come from the exact transport.
type SAMLIDPConfirmationRequest struct {
	TenantID      identity.TenantID
	ProviderID    string
	PendingID     identity.CommandID
	Origin        string
	Browser, Form authentication.BearerCredential
}

func (SAMLIDPArrivalRequest) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLIDPArrivalRequest(redacted)")
}
func (SAMLIDPArrivalRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLIDPArrivalRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLIDPArrivalRequest) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLIDPArrivalRequest(redacted)")
}

func (SAMLIDPArrivalResult) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLIDPArrivalResult(redacted)")
}
func (SAMLIDPArrivalResult) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (SAMLIDPArrivalResult) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (SAMLIDPArrivalResult) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLIDPArrivalResult(redacted)")
}

func (SAMLIDPConfirmationRequest) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLIDPConfirmationRequest(redacted)")
}
func (SAMLIDPConfirmationRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLIDPConfirmationRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLIDPConfirmationRequest) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLIDPConfirmationRequest(redacted)")
}

// SAMLIDPConfirmationRateContext identifies authenticated pending quota scope
// without creating a session or widening the original validity window.
type SAMLIDPConfirmationRateContext struct {
	ProviderID string
	PendingID  identity.CommandID
	Lifetime   time.Duration
}

// SAMLIDPSigninOwner is the selected trusted native owner for the two visibly
// separate steps. Only ConfirmSAMLIDP may settle a session; it reauthenticates
// the original pair after the read-only quota lookup.
type SAMLIDPSigninOwner interface {
	PrepareSAMLIDP(context.Context, SAMLIDPArrivalRequest) (SAMLIDPArrivalResult, error)
	SAMLIDPConfirmationRateSource(context.Context, SAMLIDPConfirmationRequest) (SAMLIDPConfirmationRateContext, error)
	ConfirmSAMLIDP(context.Context, SAMLIDPConfirmationRequest) (SigninCallbackResult, error)
}

// SAMLIDPSigninConfig selects one installed IdP-initiated linked-user route.
// The same exact SP HTTPS URL receives a permitted IdP arrival and a separate
// same-origin form confirmation. SuccessCallback is fixed by the SP, never
// supplied through the assertion, form, query or a redirect hint. RelayState
// is not selected in this profile. Required dependencies are borrowed.
type SAMLIDPSigninConfig struct {
	Network                        identityhttp.NetworkConfig
	TenantID                       identity.TenantID
	Origin, IdentityProviderOrigin identityhttp.Origin
	ProviderID, SuccessCallback    string
	Audience                       string
	Cookie                         session.CookiePolicy
	CSRFCookie                     session.CSRFCookiePolicy
	Rate                           *identityhttp.AuthRateLimiter
	Now                            func() time.Time
	MaximumDuration                time.Duration
	Owner                          SAMLIDPSigninOwner
}

// NavigationPolicy is the required companion selection for NewRouter. The
// first origin is the exact effective SP destination, the second is the IdP
// source. This profile never grants CORS to scripts.
func (c SAMLIDPSigninConfig) NavigationPolicy() identityhttp.CORSRoutePolicy {
	return identityhttp.CORSRoutePolicy{Method: http.MethodPost, Path: samlIDPPath(c.ProviderID),
		Credentials: identityhttp.CORSSAMLIDPPostNavigation, Origins: []identityhttp.Origin{c.Origin, c.IdentityProviderOrigin}}
}

func samlIDPPath(provider string) string { return "/saml2/" + provider + "/idp-init" }

// NewSAMLIDPInitiatedOperation returns one opt-in canonical operation.
// Include it in the selected sso/saml feature and add NavigationPolicy when
// constructing the router. It adds no SP start, metadata, or logout route.
func NewSAMLIDPInitiatedOperation(c SAMLIDPSigninConfig) (identityhttp.OperationDescriptor, error) {
	p, err := newSAMLIDPSigninProfile(c)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	handler, err := p.handler()
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "sso/saml", OperationID: samlIDPInitOperation, Handler: handler, ProviderPathIDs: []string{c.ProviderID},
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 8192,
	})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = samlIDPInitWire()
	return op, nil
}

type samlIDPSigninProfile struct {
	c                 SAMLIDPSigninConfig
	network           *identityhttp.NetworkResolver
	decoder           *identityhttp.RequestDecoder
	sp, idp           *identityhttp.OriginGuard
	path, destination string
	front             session.FrontchannelCookiePolicy
	clearFront        http.Cookie
}

func newSAMLIDPSigninProfile(c SAMLIDPSigninConfig) (samlIDPSigninProfile, error) {
	if c.TenantID == "" || !validProviderID(c.ProviderID) || c.Origin == c.IdentityProviderOrigin || c.Audience == "" ||
		!configuredOwner(c.Owner) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return samlIDPSigninProfile{}, identityhttp.ErrInvalidInput
	}
	path := samlIDPPath(c.ProviderID)
	callback, err := signinHTTPSURL(c.SuccessCallback)
	if err != nil || callback.Scheme+"://"+callback.Host != string(c.Origin) || callback.Path == path {
		return samlIDPSigninProfile{}, identityhttp.ErrInvalidInput
	}
	front, err := session.NewSAMLIDPConfirmationCookiePolicy(path)
	if err != nil {
		return samlIDPSigninProfile{}, identityhttp.ErrInvalidInput
	}
	clearFront, _ := front.DeletionAttributes()
	auth, authErr := c.Cookie.DeletionAttributes()
	csrf, csrfErr := c.CSRFCookie.DeletionAttributes()
	if authErr != nil || csrfErr != nil || auth.Name == csrf.Name || auth.Name == clearFront.Name || csrf.Name == clearFront.Name ||
		auth.SameSite != http.SameSiteLaxMode || csrf.SameSite != http.SameSiteLaxMode {
		return samlIDPSigninProfile{}, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return samlIDPSigninProfile{}, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return samlIDPSigninProfile{}, err
	}
	guard := func(origin identityhttp.Origin) (*identityhttp.OriginGuard, error) {
		return identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	}
	sp, err := guard(c.Origin)
	if err != nil {
		return samlIDPSigninProfile{}, err
	}
	idp, err := guard(c.IdentityProviderOrigin)
	if err != nil {
		return samlIDPSigninProfile{}, err
	}
	return samlIDPSigninProfile{c: c, network: network, decoder: decoder, sp: sp, idp: idp, path: path,
		destination: string(c.Origin) + path, front: front, clearFront: clearFront}, nil
}

type samlIDPState struct {
	facts   identityhttp.NetworkFacts
	arrival *SAMLIDPArrivalRequest
	confirm SAMLIDPConfirmationRequest
	source  SAMLIDPConfirmationRateContext
}

func (samlIDPState) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.samlIDPState(redacted)")
}

func (p samlIDPSigninProfile) decode(r *http.Request) (s samlIDPState, err error) {
	if !exactSAMLRequest(r, http.MethodPost, p.path) || r.URL.RawQuery != "" {
		return s, identityhttp.ErrInvalidInput
	}
	s.facts, err = p.network.Resolve(r)
	if err != nil || s.facts.Realm() != identityhttp.RealmTenant || s.facts.TenantID() != p.c.TenantID || s.facts.Origin() != string(p.c.Origin) {
		return s, identity.ForbiddenError{}
	}
	_, spErr := p.sp.Check(r)
	_, idpErr := p.idp.Check(r)
	if spErr != nil && idpErr != nil {
		return s, identity.ForbiddenError{}
	}
	if _, _, err := p.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return s, identityhttp.ErrInvalidInput
	}
	form, err := p.decoder.Form(r)
	if err != nil {
		return s, samlDecodeError(err)
	}
	if response, present := form["SAMLResponse"]; present {
		if len(form) != 1 || response[0] == "" {
			return s, identityhttp.ErrInvalidInput
		}
		if idpErr != nil {
			return s, identity.ForbiddenError{}
		}
		s.arrival = &SAMLIDPArrivalRequest{TenantID: s.facts.TenantID(), ProviderID: p.c.ProviderID,
			ReceivedAssertionConsumerURL: p.destination, SAMLResponse: response[0]}
		return s, nil
	}
	if spErr != nil {
		return s, identity.ForbiddenError{}
	}
	if len(form) != 2 || !validSAMLRelay(form.Get("confirmation")) {
		return s, identityhttp.ErrInvalidInput
	}
	pending, err := identity.ParseCommandID(form.Get("pending"))
	if err != nil {
		return s, identityhttp.ErrInvalidInput
	}
	browser, _, err := p.decoder.CookieBearer(r, p.clearFront.Name, identityhttp.HeaderRequired)
	if err != nil || !validSAMLRelay(browser.Token()) || browser.Token() == form.Get("confirmation") {
		return s, identity.ForbiddenError{}
	}
	s.confirm = SAMLIDPConfirmationRequest{TenantID: s.facts.TenantID(), ProviderID: p.c.ProviderID, PendingID: pending,
		Origin: string(p.c.Origin), Browser: browser, Form: authentication.NewBearerCredential(form.Get("confirmation"))}
	return s, nil
}

func (p samlIDPSigninProfile) handler() (http.Handler, error) {
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[samlIDPState]{
		MaximumDuration: p.c.MaximumDuration, Reject: writeSigninError, Decode: p.decode,
		Authenticate: func(r *http.Request, s samlIDPState) (samlIDPState, error) {
			ctx := r.Context()
			if err := admitSigninIP(ctx, p.c.Rate, s.facts, samlIDPInitOperation, p.c.ProviderID); err != nil || s.arrival != nil {
				return s, err
			}
			source, err := p.c.Owner.SAMLIDPConfirmationRateSource(ctx, s.confirm)
			if err != nil {
				return s, err
			}
			if source.ProviderID != p.c.ProviderID || source.PendingID != s.confirm.PendingID || source.Lifetime < time.Second || source.Lifetime > 5*time.Minute {
				return s, identity.ForbiddenError{}
			}
			s.source = source
			return s, nil
		},
		Admit: func(r *http.Request, s samlIDPState) error {
			if s.arrival != nil {
				return nil
			}
			decision, err := p.c.Rate.AdmitProviderTransaction(r.Context(), s.facts, samlIDPInitOperation, p.c.ProviderID, string(s.source.PendingID), s.source.Lifetime)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return discoveryRateDenial{retry: decision.RetryAfter}
			}
			if err != nil || !decision.Allowed {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s samlIDPState) {
			if s.arrival != nil {
				p.prepare(w, r, *s.arrival)
				return
			}
			p.confirm(w, r, s.confirm)
		},
	})
	if err != nil {
		return nil, err
	}
	return &signinCallbackHandler{pipeline: pipeline}, nil
}

func (p samlIDPSigninProfile) prepare(w http.ResponseWriter, r *http.Request, request SAMLIDPArrivalRequest) {
	out, err := p.c.Owner.PrepareSAMLIDP(r.Context(), request)
	if err != nil {
		writeSigninError(w, r, err)
		return
	}
	_, idErr := identity.ParseCommandID(string(out.PendingID))
	b, f := out.BrowserCookie.Token(), out.Synchronizer.Token()
	cookie, cookieErr := p.front.Attributes(p.c.Now(), out.ExpiresAt)
	if idErr != nil || cookieErr != nil || !validSAMLRelay(b) || !validSAMLRelay(f) || b == f || r.Context().Err() != nil {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	cookie.Value = b
	if cookie.Valid() != nil {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	// Only the synchronizer and opaque pending identifier go into the
	// explicit user-confirmed form; never include the original SAML data.
	// Fetch's navigation Origin algorithm would send null on this POST under
	// the router's no-referrer default. This document alone needs same-origin.
	page := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="same-origin"><title>Confirm sign-in</title></head>` +
		`<body><main><h1>Confirm sign-in</h1><form method="post" action="` + html.EscapeString(p.path) + `">` +
		`<input type="hidden" name="pending" value="` + html.EscapeString(string(out.PendingID)) + `">` +
		`<input type="hidden" name="confirmation" value="` + html.EscapeString(f) + `">` +
		`<button type="submit">Continue signing in</button></form></main></body></html>`
	delivery := r.Context().Value(signinDeliveryKey{}).(*signinDelivery)
	delivery.confirmation = &signinConfirmationPage{html: page, cookie: cookie.String(), current: func() bool {
		return r.Context().Err() == nil && out.ExpiresAt.Sub(p.c.Now()) >= time.Second
	}}
	w.WriteHeader(http.StatusOK)
}

func (p samlIDPSigninProfile) confirm(w http.ResponseWriter, r *http.Request, request SAMLIDPConfirmationRequest) {
	out, err := p.c.Owner.ConfirmSAMLIDP(r.Context(), request)
	if err != nil {
		writeSigninError(w, r, err)
		return
	}
	b, feature := out.Completion.Binding, out.Completion.Feature
	spec, err := out.Issuance.Session.Bindings()
	command, commandErr := identity.ParseCommandID(string(b.CommandID))
	if err != nil || commandErr != nil || command == request.PendingID || b.RecordID != string(request.PendingID) || b.ActorKind != authorization.SubjectServiceAccount || b.UserID == "" || b.UserID != spec.UserID ||
		feature == nil || feature.Operation.OperationID != samlIDPInitOperation || feature.BeforeVersion != 1 || feature.AfterVersion != 2 || out.RedirectURI != "" {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	// Native confirmation never selects a redirect. Use only the pinned
	// same-origin completion URL after accepted fresh credential delivery.
	out.RedirectURI = p.c.SuccessCallback
	delivery := SigninCallbackConfig{Browser: SigninBrowserConfig{TenantID: p.c.TenantID, Now: p.c.Now}, Audience: p.c.Audience,
		CallbackAllowlist: []string{p.c.SuccessCallback}, Cookie: p.c.Cookie, CSRFCookie: p.c.CSRFCookie}
	writeSigninDelivery(w, r, delivery, samlIDPInitOperation, "sso-saml", out, command, "", spec.Authentication.Proof.ExpiresAt, p.clearFront.String())
}
