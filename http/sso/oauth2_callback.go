package ssohttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

const oauth2SigninCallbackPath = "/sso/oauth2/callback"
const oauth2SigninCallbackOperation = "identity.sso.oauth-callback"

// OAuth2SigninCallbackRequest passes borrowed raw query custody to the native
// owner. Redirect is the configured local HTTPS route, never a query selector.
// FlowID is filled only after the native owner authenticates original state.
type OAuth2SigninCallbackRequest struct {
	TenantID            identity.TenantID
	RawQuery            string
	Browser             SigninBrowser
	ReceivedRedirectURI string
}

// Format redacts query and cookie credentials.
func (OAuth2SigninCallbackRequest) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.OAuth2SigninCallbackRequest(redacted)")
}

// MarshalJSON rejects serialization of borrowed credentials.
func (OAuth2SigninCallbackRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects serialization of borrowed credentials.
func (OAuth2SigninCallbackRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// OAuth2SigninCallbackOwner observes the original callback for rate admission
// without reserving it. Completion repeats protected original checks, owns
// issuer validation and settlement, and returns only fresh proved issuance.
type OAuth2SigninCallbackOwner interface {
	OAuth2CallbackRateSource(context.Context, OAuth2SigninCallbackRequest) (SigninCallbackRateContext, error)
	CompleteSSOOAuth2(context.Context, OAuth2SigninCallbackRequest) (SigninCallbackResult, error)
}

// OAuth2SigninCallbackConfig opts one installed static provider into its exact
// OAuth2 query return. Browser, audience, cookies, and same-origin allowlist
// must agree with the original native and session configuration.
type OAuth2SigninCallbackConfig struct {
	Browser           SigninBrowserConfig
	ProviderID        string
	CallbackAllowlist []string
	Audience          string
	Cookie            session.CookiePolicy
	CSRFCookie        session.CSRFCookiePolicy
	Callback          OAuth2SigninCallbackOwner
}

// NewOAuth2SigninCallbackFeature selects the fixed enterprise OAuth2 query
// callback. It adds no start, discovery, link, or OIDC route.
func NewOAuth2SigninCallbackFeature(c OAuth2SigninCallbackConfig) (identityhttp.Feature, error) {
	if !validProviderID(c.ProviderID) || !configuredOwner(c.Callback) || c.Audience == "" ||
		len(c.CallbackAllowlist) == 0 || len(c.CallbackAllowlist) > 64 {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	c.CallbackAllowlist = slices.Clone(c.CallbackAllowlist)
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
	auth, authErr := c.Cookie.DeletionAttributes()
	csrf, csrfErr := c.CSRFCookie.DeletionAttributes()
	if authErr != nil || csrfErr != nil || auth.Name == csrf.Name ||
		auth.Name == browser.flowName || auth.Name == browser.deviceName ||
		csrf.Name == browser.flowName || csrf.Name == browser.deviceName {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	handler, err := newOAuth2SigninCallbackHandler(c, browser)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	const owner = "sso/oauth2"
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: owner, OperationID: oauth2SigninCallbackOperation, Handler: handler,
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 8192,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = oauth2SigninCallbackWire()
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: owner, Operations: []identityhttp.OperationDescriptor{op}})
}

type oauth2SigninCallbackState struct {
	facts   identityhttp.NetworkFacts
	device  session.BrowserDevice
	request OAuth2SigninCallbackRequest
	source  SigninCallbackRateContext
	command identity.CommandID
}

func newOAuth2SigninCallbackHandler(c OAuth2SigninCallbackConfig, browser signinBrowserPolicy) (http.Handler, error) {
	redirect := string(c.Browser.Origin) + oauth2SigninCallbackPath
	delivery := SigninCallbackConfig{Browser: c.Browser, Cookie: c.Cookie, CSRFCookie: c.CSRFCookie, Audience: c.Audience, CallbackAllowlist: c.CallbackAllowlist}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[oauth2SigninCallbackState]{
		MaximumDuration: c.Browser.MaximumDuration, Reject: writeSigninError,
		Decode: func(r *http.Request) (s oauth2SigninCallbackState, err error) {
			if r.URL == nil || r.Method != http.MethodGet || r.URL.Path != oauth2SigninCallbackPath || r.URL.EscapedPath() != oauth2SigninCallbackPath ||
				r.URL.ForceQuery || r.URL.RawQuery == "" || r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody ||
				len(r.Trailer) != 0 || headerPresent(r.Header, "Authorization") || headerPresent(r.Header, "X-CSRF-Token") {
				return s, identityhttp.ErrInvalidInput
			}
			limit := c.Browser.Network.Limits
			if len(r.URL.RawQuery) > int(limit.MaximumURLBytes) || strings.Count(r.URL.RawQuery, "&")+1 > int(limit.MaximumFields) {
				return s, identityhttp.ErrInvalidInput
			}
			credentials := oauth2CallbackCredentialRequest(r)
			if _, _, err := browser.decoder.IdempotencyKey(credentials, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, s.request.Browser, s.device, err = browser.resolveWithCookieRequest(r, credentials, false)
			if err != nil {
				return s, err
			}
			// Do not parse issuer here: a definitive denial must reach native
			// settlement only after original browser and both quotas agree.
			s.request.TenantID, s.request.RawQuery, s.request.ReceivedRedirectURI = s.facts.TenantID(), r.URL.RawQuery, redirect
			return s, nil
		},
		Authenticate: func(r *http.Request, s oauth2SigninCallbackState) (oauth2SigninCallbackState, error) {
			ctx := r.Context()
			if err := admitSigninIP(ctx, c.Browser.Rate, s.facts, oauth2SigninCallbackOperation, c.ProviderID); err != nil {
				return s, err
			}
			source, err := c.Callback.OAuth2CallbackRateSource(ctx, s.request)
			if err != nil {
				return s, err
			}
			flow, flowErr := identity.ParsePreAuthTransactionID(string(source.FlowID))
			command, commandErr := identity.ParseCommandID(source.TransactionID)
			if source.ProviderID != c.ProviderID || flowErr != nil || commandErr != nil || !s.device.ExpiresAt().After(c.Browser.Now()) {
				return s, identity.ForbiddenError{}
			}
			s.source, s.command, s.request.Browser.FlowID = source, command, flow
			return s, nil
		},
		Admit: func(r *http.Request, s oauth2SigninCallbackState) error {
			decision, err := c.Browser.Rate.AdmitProviderTransaction(r.Context(), s.facts, oauth2SigninCallbackOperation, s.source.ProviderID, s.source.TransactionID, s.source.Lifetime)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return discoveryRateDenial{retry: decision.RetryAfter}
			}
			if err != nil || !decision.Allowed || !s.device.ExpiresAt().After(c.Browser.Now()) {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s oauth2SigninCallbackState) {
			out, err := c.Callback.CompleteSSOOAuth2(r.Context(), s.request)
			if err != nil {
				writeSigninError(w, r, err)
				return
			}
			writeSigninDelivery(w, r, delivery, oauth2SigninCallbackOperation, "sso-oauth2", out, s.command, s.request.Browser.FlowID, s.device.ExpiresAt())
		},
	})
	if err != nil {
		return nil, err
	}
	return &signinCallbackHandler{pipeline}, nil
}

// The credential decoder rejects malformed and duplicate query fields. RFC
// 9207 issuer failures must instead reach the authenticated native owner for
// terminal settlement. Remove only decoded exact `iss` fields from the cookie
// and idempotency checks. The original request still supplies network framing
// and unchanged query bytes, and all other credential aliases remain checked.
func oauth2CallbackCredentialRequest(r *http.Request) *http.Request {
	var remaining strings.Builder
	kept := 0
	for field := range strings.SplitSeq(r.URL.RawQuery, "&") {
		name, _, _ := strings.Cut(field, "=")
		decoded, err := url.QueryUnescape(name)
		if err == nil && decoded == "iss" {
			continue
		}
		if kept > 0 {
			remaining.WriteByte('&')
		}
		remaining.WriteString(field)
		kept++
	}
	view := *r
	target := *r.URL
	target.RawQuery = remaining.String()
	view.URL, view.RequestURI = &target, target.RequestURI()
	return &view
}
