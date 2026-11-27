package oauthhttp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

// OneTapRedirectCallbackHTTPInput borrows one original redirect callback for
// synchronous native completion. Complete must neither retain nor mutate the
// credential bytes, which this transport clears when the request returns.
// FlowID is only a locator. Native completion authenticates original cookie,
// mode, endpoint, provider proof and sealed initiating device context; there is
// deliberately no caller-supplied Device field.
type OneTapRedirectCallbackHTTPInput struct {
	FlowID     identity.PreAuthTransactionID
	FlowCookie auth.BearerCredential
	Callback   onetap.Callback
	Network    netip.Addr
}

// OneTapRedirectCallbackConfig selects the Google HTML redirect POST profile
// only. Origin, CallbackURL, tenant, provider and audience are trusted deployment
// configuration. CallbackURL must be the same-origin HTTPS canonical callback
// path, and FrontchannelCookie must match original issuance for that endpoint.
// Complete borrows the existing concurrency-safe native RedirectCallback owner,
// honors its bounded context and retains no input. It owns all durable proof,
// replay, account, risk and session decisions. Rate is the shared provider/IP
// admission owner. Cookie policies match native issuance; Now must be prompt
// and concurrency-safe. MaximumDuration is 1ms..30s. No resource is owned here.
type OneTapRedirectCallbackConfig struct {
	Network            identityhttp.NetworkConfig
	Provider           oauth.ProviderProfile
	Complete           func(context.Context, OneTapRedirectCallbackHTTPInput) (OneTapCallbackHTTPResult, error)
	Rate               *identityhttp.AuthRateLimiter
	Cookie             session.CookiePolicy
	FrontchannelCookie session.FrontchannelCookiePolicy
	CSRFCookie         session.CSRFCookiePolicy
	Origin             identityhttp.Origin
	TenantID           identity.TenantID
	Audience           string
	CallbackURL        string
	Now                func() time.Time
	MaximumDuration    time.Duration
}

// Format redacts borrowed original callback custody.
func (OneTapRedirectCallbackHTTPInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.OneTapRedirectCallbackHTTPInput(redacted)"))
}

// MarshalJSON refuses implicit credential export.
func (OneTapRedirectCallbackHTTPInput) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText refuses implicit credential export.
func (OneTapRedirectCallbackHTTPInput) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts borrowed runtime composition.
func (OneTapRedirectCallbackConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.OneTapRedirectCallbackConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime composition export.
func (OneTapRedirectCallbackConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText refuses implicit runtime composition export.
func (OneTapRedirectCallbackConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type oneTapRedirectCallbackState struct {
	facts identityhttp.NetworkFacts
	input OneTapRedirectCallbackHTTPInput
}

// NewOneTapRedirectCallbackHandler accepts only exact POST
// /v1/oauth/onetap-callback at the selected trusted HTTPS tenant endpoint.
// Bounded form state is the canonical native FlowID, not authentication. Only
// the original path-bound frontchannel cookie and exact Google double-submit
// admit completion; no Lax flow/device cookie or bearer alternative is used.
// Sender Origin/Referer and bounded unknown form parameters convey no authority.
// Only a fresh accepted native result delivers its original session and CSRF
// cookies with 200 {status:"signed_in"}. Error, late, cancelled and replayed
// results deliver no cookies, redirects or serialized credentials. Independent
// requests may share the handler; callers own request and response lifetimes.
func NewOneTapRedirectCallbackHandler(c OneTapRedirectCallbackConfig) (http.Handler, error) {
	const callbackPath = "/v1/oauth/onetap-callback"
	if c.Complete == nil || !c.Rate.Configured() || c.Now == nil || c.TenantID == "" || c.Audience == "" || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.Provider.ID != "google" || !c.Provider.GoogleAccounts || c.Provider.Version == 0 || c.Provider.Issuer != "https://accounts.google.com" || c.Provider.ClientID == "" || c.Provider.MaxTokenBytes < 1 || c.Provider.MaxTokenBytes > 1<<20 || c.CallbackURL != string(c.Origin)+callbackPath {
		return nil, identityhttp.ErrInvalidInput
	}
	c.Provider.Scopes, c.Provider.Algorithms = slices.Clone(c.Provider.Scopes), slices.Clone(c.Provider.Algorithms)
	expected, err := session.NewOneTapRedirectFrontchannelCookiePolicy(string(c.Origin), c.CallbackURL)
	if err != nil || c.FrontchannelCookie != expected {
		return nil, identityhttp.ErrInvalidInput
	}
	flow, err := c.FrontchannelCookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	authentication, err := c.Cookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	csrf, err := c.CSRFCookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	names := []string{authentication.Name, flow.Name, csrf.Name, "g_csrf_token"}
	for i, name := range names {
		for _, other := range names[i+1:] {
			if strings.EqualFold(name, other) {
				return nil, identityhttp.ErrInvalidInput
			}
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
	// This validates trusted origin configuration only. Redirect is a cross-site
	// form POST; sender headers are not the original transaction's origin proof.
	if _, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny}); err != nil {
		return nil, err
	}
	deliveryConfig := OneTapCallbackConfig{Cookie: c.Cookie, CSRFCookie: c.CSRFCookie, TenantID: c.TenantID, Audience: c.Audience, Now: c.Now}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[oneTapRedirectCallbackState]{
		MaximumDuration: c.MaximumDuration,
		Reject:          oneTapCallbackReject,
		Decode: func(r *http.Request) (s oneTapRedirectCallbackState, err error) {
			if r.Method != http.MethodPost || r.URL.Path != callbackPath || r.URL.EscapedPath() != callbackPath || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant || s.facts.TenantID() != c.TenantID || s.facts.Scheme() != "https" || s.facts.Origin() != string(c.Origin) {
				return s, identity.ForbiddenError{}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			browser, _, err := decoder.CookieBearer(r, flow.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(browser.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			googleCookie, err := oneTapCallbackGoogleCookie(r, flow.Name, "")
			if err != nil {
				return s, err
			}
			s.input, err = oneTapRedirectCallbackForm(decoder, r, c.Provider, googleCookie)
			if err != nil {
				return s, err
			}
			r.Context().Value(oneTapCallbackKey{}).(*oneTapCallbackDelivery).credential = s.input.Callback.Credential.IDToken
			s.input.FlowCookie, s.input.Network = browser, s.facts.ClientIP()
			s.input.Callback.Origin, s.input.Callback.Redirect = string(c.Origin), c.CallbackURL
			return s, nil
		},
		Authenticate: func(_ *http.Request, s oneTapRedirectCallbackState) (oneTapRedirectCallbackState, error) {
			return s, nil
		},
		Admit: func(r *http.Request, s oneTapRedirectCallbackState) error {
			admitted, err := c.Rate.AdmitProviderIP(r.Context(), s.facts, "identity.oauth.onetap-callback", c.Provider.ID)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return providerRateFailure{retry: admitted.RetryAfter}
			}
			if err == nil && !admitted.Allowed {
				return identityhttp.ErrRateUnavailable
			}
			return err
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s oneTapRedirectCallbackState) {
			delivery := r.Context().Value(oneTapCallbackKey{}).(*oneTapCallbackDelivery)
			if delivery.committed {
				return
			}
			out, err := c.Complete(r.Context(), s.input)
			if err != nil {
				oneTapCallbackReject(w, r, err)
				return
			}
			// Reuse the popup's original native session/CSRF verifier and response
			// custody fence; neither path may renew the native delivery deadline.
			delivery.emit = func() ([]string, error) {
				if r.Context().Err() != nil {
					return nil, identityhttp.ErrUnavailable
				}
				cookies, err := oneTapCallbackCookies(deliveryConfig, out)
				if err != nil || r.Context().Err() != nil {
					return nil, identityhttp.ErrUnavailable
				}
				return cookies, nil
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{\"status\":\"signed_in\"}\n"))
		},
	})
	if err != nil {
		return nil, err
	}
	return &oneTapCallbackHandler{pipeline: pipeline}, nil
}

func oneTapRedirectCallbackForm(decoder *identityhttp.RequestDecoder, r *http.Request, provider oauth.ProviderProfile, cookie string) (OneTapRedirectCallbackHTTPInput, error) {
	var in OneTapRedirectCallbackHTTPInput
	fields, err := decoder.Form(r)
	if err != nil {
		return in, identityhttp.ErrInvalidInput
	}
	flow := fields.Get("state")
	if len(flow) != 22 {
		return in, identityhttp.ErrInvalidInput
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(flow)
	defer clear(decoded)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != flow {
		return in, identityhttp.ErrInvalidInput
	}
	credential, csrf := fields.Get("credential"), fields.Get("g_csrf_token")
	if len(credential) == 0 || len(credential) > provider.MaxTokenBytes || !oneTapCallbackCSRFValue(csrf) {
		return in, identityhttp.ErrInvalidInput
	}
	// Google's HTML API requires the cookie/body pair before ID-token work and
	// ignores unrecognized response parameters. No supplied client_id, endpoint,
	// select_by or device can replace trusted native configuration.
	// https://developers.google.com/identity/gsi/web/reference/html-reference#server-side_integration
	a, b := sha256.Sum256([]byte(cookie)), sha256.Sum256([]byte(csrf))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		return in, identity.ForbiddenError{}
	}
	in.FlowID = identity.PreAuthTransactionID(flow)
	in.Callback = onetap.Callback{CSRFCookies: []string{cookie}, CSRFBody: []string{csrf}, Credential: oauth.GoogleCredential{IDToken: []byte(credential)}}
	return in, nil
}
