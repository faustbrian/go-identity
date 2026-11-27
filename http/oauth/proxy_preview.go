package oauthhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/session"
)

// ProxyPreviewConfig selects one canonical HTTPS preview completion endpoint.
// Network is the borrowed immutable tenant/proxy policy; Complete is the
// concurrency-safe native one-use completion owner, not an envelope decoder.
// It must honor the bounded context, authenticate the original flow cookie and
// retain no input. The transport clears the borrowed envelope on return.
// Cookie policies must match ordinary native signin issuance. Now must be
// prompt and concurrency-safe; MaximumDuration is explicitly 1ms..20s.
type ProxyPreviewConfig struct {
	Endpoint        string
	TenantID        identity.TenantID
	ProviderID      string
	Audience        string
	Network         *identityhttp.NetworkResolver
	FlowCookie      session.CookiePolicy
	Cookie          session.CookiePolicy
	Device          session.BrowserDeviceConfig
	CSRFCookie      session.CSRFCookiePolicy
	Now             func() time.Time
	MaximumDuration time.Duration
	Complete        func(context.Context, identity.PreAuthTransactionID, oauthproxy.PreviewCompletionRequest, string, string) (oauth.SigninCallbackResult, error)
}

// Format redacts browser-device custody and borrowed runtime composition.
func (ProxyPreviewConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.ProxyPreviewConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime composition export.
func (ProxyPreviewConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText refuses implicit runtime composition export.
func (ProxyPreviewConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewProxyPreviewBrowserHandler selects the relay GET and completion POST at
// one registered preview endpoint. The landing uses direct TLS and successURL
// must be a distinct path at that exact origin. A different path or method
// selects neither browser boundary. Construction borrows the same owners as
// NewProxyPreviewHandler and makes no state changes.
func NewProxyPreviewBrowserHandler(c ProxyPreviewConfig, successURL string) (http.Handler, error) {
	landing, err := NewProxyHandoffLanding(c.Endpoint, successURL)
	if err != nil {
		return nil, err
	}
	complete, err := NewProxyPreviewHandler(c)
	if err != nil {
		return nil, err
	}
	endpoint, _ := proxyHandoffEndpoint(c.Endpoint)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyPreviewClearDelivery(w)
		if r == nil || r.URL == nil || r.URL.Path != endpoint.Path || r.URL.EscapedPath() != endpoint.Path {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			landing.ServeHTTP(w, r)
		case http.MethodPost:
			complete.ServeHTTP(w, r)
		default:
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}), nil
}

// NewProxyPreviewHandler accepts only POST at the exact selected endpoint with
// a same-origin Origin header, the original flow and signed device cookies,
// and closed bounded JSON {flow,envelope}. Query/credential-header alternatives
// and Referer fallback are forbidden. Flow is a locator, never authority.
// Native completion owns envelope authentication, one-use consumption and all
// account/risk/session effects. Only its newly committed matching result may
// produce empty 204 with ordinary authentication/CSRF cookies and flow expiry.
// Replay, expiry, cancellation and invalid output disclose no credentials or
// redirects. The handler owns no resources; callers own request-body closure,
// server read/write deadlines and response lifetimes. Requests may run concurrently.
func NewProxyPreviewHandler(c ProxyPreviewConfig) (http.Handler, error) {
	endpoint, err := proxyHandoffEndpoint(c.Endpoint)
	if err != nil || endpoint.Path == "/" || c.TenantID == "" || c.ProviderID == "" || c.Audience == "" || c.Now == nil || c.Complete == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 20*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	origin := identityhttp.Origin(endpoint.Scheme + "://" + endpoint.Host)
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: c.Network, TrustedOrigins: []identityhttp.Origin{origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	flow, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flow.Name != "__Host-identity_flow" || flow.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	authentication, err := c.Cookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	deviceCookie, err := c.Device.Cookie.DeletionAttributes()
	if err != nil || deviceCookie.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	csrf, err := c.CSRFCookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	names := []string{flow.Name, authentication.Name, deviceCookie.Name, csrf.Name}
	for i, name := range names {
		for _, other := range names[i+1:] {
			if strings.EqualFold(name, other) {
				return nil, identityhttp.ErrInvalidInput
			}
		}
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	// The relay's canonical 8192-byte envelope needs at most 10923 base64
	// bytes. This fixed transport profile leaves bounded JSON framing room,
	// not an independently configurable envelope or alternate input channel.
	decoder, err := identityhttp.NewRequestDecoder(identityhttp.Limits{MaximumHeaderBytes: 16384, MaximumURLBytes: 2048, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 2, MaximumDepth: 1})
	if err != nil {
		return nil, err
	}
	deliveryConfig := Config{Provider: oauth.ProviderProfile{ID: c.ProviderID}, Cookie: c.Cookie, Now: c.Now}
	selected := SigninCallbackConfig{CSRFCookie: c.CSRFCookie, Audience: c.Audience}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyPreviewClearDelivery(w)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r == nil || r.URL == nil {
			proxyPreviewReject(w, r, identityhttp.ErrInvalidInput)
			return
		}
		ctx, stop := context.WithTimeout(r.Context(), c.MaximumDuration)
		defer stop()
		r = r.WithContext(ctx)
		u := r.URL
		if r.Method != http.MethodPost || u.Path != endpoint.Path || u.EscapedPath() != endpoint.Path || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || u.User != nil || len(r.Trailer) != 0 {
			proxyPreviewReject(w, r, identityhttp.ErrInvalidInput)
			return
		}
		facts, err := c.Network.Resolve(r)
		if err != nil || facts.Realm() != identityhttp.RealmTenant || facts.TenantID() != c.TenantID || facts.Scheme() != "https" || facts.Origin() != string(origin) {
			proxyPreviewReject(w, r, identity.ForbiddenError{})
			return
		}
		if _, err := origins.CheckBound(r, origin); err != nil {
			proxyPreviewReject(w, r, identity.ForbiddenError{})
			return
		}
		if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
			proxyPreviewReject(w, r, identityhttp.ErrInvalidInput)
			return
		}
		for name := range r.Header {
			if strings.EqualFold(name, "X-CSRF-Token") {
				proxyPreviewReject(w, r, identityhttp.ErrInvalidInput)
				return
			}
		}
		browser, _, err := decoder.CookieBearer(r, flow.Name, identityhttp.HeaderRequired)
		if err != nil {
			proxyPreviewReject(w, r, identityhttp.ErrInvalidInput)
			return
		}
		if _, err := session.ParseToken(browser.Token()); err != nil {
			proxyPreviewReject(w, r, identityhttp.ErrInvalidInput)
			return
		}
		deviceBearer, _, err := decoder.CookieBearer(r, deviceCookie.Name, identityhttp.HeaderRequired)
		if err != nil {
			proxyPreviewReject(w, r, identityhttp.ErrInvalidInput)
			return
		}
		device, err := devices.Resolve(ctx, c.Now(), facts.TenantID(), facts.Origin(), deviceBearer.Token())
		if err != nil {
			proxyPreviewReject(w, r, identity.ForbiddenError{})
			return
		}
		id, envelope, err := proxyPreviewJSON(decoder, r)
		defer clear(envelope)
		if err != nil {
			proxyPreviewReject(w, r, identityhttp.ErrInvalidInput)
			return
		}
		if ctx.Err() != nil || !device.ExpiresAt().After(c.Now()) {
			proxyPreviewReject(w, r, identityhttp.ErrUnavailable)
			return
		}
		out, err := c.Complete(ctx, id, oauthproxy.PreviewCompletionRequest{Origin: string(origin), FlowCookie: browser, Envelope: envelope}, facts.ClientIP().String(), device.DeviceID())
		if err != nil {
			proxyPreviewReject(w, r, err)
			return
		}
		redirect, valid := out.Outcome.RedirectURI()
		if !valid || redirect.String() != c.Endpoint || out.Outcome.Denied() || out.Session.Replayed || out.Session.CommitOutcome != identity.CommitOutcomeCommitted || out.Session.DeliveryValidUntil.IsZero() {
			proxyPreviewReject(w, r, identityhttp.ErrUnavailable)
			return
		}
		deliveryNow := c.Now()
		requestDelivery := deliveryConfig
		requestDelivery.Now = func() time.Time { return deliveryNow }
		cookies, current, err := signinCallbackDelivery(requestDelivery, selected, c.TenantID, out)
		if err != nil || len(cookies) != 2 || current == nil {
			proxyPreviewReject(w, r, identityhttp.ErrUnavailable)
			return
		}
		// Native preview completion supplies the earliest original browser /
		// envelope cutoff; ordinary session validity cannot extend that lease.
		deliveryNow = c.Now()
		if !current() || !out.Session.DeliveryValidUntil.After(deliveryNow) || !device.ExpiresAt().After(deliveryNow) || ctx.Err() != nil {
			proxyPreviewReject(w, r, identityhttp.ErrUnavailable)
			return
		}
		proxyPreviewClearDelivery(w)
		for _, cookie := range cookies {
			w.Header().Add("Set-Cookie", cookie)
		}
		w.Header().Add("Set-Cookie", flow.String())
		w.WriteHeader(http.StatusNoContent)
	}), nil
}

func proxyPreviewJSON(decoder *identityhttp.RequestDecoder, r *http.Request) (identity.PreAuthTransactionID, []byte, error) {
	fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
	defer func() {
		for _, raw := range fields {
			clear(raw)
		}
	}()
	if err != nil || len(fields) != 2 {
		return "", nil, identityhttp.ErrInvalidInput
	}
	var flow, envelope string
	if json.Unmarshal(fields["flow"], &flow) != nil || json.Unmarshal(fields["envelope"], &envelope) != nil {
		return "", nil, identityhttp.ErrInvalidInput
	}
	return parseProxyHandoff(flow, envelope)
}

func proxyPreviewReject(w http.ResponseWriter, r *http.Request, err error) {
	proxyPreviewClearDelivery(w)
	switch {
	case errors.Is(err, oauthproxy.CompletionInvalid):
		err = identityhttp.ErrInvalidInput
	case errors.Is(err, oauthproxy.CompletionDenied):
		err = identity.ForbiddenError{}
	case errors.Is(err, oauthproxy.CompletionUnavailable):
		err = identityhttp.ErrUnavailable
	}
	oneTapCallbackReject(w, r, err)
}

func proxyPreviewClearDelivery(w http.ResponseWriter) {
	for name := range w.Header() {
		if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "Trailer") || strings.HasPrefix(strings.ToLower(name), strings.ToLower(http.TrailerPrefix)) {
			delete(w.Header(), name)
		}
	}
}
