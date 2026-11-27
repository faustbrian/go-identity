package oauthhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

// OneTapRedirectStartHTTPResult transfers one original native StartRedirect
// outcome and its RedirectBrowser custody without regeneration or reveal. Only
// this invocation's fresh exact commit can carry projection, cookie and token.
// Replay, unknown results and recovery carry no response-delivery authority.
type OneTapRedirectStartHTTPResult struct {
	CommandID  identity.CommandID
	Outcome    identity.CommitOutcome
	Replayed   bool
	Projection onetap.BrowserRedirectStartProjection
	Cookie     http.Cookie
	Token      session.Token
}

// OneTapRedirectStartConfig opts into only the standalone Google redirect-button
// start handler. Start is the synchronous borrowed native StartRedirect mapping;
// it must honor context and transfer only its original receipt/RedirectBrowser.
// ProviderID must be google. CallbackURL must be Origin plus the exact selected
// /v1/oauth/onetap-callback path, not a form field or navigation destination.
// Device is the existing signed Lax browser-device policy; no new device is
// issued here. Rate owns shared provider/IP admission. Lifetime resolves Remember
// once without extending the original five-minute flow. Now must be prompt and
// concurrency-safe; MaximumDuration is 1ms..30s and earlier deadlines win.
type OneTapRedirectStartConfig struct {
	Network         identityhttp.NetworkConfig
	ProviderID      string
	ClientID        string
	CallbackURL     string
	Start           func(context.Context, onetap.BrowserRedirectStartRequest) (OneTapRedirectStartHTTPResult, error)
	Rate            *identityhttp.AuthRateLimiter
	Device          session.BrowserDeviceConfig
	Origin          identityhttp.Origin
	Lifetime        session.LifetimeConfig
	Now             func() time.Time
	MaximumDuration time.Duration
}

type oneTapRedirectStartBinding struct {
	config OneTapRedirectStartConfig
	cookie session.FrontchannelCookiePolicy
}

// NewOneTapRedirectStartFeature selects the redirect button Start and its
// exact wire contract; the separately selected callback is not implied.
func NewOneTapRedirectStartFeature(c OneTapRedirectStartConfig) (identityhttp.Feature, error) {
	h, err := NewOneTapRedirectStartHandler(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-start", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: maximumOneTapStartResponse})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = wireOneTapStartProfile(c.Origin, c.CallbackURL)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/oauth/onetap", Operations: []identityhttp.OperationDescriptor{op}})
}

// NewOneTapRedirectStartHandler selects exact POST /v1/oauth/onetap-start with
// same-origin HTTPS tenant admission, a signed existing device, one retry key
// and closed button/optional-remember JSON. It enables no feature registration,
// callback, CORS or navigation. Only fresh native custody can deliver the original
// path-bound frontchannel cookie and detached typed GIS launch; no bearer enters
// JSON. The server retains raw IO/write-deadline ownership and no retry occurs.
func NewOneTapRedirectStartHandler(c OneTapRedirectStartConfig) (http.Handler, error) {
	if c.Start == nil || c.ProviderID != "google" || c.CallbackURL != string(c.Origin)+"/v1/oauth/onetap-callback" || !strings.HasPrefix(string(c.Origin), "https://") {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := session.NewOneTapRedirectFrontchannelCookiePolicy(string(c.Origin), c.CallbackURL)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}

	base := OneTapStartConfig{Network: c.Network, ProviderID: c.ProviderID, ClientID: c.ClientID, Rate: c.Rate, Device: c.Device, Origin: c.Origin, Lifetime: c.Lifetime, Now: c.Now, MaximumDuration: c.MaximumDuration}
	return newOneTapStartHandler(base, &oneTapRedirectStartBinding{config: c, cookie: cookie})
}

func (b *oneTapRedirectStartBinding) handle(w http.ResponseWriter, r *http.Request, s oneTapStartState, delivery *oneTapStartDelivery, reject func(http.ResponseWriter, *http.Request, error)) {
	c := b.config
	out, err := c.Start(r.Context(), s.redirectRequest)
	if err != nil {
		reject(w, r, err)
		return
	}

	projection, err := b.projection(s, out, c.Now())
	if err != nil || r.Context().Err() != nil {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}

	body, err := json.Marshal(projection)
	if err != nil || len(body) > maximumOneTapStartResponse {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}

	delivery.cookie, delivery.token, delivery.expires = out.Cookie, out.Token, projection.ExpiresAt
	delivery.body, delivery.ctx = body, r.Context()
	delivery.current = func() bool { _, err := b.projection(s, out, c.Now()); return err == nil }
	delivery.now = c.Now
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (b *oneTapRedirectStartBinding) projection(s oneTapStartState, out OneTapRedirectStartHTTPResult, now time.Time) (onetap.BrowserRedirectStartProjection, error) {
	deny := func() (onetap.BrowserRedirectStartProjection, error) {
		return onetap.BrowserRedirectStartProjection{}, identityhttp.ErrUnavailable
	}
	c, p := b.config, out.Projection
	if out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || out.Token == (session.Token{}) || now.IsZero() || !s.device.ExpiresAt().After(now) {
		return deny()
	}
	if p.Experience != onetap.BrowserStartRedirectButton || p.ClientID != c.ClientID || p.LoginURI != c.CallbackURL || p.AllowedParentOrigin != string(c.Origin) {
		return deny()
	}
	if p.IssuedAt.Location() != time.UTC || p.ExpiresAt.Location() != time.UTC || p.IssuedAt.Nanosecond() != 0 || p.ExpiresAt.Nanosecond() != 0 {
		return deny()
	}
	if now.Before(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) != 5*time.Minute || p.ExpiresAt.Sub(now) < time.Second || p.ExpiresAt.Sub(now) > 5*time.Minute {
		return deny()
	}

	if _, err := identity.ParseCommandID(string(out.CommandID)); err != nil {
		return deny()
	}
	if _, err := identity.ParsePreAuthTransactionID(p.State); err != nil {
		return deny()
	}
	if len(p.Nonce) != 43 {
		return deny()
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(p.Nonce)
	if err != nil || len(nonce) != 32 || [32]byte(nonce) == ([32]byte{}) {
		return deny()
	}

	request, err := s.redirectRequest.Bindings()
	if err != nil {
		return deny()
	}
	want, err := request.Options.Projection()
	if err != nil || want.Experience != p.Experience || want.Prompt != nil || want.Button == nil || *want.Button != p.Button || p.Button.UXMode != onetap.ButtonRedirect {
		return deny()
	}

	expected, err := b.cookie.DeletionAttributes()
	if err != nil || !oneTapStartCookieMatches(expected, out.Cookie, p.ExpiresAt) {
		return deny()
	}
	return p, nil
}

// Format redacts borrowed runtime configuration.
func (OneTapRedirectStartConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.OneTapRedirectStartConfig(redacted)"))
}

// MarshalJSON denies implicit runtime configuration export.
func (OneTapRedirectStartConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText denies implicit runtime configuration export.
func (OneTapRedirectStartConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// Format redacts original native browser custody.
func (OneTapRedirectStartHTTPResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.OneTapRedirectStartHTTPResult(redacted)"))
}

// MarshalJSON denies implicit native browser custody export.
func (OneTapRedirectStartHTTPResult) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText denies implicit native browser custody export.
func (OneTapRedirectStartHTTPResult) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}
