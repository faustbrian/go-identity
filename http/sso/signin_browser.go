package ssohttp

import (
	"fmt"
	"net/http"
	"net/netip"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// SigninBrowser is transport-observed correlation, not an authenticated user.
// The native owner must authenticate the original flow before any effect.
type SigninBrowser struct {
	FlowID     identity.PreAuthTransactionID
	FlowCookie authentication.BearerCredential
	Origin     string
	Network    netip.Addr
	Device     string
}

func (SigninBrowser) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "ssohttp.SigninBrowser(redacted)")
}
func (SigninBrowser) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (SigninBrowser) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// SigninBrowserConfig binds one exact HTTPS tenant installation to the existing
// original flow and device issuers. Both cookies must permit a top-level
// provider return. The limiter and clock are borrowed concurrency-safe owners.
type SigninBrowserConfig struct {
	Network         identityhttp.NetworkConfig
	TenantID        identity.TenantID
	Origin          identityhttp.Origin
	FlowCookie      session.CookiePolicy
	Device          session.BrowserDeviceConfig
	Rate            *identityhttp.AuthRateLimiter
	Now             func() time.Time
	MaximumDuration time.Duration
}

type signinBrowserPolicy struct {
	config     SigninBrowserConfig
	network    *identityhttp.NetworkResolver
	decoder    *identityhttp.RequestDecoder
	origins    *identityhttp.OriginGuard
	devices    *session.BrowserDeviceCodec
	flowName   string
	deviceName string
}

func newSigninBrowserPolicy(c SigninBrowserConfig) (signinBrowserPolicy, error) {
	if c.TenantID == "" || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return signinBrowserPolicy{}, identityhttp.ErrInvalidInput
	}
	flow, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flow.Name != "__Host-identity_flow" || flow.SameSite != http.SameSiteLaxMode {
		return signinBrowserPolicy{}, identityhttp.ErrInvalidInput
	}
	device, err := c.Device.Cookie.DeletionAttributes()
	if err != nil || device.Name == flow.Name || device.SameSite != http.SameSiteLaxMode {
		return signinBrowserPolicy{}, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return signinBrowserPolicy{}, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return signinBrowserPolicy{}, err
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return signinBrowserPolicy{}, err
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return signinBrowserPolicy{}, identityhttp.ErrInvalidInput
	}
	return signinBrowserPolicy{c, network, decoder, origins, devices, flow.Name, device.Name}, nil
}

func (p signinBrowserPolicy) resolve(r *http.Request, requireOrigin bool) (identityhttp.NetworkFacts, SigninBrowser, session.BrowserDevice, error) {
	return p.resolveWithCookieRequest(r, r, requireOrigin)
}

func (p signinBrowserPolicy) resolveWithCookieRequest(r, cookieRequest *http.Request, requireOrigin bool) (identityhttp.NetworkFacts, SigninBrowser, session.BrowserDevice, error) {
	facts, browser, device, err := p.resolveDeviceWithCookieRequest(r, cookieRequest, requireOrigin)
	if err != nil {
		return facts, browser, device, err
	}
	browser.FlowCookie, err = p.sessionCookie(cookieRequest, p.flowName, identityhttp.HeaderRequired)
	return facts, browser, device, err
}

func (p signinBrowserPolicy) sessionCookie(r *http.Request, name string, requirement identityhttp.HeaderRequirement) (authentication.BearerCredential, error) {
	cookie, found, err := p.decoder.CookieBearer(r, name, requirement)
	if err != nil {
		return authentication.BearerCredential{}, identity.ForbiddenError{}
	}
	if found {
		if _, err := session.ParseToken(cookie.Token()); err != nil {
			return authentication.BearerCredential{}, identity.ForbiddenError{}
		}
	}
	return cookie, nil
}

func (p signinBrowserPolicy) resolveDevice(r *http.Request, requireOrigin bool) (identityhttp.NetworkFacts, SigninBrowser, session.BrowserDevice, error) {
	return p.resolveDeviceWithCookieRequest(r, r, requireOrigin)
}

func (p signinBrowserPolicy) resolveDeviceWithCookieRequest(r, cookieRequest *http.Request, requireOrigin bool) (identityhttp.NetworkFacts, SigninBrowser, session.BrowserDevice, error) {
	facts, err := p.network.Resolve(r)
	if err != nil || facts.Realm() != identityhttp.RealmTenant || facts.TenantID() != p.config.TenantID || facts.Scheme() != "https" || facts.Origin() != string(p.config.Origin) {
		return facts, SigninBrowser{}, session.BrowserDevice{}, identity.ForbiddenError{}
	}
	if requireOrigin || headerPresent(r.Header, "Origin") {
		if _, err := p.origins.CheckBound(r, p.config.Origin); err != nil {
			return facts, SigninBrowser{}, session.BrowserDevice{}, identity.ForbiddenError{}
		}
	}
	device, _, err := p.decoder.CookieBearer(cookieRequest, p.deviceName, identityhttp.HeaderRequired)
	if err != nil {
		return facts, SigninBrowser{}, session.BrowserDevice{}, identity.ForbiddenError{}
	}
	signed, err := p.devices.Resolve(r.Context(), p.config.Now(), facts.TenantID(), facts.Origin(), device.Token())
	if err != nil {
		return facts, SigninBrowser{}, session.BrowserDevice{}, identity.ForbiddenError{}
	}
	return facts, SigninBrowser{Origin: facts.Origin(), Network: facts.ClientIP(), Device: signed.DeviceID()}, signed, nil
}
