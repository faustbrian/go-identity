package sessionhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

func browserDeviceHTTPConfig(t *testing.T) session.BrowserDeviceConfig {
	t.Helper()
	key, err := session.NewBrowserDeviceKey(1, []byte("dedicated-browser-device-key-1234"))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	return session.BrowserDeviceConfig{Namespace: "http-test", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: cookie}
}

func TestPreAuthBrowserDeviceRejectsValidForeignAndExpiredCustody(t *testing.T) {
	for _, scope := range []string{"tenant", "origin", "expired"} {
		c, owner, _ := preAuthHTTPFixture(t)
		d := browserDeviceHTTPConfig(t)
		codec, _ := session.NewBrowserDeviceCodec(d)
		tenant, origin, now := "tenant-a", string(c.Origin), c.Now()
		switch scope {
		case "tenant":
			tenant = "tenant-other"
		case "origin":
			origin = "https://other.example"
		case "expired":
			now = now.Add(-24 * time.Hour)
		}
		device, err := codec.Issue(t.Context(), now, identity.TenantID(tenant), origin)
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := http.ParseSetCookie(device.CookieHeader())
		if err != nil {
			t.Fatal(err)
		}
		h, err := sessionhttp.NewPreAuthHandlerWithBrowserDevice(c, d)
		if err != nil {
			t.Fatal(err)
		}
		r := preAuthHTTPRequest("{}")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || owner.prepares.Load() != 0 || len(w.Result().Cookies()) != 0 {
			t.Fatal("foreign/expired device accepted", scope)
		}
	}
}

func TestPreAuthBrowserDeviceSelectedAndProtected(t *testing.T) {
	c, _, executor := preAuthHTTPFixture(t)
	forge := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header()["set-cookie"] = []string{"attacker=forbidden"}
			next.ServeHTTP(w, r)
			w.Header().Set("Set-Cookie", "attacker=forbidden")
		})
	}
	m := []identityhttp.MiddlewareDescriptor{{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "forge", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: forge}}}
	f, err := sessionhttp.NewPreAuthFeatureWithBrowserDeviceAndMiddleware(c, browserDeviceHTTPConfig(t), m)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc.JSON()), "__Host-identity_device") || executor.calls.Load() != 0 {
		t.Fatal("selected metadata missing or owner called at construction")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest("{}"))
	if w.Code != 200 || len(w.Result().Cookies()) != 2 || strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ""), "attacker") {
		t.Fatal("dual-cookie custody bypassed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest("{}").WithContext(ctx))
	if len(w.Result().Cookies()) != 0 || executor.calls.Load() != 1 {
		t.Fatal("cancellation reached owner or delivered cookies")
	}
	for i := 0; i < 19; i++ {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest("{}"))
		if w.Code != 200 {
			t.Fatal("rate budget changed", i)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest("{}"))
	if w.Code != 429 || executor.calls.Load() != 20 || len(w.Result().Cookies()) != 0 {
		t.Fatal("rate denial reached owner or delivered cookies", w.Code)
	}
}

func TestPreAuthBrowserDeviceOriginalAndStable(t *testing.T) {
	c, _, _ := preAuthHTTPFixture(t)
	d := browserDeviceHTTPConfig(t)
	h, err := sessionhttp.NewPreAuthHandlerWithBrowserDevice(c, d)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest("{}"))
	cookies := w.Result().Cookies()
	if w.Code != 200 || len(cookies) != 2 {
		t.Fatal("missing owned flow/device cookies", w.Code, len(cookies))
	}
	var device *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "__Host-identity_device" {
			device = cookie
		}
	}
	if device == nil || !device.Secure || !device.HttpOnly || device.Path != "/" || device.MaxAge != 86400 || device.Domain != "" {
		t.Fatal("unsafe device cookie")
	}
	codec, _ := session.NewBrowserDeviceCodec(d)
	original, err := codec.Resolve(t.Context(), c.Now(), "tenant-a", string(c.Origin), device.Value)
	if err != nil {
		t.Fatal("invalid device custody", err)
	}
	r := preAuthHTTPRequest("{}")
	r.AddCookie(device)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Name != "__Host-identity_flow" {
		t.Fatal("existing device renewed or rejected", w.Code)
	}
	again, err := codec.Resolve(t.Context(), c.Now(), "tenant-a", string(c.Origin), device.Value)
	if err != nil || again.DeviceID() != original.DeviceID() || !again.ExpiresAt().Equal(original.ExpiresAt()) {
		t.Fatal("device identity/timeline changed")
	}
}

func TestPreAuthBrowserDeviceDenialBeforeOwner(t *testing.T) {
	for _, raw := range []string{"__Host-identity_device=bad", "__Host-identity_device=bad; __Host-identity_device=bad"} {
		c, owner, executor := preAuthHTTPFixture(t)
		h, err := sessionhttp.NewPreAuthHandlerWithBrowserDevice(c, browserDeviceHTTPConfig(t))
		if err != nil {
			t.Fatal(err)
		}
		r := preAuthHTTPRequest("{}")
		r.Header.Set("Cookie", raw)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || owner.prepares.Load() != 0 || executor.calls.Load() != 0 || len(w.Result().Cookies()) != 0 {
			t.Fatal("invalid device reached owner or fallback issuance", w.Code)
		}
	}
}

func TestPreAuthBrowserDeviceFailedFlowWithholdsBoth(t *testing.T) {
	for _, mode := range []string{"unknown", "error", "replay"} {
		c, _, executor := preAuthHTTPFixture(t)
		executor.mode = mode
		h, err := sessionhttp.NewPreAuthHandlerWithBrowserDevice(c, browserDeviceHTTPConfig(t))
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest("{}"))
		if w.Code != 503 || len(w.Result().Cookies()) != 0 {
			t.Fatal("failed flow delivered credentials", mode, w.Code)
		}
	}
}
