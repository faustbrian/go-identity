package passwordhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/session"
)

func verificationDevice(t *testing.T, f *changeFixture) (session.BrowserDeviceConfig, *http.Cookie, string) {
	t.Helper()
	key, err := session.NewBrowserDeviceKey(1, []byte("dedicated-verification-device-key"))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	c := session.BrowserDeviceConfig{Namespace: "verification-device-test", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: cookie}
	codec, err := session.NewBrowserDeviceCodec(c)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(context.Background(), f.clock.Now(), "tenant-a", "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := http.ParseSetCookie(device.CookieHeader())
	if err != nil {
		t.Fatal(err)
	}
	return c, wire, device.DeviceID()
}

func TestDeviceBoundBearerVerificationUsesOriginalSignedCorrelation(t *testing.T) {
	f, c, work := newVerification(t)
	device, cookie, id := verificationDevice(t, f)
	feature, err := passwordhttp.NewBrowserDeviceBearerVerificationFeature(passwordhttp.BrowserDeviceBearerVerificationConfig{Verification: c, Device: device})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Device verification", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	r := verificationRequest(f)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || work.calls != 1 || work.last.Device != id || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("original correlation not conserved: status=%d calls=%d matching=%t cookies=%d", w.Code, work.calls, work.last.Device == id, len(w.Header().Values("Set-Cookie")))
	}
	if len(doc.Operations()) != 1 {
		t.Fatal("device profile advertised extra route")
	}
	var document struct {
		Paths map[string]map[string]struct {
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &document) != nil {
		t.Fatal("invalid selected document")
	}
	security := document.Paths["/v1/password/verify"]["post"].Security
	if len(security) != 1 || len(security[0]) != 2 {
		t.Fatal("wire advertised credential alternatives instead of conjunction")
	}
	for _, name := range []string{"PasswordVerificationBearer", "PasswordVerificationBrowserDevice"} {
		if _, ok := security[0][name]; !ok {
			t.Fatal("required custody absent from selected wire")
		}
	}
	// Generic bearer transport still ignores the same device cookie.
	f, c, work = newVerification(t)
	r = verificationRequest(f)
	r.AddCookie(cookie)
	w = serveVerification(t, c, r)
	if w.Code != 200 || work.last.Device != "" {
		t.Fatal("generic profile silently adopted cookies")
	}
}

func TestDeviceBoundVerificationRejectsMissingDuplicatedTamperedAndStaleCustody(t *testing.T) {
	for _, scenario := range []string{"missing", "duplicate", "tampered", "expired", "cross-origin", "body-override", "expiry-after-hook"} {
		t.Run(scenario, func(t *testing.T) {
			f, c, work := newVerification(t)
			device, cookie, _ := verificationDevice(t, f)
			c.Network.TenantHosts = append(c.Network.TenantHosts, identityhttp.TenantHost{Host: "other.example", TenantID: "tenant-a"})
			var middleware []identityhttp.MiddlewareDescriptor
			if scenario == "expiry-after-hook" {
				codec, _ := session.NewBrowserDeviceCodec(device)
				original, err := codec.Issue(context.Background(), f.clock.Now().Add(-time.Hour+5*time.Second), "tenant-a", "https://tenant.example")
				if err != nil {
					t.Fatal(err)
				}
				cookie, _ = http.ParseSetCookie(original.CookieHeader())
				middleware = []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "expire-device", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						f.clock.now = f.clock.now.Add(5 * time.Second)
						next.ServeHTTP(w, r)
					})
				}}}}
			}
			h, err := passwordhttp.NewBrowserDeviceBearerVerificationHandlerWithMiddleware(passwordhttp.BrowserDeviceBearerVerificationConfig{Verification: c, Device: device}, middleware)
			if err != nil {
				t.Fatal(err)
			}
			r := verificationRequest(f)
			switch scenario {
			case "missing":
			case "duplicate":
				r.AddCookie(cookie)
				r.AddCookie(cookie)
			case "tampered":
				cookie.Value = "B" + cookie.Value[1:]
				r.AddCookie(cookie)
			case "expired":
				f.clock.now = f.clock.now.Add(time.Hour)
				r.AddCookie(cookie)
			case "cross-origin":
				r.Host = "other.example"
				r.AddCookie(cookie)
			case "body-override":
				r.AddCookie(cookie)
				r.Body = httpBody(`{"password":"synthetic","purpose":"identity.password.verify","action":"identity.password.change","audience":"identity-service","device":"attacker"}`)
				r.ContentLength = -1
			default:
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code == 200 || work.calls != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("invalid correlation issued proof")
			}
		})
	}
}

func TestDeviceBoundVerificationFeatureSelectionIsExplicit(t *testing.T) {
	f, c, _ := newVerification(t)
	device, _, _ := verificationDevice(t, f)
	selected := passwordhttp.BrowserDeviceBearerVerificationConfig{Verification: c, Device: device}
	if _, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{BearerVerification: &c, BrowserDeviceBearerVerification: &selected}); err == nil {
		t.Fatal("ambiguous verification profiles accepted")
	}
	if _, err := passwordhttp.NewBrowserDeviceBearerVerificationHandler(passwordhttp.BrowserDeviceBearerVerificationConfig{Verification: c}); err == nil {
		t.Fatal("missing issuer policy accepted")
	}
	feature, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{Change: &f.config, BrowserDeviceBearerVerification: &selected})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(ops) != 2 {
		t.Fatal("combined owner selection lost operations", err)
	}
}
