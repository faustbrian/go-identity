package mfahttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
)

func FuzzMFAListHTTPEnvelope(f *testing.F) {
	f.Add("", "")
	f.Add("userID=other", "malformed")
	f.Add("%00", "__Host-session=one; __Host-session=two")
	f.Fuzz(func(t *testing.T, query, cookie string) {
		if len(query) > 4096 || len(cookie) > 4096 {
			return
		}
		c, _, _, clock, r := uriFixture(t)
		rate, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: &listRate{}, Namespace: "mfa-list-fuzz", Now: clock.Now, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second, EmergencyMaximumKeys: 128})
		if err != nil {
			t.Fatal(err)
		}
		defer rate.Close()
		owner := &listOwner{result: mfa.ListResult{Factors: []mfa.FactorProjection{}, TrustedDevices: []mfa.TrustedDeviceProjection{}}}
		h, err := NewListHandler(ListConfig{Network: c.Network, Sessions: c.Sessions, Service: owner, Rate: rate, Cookie: c.Cookie, Now: clock.Now, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		r.Method = http.MethodGet
		r.URL.Path = "/v1/mfa/list"
		r.URL.RawQuery = query
		r.Body = http.NoBody
		r.ContentLength = 0
		r.Header.Set("Cookie", cookie)
		r.Header.Del("Origin")
		r.Header.Del("X-CSRF-Token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Body.Len() > 262144 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("hostile listing envelope escaped bounds or credential-free policy")
		}
	})
}
