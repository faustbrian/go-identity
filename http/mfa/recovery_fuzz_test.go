package mfahttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzRecoveryClosedJSON(f *testing.F) {
	for _, seed := range []string{"", `{}`, `{"recoveryCode":null}`, `{"recoveryCode":"12345678","recoveryCode":"87654321"}`, `{"factorID":"caller-selected"}`, `{"recoveryCode":{"nested":[1,2,3]}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		base, totp, _, device := handlerFixture(t)
		owner := &recoveryNative{rate: totp.rate}
		config := RecoveryUseConfig{Network: base.Network, Service: owner, Rate: base.Rate, Origin: base.Origin, CallbackURL: base.CallbackURL, SessionCookie: base.SessionCookie, Device: base.Device, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Audience: base.Audience, Now: base.Now, MaximumDuration: base.MaximumDuration}
		h, err := NewRecoveryUseHandler(config)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/recovery-use", strings.NewReader(body))
		r.RequestURI = r.URL.RequestURI()
		r.RemoteAddr = "127.0.0.1:4242"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", string(config.Origin))
		r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
		r.AddCookie(device)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() > 16384 || totp.calls != 0 {
			t.Fatal("recovery hostile/replay input escaped transport custody")
		}
	})
}
