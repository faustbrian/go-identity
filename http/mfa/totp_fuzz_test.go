package mfahttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzTOTPClosedJSON(f *testing.F) {
	for _, seed := range []string{"", `{}`, `{"code":null}`, `{"code":"1234","code":"5678"}`, `{"unknown":{"nested":[1,2,3]}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		c, _, _, device := handlerFixture(t)
		h, err := NewTOTPVerifyHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader(body))
		r.RequestURI = r.URL.RequestURI()
		r.RemoteAddr = "127.0.0.1:4242"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", string(c.Origin))
		r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
		r.AddCookie(device)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("X-MFA-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() > 16384 {
			t.Fatal("hostile/replay boundary leaked credentials or unbounded output")
		}
	})
}
