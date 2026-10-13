package mfahttp

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
)

func FuzzActiveStepUpClosedInput(f *testing.F) {
	for _, body := range []string{"", `{}`, `{"commandID":null}`, `{"code":"1234","code":"5678"}`, `{"factorID":{"nested":[1,2,3]}}`, `{"commandID":"AAAAAAAAAAAAAAAAAAAAAQ","factorID":"AAAAAAAAAAAAAAAAAAAAAg","code":"123456"}`} {
		f.Add(body, "step-up")
	}
	f.Add(`{}`, "enrollment")
	f.Add(`{"commandID":"AAAAAAAAAAAAAAAAAAAAAQ","factorID":"AAAAAAAAAAAAAAAAAAAAAg","code":"123456","purpose":null}`, "step-up")
	f.Add(`{"commandID":"AAAAAAAAAAAAAAAAAAAAAQ","factorID":"AAAAAAAAAAAAAAAAAAAAAg","code":"123456","purpose":"identity.admin.mfa-reset"}`, "step-up")
	f.Add(`{"commandID":"AAAAAAAAAAAAAAAAAAAAAQ","factorID":"AAAAAAAAAAAAAAAAAAAAAg","code":"123456","purpose":"identity.mfa.recovery-regenerate"}`, "step-up")
	f.Add(`{}`, "")
	f.Fuzz(func(t *testing.T, body, variant string) {
		if len(body) > 8192 || len(variant) > 256 {
			return
		}
		c, _, _, clock, r := uriFixture(t)
		owner := &stepUpOwner{confirmationOwner: confirmationOwner{until: clock.now.Add(10 * time.Second), result: mfa.TotpVerifyResult{}}}
		rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: &strictRate{}, Namespace: "step-up-fuzz", Key: [32]byte{4}, Now: clock.Now, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rate.Close() })
		h, err := NewActiveStepUpHandler(ActiveStepUpConfig{Network: c.Network, Sessions: c.Sessions, Service: owner, Rate: rate, Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration})
		if err != nil {
			t.Fatal(err)
		}
		r.URL.Path = "/v1/mfa/totp-verify"
		r.RequestURI = r.URL.RequestURI()
		r.Header.Set("X-MFA-Variant", variant)
		r.Body = ioBody(body)
		r.ContentLength = int64(len(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == 200 || strings.Contains(w.Body.String(), `"proofID"`) || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() > 16384 {
			t.Fatal("hostile/uncommitted step-up disclosed proof or unbounded output")
		}
	})
}
