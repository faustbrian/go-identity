package mfahttp

import (
	"net/http/httptest"
	"testing"
)

func FuzzOTPSendClosedJSON(f *testing.F) {
	for _, seed := range []string{"", `{}`, `{"channel":null}`, `{"channel":"email","channel":"sms"}`, `{"commandID":"override"}`, `{"idempotencyKey":"override"}`, `{"destination":{"nested":[1,2,3]}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		c, owner, _, device := otpSendFixture(t)
		h, err := NewOTPSendHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, otpSendRequest(c, body, device))
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("X-MFA-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() > 16384 {
			t.Fatal("hostile sending input escaped response boundary")
		}
		if owner.calls > 1 {
			t.Fatal("transport retried native sending")
		}
	})
}
