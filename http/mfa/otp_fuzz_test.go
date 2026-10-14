package mfahttp

import (
	"net/http/httptest"
	"testing"
)

func FuzzOTPClosedLoginJSON(f *testing.F) {
	for _, seed := range []string{"", `{}`, `{"code":null}`, `{"code":"1234","code":"5678"}`, `{"factorID":"foreign"}`, `{"unknown":{"nested":[1,2,3]}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		c, _, _, _, device := otpHandlerFixture(t)
		h, err := NewOTPVerifyHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, otpRequest(c, body, device))
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("X-MFA-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() > 16384 {
			t.Fatal("hostile/replay OTP input escaped credential/size boundary")
		}
	})
}
