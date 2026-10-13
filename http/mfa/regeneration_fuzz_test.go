package mfahttp

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/mfa"
)

func FuzzRegenerationClosedInput(f *testing.F) {
	for _, body := range []string{"", `{}`, `{"proofID":null}`, `{"proofID":"a","proofID":"b"}`, `{"commandID":{"nested":[1,2,3]}}`, `{"commandID":"AAAAAAAAAAAAAAAAAAAAAQ","proofID":"AAAAAAAAAAAAAAAAAAAAAg"}`, `{"commandID":"AAAAAAAAAAAAAAAAAAAAAQ","proofID":"AAAAAAAAAAAAAAAAAAAAAg","userID":"another-user"}`} {
		f.Add(body)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		c, _, _, _, r := uriFixture(t)
		owner := &regenerationOwner{result: mfa.RecoveryRegenerateResult{}}
		h, err := NewRecoveryRegenerateHandler(RecoveryRegenerateConfig{Network: c.Network, Sessions: c.Sessions, Proofs: owner, Service: owner, Rate: c.Rate, Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration, MaximumAge: time.Minute, CodeCount: 1})
		if err != nil {
			t.Fatal(err)
		}
		r.URL.Path = "/v1/mfa/recovery-regenerate"
		r.RequestURI = r.URL.RequestURI()
		r.Body = ioBody(body)
		r.ContentLength = int64(len(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if owner.calls != 0 || w.Code == 200 || strings.Contains(w.Body.String(), `"recoveryCodes"`) || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() > 16384 {
			t.Fatal("hostile/unissued input acquired replacement authority or unbounded output")
		}
	})
}
