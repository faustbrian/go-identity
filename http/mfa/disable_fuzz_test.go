package mfahttp

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func FuzzDisableHTTPEnvelope(f *testing.F) {
	f.Add([]byte(`{}`), "", "original-key")
	f.Add([]byte(`{"target":"all","proofID":"AAAAAAAAAAAAAAAAAAAAAg"}`), "", "original-key")
	f.Add([]byte(`{"target":"one","factorID":"AAAAAAAAAAAAAAAAAAAABA","proofID":"AAAAAAAAAAAAAAAAAAAAAg"}`), "", "original-key")
	f.Add([]byte(`{"target":"all","factorID":null,"proofID":"AAAAAAAAAAAAAAAAAAAAAg"}`), "", "original-key")
	f.Add([]byte(`{"target":"one","target":"all","proofID":"AAAAAAAAAAAAAAAAAAAAAg"}`), "userID=foreign", "duplicate-input")
	f.Fuzz(func(t *testing.T, body []byte, query, key string) {
		if len(body) > 8192 || len(query) > 4096 || len(key) > 512 {
			t.Skip()
		}
		base, proofs, _, _, r := enableFixture(t)
		owner := &disableOwner{}
		c := DisableConfig{Network: base.Network, Sessions: base.Sessions, Proofs: proofs, Service: owner, Rate: base.Rate, Cookie: base.Cookie, TrustedOrigins: base.TrustedOrigins, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration, MaximumAge: time.Minute}
		h, err := NewDisableHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		r.URL.Path = "/v1/mfa/disable"
		r.URL.RawQuery = query
		r.RequestURI = r.URL.RequestURI()
		r.Header.Set("Idempotency-Key", key)
		r.Body = ioBody(string(body))
		r.ContentLength = int64(len(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		// The original fixture proof is for another purpose. Parsing or caller
		// input must never promote it into disable authority or issue a session.
		if w.Code == 200 || owner.calls != 0 || strings.Contains(w.Body.String(), `"factors"`) || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("hostile envelope promoted purpose or exported state/credentials")
		}
	})
}
