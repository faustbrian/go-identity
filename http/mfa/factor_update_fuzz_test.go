package mfahttp

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func FuzzFactorUpdateHTTPEnvelope(f *testing.F) {
	f.Add([]byte(`{}`), "", "original-key")
	f.Add([]byte(`{"factorID":"AAAAAAAAAAAAAAAAAAAABA","proofID":"AAAAAAAAAAAAAAAAAAAAAg","action":"rename","name":null,"expectedVersion":1}`), "", "original-key")
	f.Add([]byte(`{"factorID":"one","factorID":"two"}`), "userID=foreign", "duplicate-input")
	f.Fuzz(func(t *testing.T, body []byte, query, key string) {
		if len(body) > 8192 || len(query) > 4096 || len(key) > 512 {
			t.Skip()
		}
		base, proofs, _, _, r := enableFixture(t)
		owner := &factorUpdateOwner{enableOwner: proofs}
		config := FactorUpdateConfig{Network: base.Network, Sessions: base.Sessions, Proofs: proofs, Service: owner, Rate: base.Rate, Cookie: base.Cookie, TrustedOrigins: base.TrustedOrigins, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration, MaximumAge: time.Minute}
		h, err := NewFactorUpdateHandler(config)
		if err != nil {
			t.Fatal(err)
		}
		r.URL.Path = "/v1/mfa/factor-update"
		r.URL.RawQuery = query
		r.RequestURI = r.URL.RequestURI()
		r.Header.Set("Idempotency-Key", key)
		r.Body = ioBody(string(body))
		r.ContentLength = int64(len(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == 200 || strings.Contains(w.Body.String(), `"factor"`) || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("hostile envelope fabricated metadata or credentials")
		}
	})
}
