package mfahttp

import (
	"net/http/httptest"
	"testing"
)

// FuzzURIHTTPDecodeBoundary covers hostile closed JSON; the native adapter's
// independent transactional tests remain the proof of factor/reveal authority.
func FuzzURIHTTPDecodeBoundary(f *testing.F) {
	for _, seed := range []string{`{}`, `{"commandID":null,"enrollmentID":null}`, `{"commandID":"x","commandID":"y","enrollmentID":"z"}`, `{"commandID":"AAAAAAAAAAAAAAAAAAAAAA","enrollmentID":"AQEBAQEBAQEBAQEBAQEBAQ"}`, `{"commandID":[[[[[]]]]],"enrollmentID":true}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 16384 {
			return
		}
		c, _, _, _, r := uriFixture(t)
		r.Body = ioBody(body)
		r.ContentLength = int64(len(body))
		h, err := NewURIHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Location") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
			t.Fatal("hostile input escaped credential/cache boundary")
		}
	})
}
