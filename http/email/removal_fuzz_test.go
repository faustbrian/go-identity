package emailhttp_test

import (
	emailhttp "github.com/faustbrian/go-identity/http/email"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzEmailRemovalBody(f *testing.F) {
	f.Add(`{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","addressID":"target-address","expectedIdentifierVersion":"1","expectedVerificationVersion":"1","reason":"user-requested","primaryDisposition":"replace-primary","recoveryDisposition":"preserve-verified-email","replacementAddressID":"remaining-address","expectedReplacementIdentifierVersion":"5","expectedReplacementVerificationVersion":"7"}`)
	for _, seed := range []string{`{}`, `null`, `{"proofID":null}`, `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","proofID":"duplicate"}`, `{"tenantID":"foreign"}`, `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","addressID":"target-address","expectedIdentifierVersion":"1","expectedVerificationVersion":"1","reason":"user-requested","primaryDisposition":"leave-unassigned","recoveryDisposition":"preserve-verified-email"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 17000 {
			return
		}
		c, owner, r := removalFixture(t)
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		h, err := emailhttp.NewAddressRemoveHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if owner.removals > 1 || owner.rates > 1 || owner.reads > 1 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Location") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("removal decoder escaped bounded request custody")
		}
		if w.Code == 200 && (owner.removals != 1 || owner.rates != 1 || owner.reads != 1) {
			t.Fatal("removal acknowledged without original owner")
		}
	})
}
