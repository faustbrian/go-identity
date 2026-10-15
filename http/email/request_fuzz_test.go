package emailhttp_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	emailhttp "github.com/faustbrian/go-identity/http/email"
)

// Exercise the actual closed HTTP decoder, not a parallel permissive JSON
// parser. Native signature/SQL custody is covered by the real integration.
func FuzzEmailRequestBody(f *testing.F) {
	for _, seed := range []string{`{}`, `null`, `{"proofID":null}`, `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","address":"a@example.test","callback":"https://tenant.example/finish"}`, `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","proofID":"duplicate"}`, `{"ProofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, `{"tenantID":"foreign"}`, `{"addressID":"pending"}`} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, body string, change bool) {
		if len(body) > 17000 {
			return
		}
		config, owner, request := emailRequestFixture(t, change)
		request.Body = io.NopCloser(strings.NewReader(body))
		request.ContentLength = int64(len(body))
		var handler http.Handler
		var err error
		if change {
			handler, err = emailhttp.NewChangeRequestHandler(config)
		} else {
			handler, err = emailhttp.NewVerificationSendHandler(config)
		}
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if owner.calls > 1 || owner.sources > 1 || owner.reads > 1 || len(response.Result().Cookies()) != 0 || response.Header().Get("Location") != "" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("decoder escaped one-request custody")
		}
		if response.Code == http.StatusAccepted && (owner.calls != 1 || owner.sources != 1 || owner.reads != 1) {
			t.Fatal("acknowledged without original owner")
		}
	})
}
