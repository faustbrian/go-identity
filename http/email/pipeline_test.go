package emailhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
)

func TestConfirmationMiddlewareCannotReplaceCustodyOrIssueCredentials(t *testing.T) {
	c, s, body := fixture(t)
	h, err := emailhttp.NewConfirmationHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	h, err = identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "extension/test", Middleware: identityhttp.Middleware{Name: "custody", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state, ok := identityhttp.PipelineValue[emailhttp.ConfirmationState](r)
			if !ok {
				t.Error("actual authenticated phase missing")
			}
			out, _ := state.Attempt()
			out.CommitOutcome = "committed"
			r.Host = "foreign.example"
			r.Header.Set("Authorization", "Bearer fabricated")
			w.Header()["set-cookie"] = []string{"fabricated=credential"}
			w.Header().Set("Location", "https://foreign.example")
			w.Header().Set("X-CSRF-Token", "fabricated")
			next.ServeHTTP(w, r)
			next.ServeHTTP(w, r)
			w.Header().Set(http.TrailerPrefix+"Set-Cookie", "fabricated=late")
			w.Header().Set("Trailer", "Authorization")
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 200 || s.calls != 1 || s.sources != 1 || s.last.TenantID != "tenant-a" || w.Header().Get("Location") != "" || w.Header().Get("X-CSRF-Token") != "" || len(w.Result().Cookies()) != 0 || w.Header().Get("Trailer") != "" || w.Header().Get(http.TrailerPrefix+"Set-Cookie") != "" {
		t.Fatal("middleware replaced source/reentered/issued credential", w.Code)
	}
}

func TestConfirmationConstructionRejectsMissingOwners(t *testing.T) {
	for _, change := range []func(*emailhttp.ConfirmationConfig){func(c *emailhttp.ConfirmationConfig) { c.Service = nil }, func(c *emailhttp.ConfirmationConfig) { c.Rate = nil }, func(c *emailhttp.ConfirmationConfig) { c.Now = nil }, func(c *emailhttp.ConfirmationConfig) { c.PolicyRevision = 0 }, func(c *emailhttp.ConfirmationConfig) { c.ActorID = "" }, func(c *emailhttp.ConfirmationConfig) { c.MaximumDuration = 0 }} {
		c, _, _ := fixture(t)
		change(&c)
		if h, err := emailhttp.NewConfirmationHandler(c); err == nil || h != nil {
			t.Fatal("missing dependency selected handler")
		}
	}
}
