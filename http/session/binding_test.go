package sessionhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

func TestSessionOperationBindingUsesRealPhasesAndResponseCustody(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newLogout(t, mode)
		feature, err := sessionhttp.NewFeature(f.config)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range feature.Operations() {
			var observed bool
			hook := logoutMiddleware(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if s, ok := identityhttp.PipelineValue[sessionhttp.GetState](r); ok {
					_, observed = s.Principal()
				} else if s, ok := identityhttp.PipelineValue[sessionhttp.SignOutState](r); ok {
					_, observed = s.Principal()
				}
				w.Header().Add("Set-Cookie", "attacker=value; Secure")
				w.Header().Set("Cache-Control", "public")
				next.ServeHTTP(w, r)
			})
			h, err := identityhttp.WithOperationMiddleware(op.Handler, []identityhttp.MiddlewareDescriptor{hook})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			r := request(f.fixture, true)
			if op.Route.Method == http.MethodPost {
				r = logoutRequest(f, true)
			}
			before := f.calls.Load()
			h.ServeHTTP(w, r)
			wantReads := int32(1)
			if op.Route.Method == http.MethodPost {
				wantReads = 2
			}
			if w.Code != 200 || !observed || f.calls.Load()-before != wantReads || w.Result().Header.Get("Cache-Control") != "no-store" {
				t.Fatal("binding bypassed actual owner phases or response protection")
			}
			wantCookies := 0
			if mode == session.CredentialCookie && op.Route.Method == http.MethodPost {
				wantCookies = 1
			}
			if len(w.Result().Cookies()) != wantCookies {
				t.Fatal("binding lost cookie custody")
			}
		}
	}
}
