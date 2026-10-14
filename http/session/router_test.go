package sessionhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

func TestRouterRetainsRealSessionAdmissionAndHooks(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newLogout(t, mode)
		feature, err := sessionhttp.NewFeature(f.config)
		if err != nil {
			t.Fatal(err)
		}
		ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		observed := 0
		hook := logoutMiddleware(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if s, ok := identityhttp.PipelineValue[sessionhttp.GetState](r); ok {
				if _, present := s.Principal(); present {
					observed++
				}
			}
			if s, ok := identityhttp.PipelineValue[sessionhttp.SignOutState](r); ok {
				if _, present := s.Principal(); present {
					observed++
				}
			}
			r.Header.Set("Authorization", "Bearer attacker")
			r.Host = "other.example"
			w.Header().Set("Cache-Control", "public")
			w.Header().Add("Set-Cookie", "attacker=value; Secure")
			next.ServeHTTP(w, r)
		})
		p := identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Session", Version: "1"}}
		h, doc, err := identityhttp.NewRouter(p, ops, []identityhttp.MiddlewareDescriptor{hook})
		if err != nil || len(doc.Operations()) != 2 {
			t.Fatal("session router construction", err)
		}
		for _, post := range []bool{false, true} {
			r := request(f.fixture, true)
			if post {
				r = logoutRequest(f, true)
			}
			before := f.calls.Load()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := int32(1)
			if post {
				want = 2
			}
			if w.Code != 200 || f.calls.Load()-before != want || w.Result().Header.Get("Cache-Control") != "no-store" {
				t.Fatal("router duplicated or bypassed admission", w.Code)
			}
			cookies := 0
			if post && mode == session.CredentialCookie {
				cookies = 1
			}
			if len(w.Result().Cookies()) != cookies {
				t.Fatal("router lost cookie custody")
			}
		}
		if observed != 2 {
			t.Fatal("hooks not attached to real authentication")
		}
	}
}

func TestRouterSessionRateAdmissionIsNotDuplicated(t *testing.T) {
	f := newLogout(t, session.CredentialBearer)
	feature, err := sessionhttp.NewFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	op := feature.Operations()[0]
	h, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Session", Version: "1"}}, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(f.fixture, true))
		want := 200
		if i == 100 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("canonical quota changed at request %d: %d", i+1, w.Code)
		}
	}
}
