package sessionhttp_test

import (
	"net/http"
	"testing"

	identity "github.com/faustbrian/go-identity"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

func TestSignoutClearsSelectedCSRFCookieOnlyAfterNativeSuccess(t *testing.T) {
	for _, scenario := range []string{"active", "absent", "wrong-csrf", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			f := newLogout(t, session.CredentialCookie)
			csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
			if err != nil {
				t.Fatal(err)
			}
			f.config.CSRFCookie = &csrf
			r := logoutRequest(f, scenario != "absent")
			if scenario == "wrong-csrf" {
				r.Header.Set("X-CSRF-Token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			}
			if scenario == "unknown" {
				f.outcome = identity.CommitOutcomeUnknown
			}
			w := logoutServe(t, f, r)
			response := w.Result()
			defer response.Body.Close()
			cookies := response.Cookies()
			if scenario == "wrong-csrf" || scenario == "unknown" {
				if w.Code < 400 || len(cookies) != 0 {
					t.Fatal("failed or uncertain logout cleared browser custody", w.Code)
				}
				if scenario == "wrong-csrf" && f.executions != 0 {
					t.Fatal("wrong synchronizer token reached mutation")
				}
				return
			}
			if w.Code != 200 || len(cookies) != 2 {
				t.Fatal("successful logout did not clear both selected cookies", w.Code, len(cookies))
			}
			if cookies[0].Name == cookies[1].Name {
				t.Fatal("cookie deletion scopes collided")
			}
			for _, cookie := range cookies {
				if cookie.Value != "" || cookie.MaxAge >= 0 || !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" {
					t.Fatal("unsafe logout deletion tuple")
				}
				if cookie.HttpOnly == (cookie.Name == "__Host-identity_csrf") {
					t.Fatal("authentication and readable synchronizer scopes were confused")
				}
			}
		})
	}
}

func TestSignoutRejectsCSRFCookieOnBearerOrCollidingScope(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newLogout(t, mode)
		csrf, _ := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
		if mode == session.CredentialCookie {
			authentication, _ := f.config.Cookie.DeletionAttributes()
			csrf, _ = session.NewCSRFCookiePolicy(session.CookieConfig{Name: authentication.Name, SameSite: authentication.SameSite})
		}
		f.config.CSRFCookie = &csrf
		if h, err := sessionhttp.NewSignOutHandler(f.config); h != nil || err == nil {
			t.Fatal("invalid synchronizer cleanup selection enabled")
		}
	}
}
