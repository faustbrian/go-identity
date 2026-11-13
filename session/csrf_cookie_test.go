package session_test

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
)

func TestCSRFCookieDeliversReadableSynchronizerStateWithoutWeakeningSessionPolicy(t *testing.T) {
	for _, sameSite := range []http.SameSite{http.SameSiteLaxMode, http.SameSiteStrictMode} {
		configuration := session.CookieConfig{Name: "__Host-identity_csrf", SameSite: sameSite}
		csrf, err := session.NewCSRFCookiePolicy(configuration)
		if err != nil {
			t.Fatal(err)
		}
		authentication, err := session.NewCookiePolicy(configuration)
		if err != nil {
			t.Fatal(err)
		}
		for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
			remember, err := session.ResolveRememberPolicy(choice, config())
			if err != nil {
				t.Fatal(err)
			}
			issued := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
			now := issued.Add(time.Hour)
			expires := issued.Add(remember.AbsoluteTTL())
			cookie, err := csrf.Attributes(remember, now, expires)
			if err != nil || cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != sameSite || cookie.Value != "" || cookie.Partitioned {
				t.Fatal("unsafe or browser-inaccessible CSRF cookie", err)
			}
			original, err := authentication.Attributes(remember, now, expires)
			if err != nil || !original.HttpOnly {
				t.Fatal("synchronizer delivery weakened authentication cookie", err)
			}
			original.HttpOnly = false
			if !reflect.DeepEqual(cookie, original) {
				t.Fatal("CSRF cookie changed the original Remember lifetime or scope")
			}
			deleted, err := csrf.DeletionAttributes()
			if err != nil || deleted.Name != cookie.Name || deleted.Domain != cookie.Domain || deleted.Path != cookie.Path || deleted.HttpOnly || !deleted.Secure || deleted.SameSite != sameSite || deleted.Value != "" || deleted.MaxAge >= 0 || !deleted.Expires.Before(now) {
				t.Fatal("CSRF deletion did not retain its exact readable-cookie scope", err)
			}
			if _, err := csrf.Attributes(remember, expires, expires); !errors.Is(err, session.ErrExpired) {
				t.Fatal("expired CSRF delivery renewed the session lifetime")
			}
		}
	}
}

func TestCSRFCookieRejectsImplicitOrUnsafePolicy(t *testing.T) {
	for _, configuration := range []session.CookieConfig{{}, {Name: "identity_csrf", SameSite: http.SameSiteLaxMode}, {Name: "__Host-identity_csrf", SameSite: http.SameSiteNoneMode}} {
		if _, err := session.NewCSRFCookiePolicy(configuration); !errors.Is(err, session.ErrInvalidPolicy) {
			t.Fatal("unsafe synchronizer cookie enabled", err)
		}
	}
	if _, err := (session.CSRFCookiePolicy{}).DeletionAttributes(); !errors.Is(err, session.ErrInvalidPolicy) {
		t.Fatal("zero synchronizer cookie enabled")
	}
}
