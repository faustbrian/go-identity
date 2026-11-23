package session_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
)

func TestSAMLIDPConfirmationCookieSelectsOnlyCanonicalIDPInitiatedPaths(t *testing.T) {
	for _, path := range []string{
		"/saml2/a/idp-init",
		"/saml2/0/idp-init",
		"/saml2/Provider_01-test/idp-init",
		"/saml2/-AAAAAAAAAAAAAAAAAAAAA/idp-init",
		"/saml2/_AAAAAAAAAAAAAAAAAAAAA/idp-init",
		"/saml2/provider.example~v2/idp-init",
		"/saml2/" + strings.Repeat("a", 128) + "/idp-init",
	} {
		t.Run(path, func(t *testing.T) {
			policy, err := session.NewSAMLIDPConfirmationCookiePolicy(path)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
			cookie, err := policy.Attributes(now, now.Add(5*time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			assertFrontchannelCookieScope(t, cookie, path)
			if cookie.MaxAge != 300 || !cookie.Expires.Equal(now.Add(5*time.Minute)) {
				t.Fatalf("confirmation lifetime changed: MaxAge=%d Expires=%s", cookie.MaxAge, cookie.Expires)
			}

			spPolicy, err := session.NewFrontchannelCookiePolicy(path)
			if !errors.Is(err, session.ErrInvalidPolicy) || !reflect.DeepEqual(spPolicy, session.FrontchannelCookiePolicy{}) {
				t.Fatal("SP-initiated callback selector accepted the IdP-initiated route", err)
			}
		})
	}
}

func TestSAMLIDPConfirmationCookieRejectsUnselectedOrAliasedPaths(t *testing.T) {
	paths := map[string]string{
		"empty":                 "",
		"root":                  "/",
		"SP assertion consumer": "/saml2/provider/acs",
		"Apple form POST":       "/v1/oauth/callback/form-post",
		"SAML metadata":         "/saml2/provider/metadata",
		"SAML logout":           "/saml2/provider/slo",
		"absolute URL":          "https://identity.example/saml2/provider/idp-init",
		"missing leading slash": "saml2/provider/idp-init",
		"double leading slash":  "//saml2/provider/idp-init",
		"route case alias":      "/SAML2/provider/idp-init",
		"suffix case alias":     "/saml2/provider/IDP-init",
		"trailing slash":        "/saml2/provider/idp-init/",
		"extra suffix":          "/saml2/provider/idp-init/extra",
		"query":                 "/saml2/provider/idp-init?confirm=true",
		"empty query":           "/saml2/provider/idp-init?",
		"fragment":              "/saml2/provider/idp-init#confirm",
		"empty fragment":        "/saml2/provider/idp-init#",
		"encoded ASCII":         "/saml2/%70rovider/idp-init",
		"escaped suffix":        "/saml2/provider/%69dp-init",
		"escaped slash":         "/saml2/provider%2Fother/idp-init",
		"lower escaped slash":   "/saml2/provider%2fother/idp-init",
		"percent":               "/saml2/provider%/idp-init",
		"empty provider":        "/saml2//idp-init",
		"extra segment":         "/saml2/provider/other/idp-init",
		"dot provider":          "/saml2/./idp-init",
		"parent provider":       "/saml2/../idp-init",
		"wildcard":              "/saml2/*/idp-init",
		"template":              "/saml2/{provider_id}/idp-init",
		"space":                 "/saml2/provider name/idp-init",
		"semicolon":             "/saml2/provider;other/idp-init",
		"backslash":             "/saml2/provider\\other/idp-init",
		"unicode":               "/saml2/prövider/idp-init",
		"invalid UTF-8":         "/saml2/provider\xff/idp-init",
		"NUL":                   "/saml2/provider\x00/idp-init",
		"newline":               "/saml2/provider\n/idp-init",
		"tab":                   "/saml2/provider\t/idp-init",
		"DEL":                   "/saml2/provider\x7f/idp-init",
		"oversized provider":    "/saml2/" + strings.Repeat("a", 129) + "/idp-init",
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			policy, err := session.NewSAMLIDPConfirmationCookiePolicy(path)
			if !errors.Is(err, session.ErrInvalidPolicy) {
				t.Fatalf("unselected confirmation path accepted: %v", err)
			}
			if !reflect.DeepEqual(policy, session.FrontchannelCookiePolicy{}) {
				t.Fatal("invalid confirmation path returned a usable policy")
			}
		})
	}
}

func TestSAMLIDPConfirmationCookieKeepsOriginalExclusiveDeadline(t *testing.T) {
	policy, err := session.NewSAMLIDPConfirmationCookiePolicy("/saml2/provider/idp-init")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	originalExpires := now.Add(5 * time.Minute)
	for _, test := range []struct {
		name    string
		at      time.Time
		seconds int
		wantErr error
	}{
		{name: "initial maximum", at: now, seconds: 300},
		{name: "retry rounds down", at: now.Add(90*time.Second + 400*time.Millisecond), seconds: 209},
		{name: "last whole second", at: originalExpires.Add(-time.Second), seconds: 1},
		{name: "subsecond remainder", at: originalExpires.Add(-time.Second + time.Nanosecond), wantErr: session.ErrExpired},
		{name: "exact original deadline", at: originalExpires, wantErr: session.ErrExpired},
		{name: "after original deadline", at: originalExpires.Add(time.Nanosecond), wantErr: session.ErrExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			cookie, err := policy.Attributes(test.at, originalExpires)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) || !reflect.DeepEqual(cookie, http.Cookie{}) {
					t.Fatal("expired confirmation returned cookie attributes", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertFrontchannelCookieScope(t, cookie, "/saml2/provider/idp-init")
			wantExpires := test.at.Add(time.Duration(test.seconds) * time.Second)
			if cookie.MaxAge != test.seconds || !cookie.Expires.Equal(wantExpires) || cookie.Expires.After(originalExpires) {
				t.Fatalf("confirmation renewed its deadline: MaxAge=%d Expires=%s", cookie.MaxAge, cookie.Expires)
			}
		})
	}

	cookie, err := policy.Attributes(now, now.Add(5*time.Minute+time.Nanosecond))
	if !errors.Is(err, session.ErrInvalidTime) || !reflect.DeepEqual(cookie, http.Cookie{}) {
		t.Fatal("confirmation accepted a lifetime longer than five minutes", err)
	}
}

func TestSAMLIDPConfirmationCookieDeletionPreservesExactSerializedScope(t *testing.T) {
	const path = "/saml2/Provider_01-test/idp-init"
	policy, err := session.NewSAMLIDPConfirmationCookiePolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.FixedZone("offset", 2*60*60))
	issued, err := policy.Attributes(now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := policy.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	if deleted.MaxAge != -1 || !deleted.Expires.Equal(time.Unix(1, 0).UTC()) {
		t.Fatal("deletion did not expire the exact confirmation cookie")
	}
	for name, cookie := range map[string]http.Cookie{"issuance": issued, "deletion": deleted} {
		t.Run(name, func(t *testing.T) {
			assertFrontchannelCookieScope(t, cookie, path)
			if err := cookie.Valid(); err != nil {
				t.Fatal(err)
			}
			if cookie.Expires.Location() != time.UTC {
				t.Fatal("confirmation cookie expiry was not normalized to UTC")
			}
			recorder := httptest.NewRecorder()
			http.SetCookie(recorder, &cookie)
			response := recorder.Result()
			defer response.Body.Close()
			parsed := response.Cookies()
			if len(parsed) != 1 {
				t.Fatalf("want one serialized confirmation cookie, got %d", len(parsed))
			}
			assertFrontchannelCookieScope(t, *parsed[0], path)
			if parsed[0].MaxAge != cookie.MaxAge || !parsed[0].Expires.Equal(cookie.Expires) || len(parsed[0].Unparsed) != 0 {
				t.Fatal("serialization changed confirmation cookie lifetime or scope")
			}
		})
	}
	unchanged, err := policy.Attributes(now, now.Add(time.Minute))
	if err != nil || !reflect.DeepEqual(unchanged, issued) {
		t.Fatal("deletion attribute calculation mutated the confirmation policy", err)
	}
}
