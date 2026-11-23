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

func TestFrontchannelCookieAcceptsOnlySelectedCanonicalCallbackPaths(t *testing.T) {
	for _, path := range []string{
		"/v1/oauth/callback/form-post",
		"/saml2/a/acs",
		"/saml2/0/acs",
		"/saml2/Provider_01-test/acs",
		"/saml2/-AAAAAAAAAAAAAAAAAAAAA/acs",
		"/saml2/_AAAAAAAAAAAAAAAAAAAAA/acs",
		"/saml2/provider.example~v2/acs",
		"/saml2/" + strings.Repeat("a", 128) + "/acs",
	} {
		t.Run(path, func(t *testing.T) {
			policy, err := session.NewFrontchannelCookiePolicy(path)
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
				t.Fatalf("five-minute lifetime changed: MaxAge=%d Expires=%s", cookie.MaxAge, cookie.Expires)
			}
		})
	}
}

func TestFrontchannelCookieRejectsNoncanonicalOrUnselectedPaths(t *testing.T) {
	paths := map[string]string{
		"empty":                 "",
		"root":                  "/",
		"normal oauth callback": "/v1/oauth/callback",
		"saml metadata":         "/saml2/provider/metadata",
		"saml logout":           "/saml2/provider/slo",
		"absolute URL":          "https://identity.example/v1/oauth/callback/form-post",
		"missing leading slash": "v1/oauth/callback/form-post",
		"double leading slash":  "//v1/oauth/callback/form-post",
		"trailing slash":        "/v1/oauth/callback/form-post/",
		"extra suffix":          "/saml2/provider/acs/extra",
		"query":                 "/v1/oauth/callback/form-post?provider=apple",
		"empty query":           "/saml2/provider/acs?",
		"fragment":              "/saml2/provider/acs#callback",
		"empty fragment":        "/v1/oauth/callback/form-post#",
		"encoded ASCII":         "/saml2/%70rovider/acs",
		"escaped slash":         "/saml2/provider%2Fother/acs",
		"lower escaped slash":   "/saml2/provider%2fother/acs",
		"percent":               "/saml2/provider%/acs",
		"empty provider":        "/saml2//acs",
		"extra segment":         "/saml2/provider/other/acs",
		"dot provider":          "/saml2/./acs",
		"parent provider":       "/saml2/../acs",
		"wildcard":              "/saml2/*/acs",
		"template":              "/saml2/{provider_id}/acs",
		"space":                 "/saml2/provider name/acs",
		"semicolon":             "/saml2/provider;other/acs",
		"backslash":             "/saml2/provider\\other/acs",
		"unicode":               "/saml2/prövider/acs",
		"invalid UTF-8":         "/saml2/provider\xff/acs",
		"NUL":                   "/saml2/provider\x00/acs",
		"newline":               "/saml2/provider\n/acs",
		"tab":                   "/saml2/provider\t/acs",
		"DEL":                   "/saml2/provider\x7f/acs",
		"oversized provider":    "/saml2/" + strings.Repeat("a", 129) + "/acs",
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			policy, err := session.NewFrontchannelCookiePolicy(path)
			if !errors.Is(err, session.ErrInvalidPolicy) {
				t.Fatalf("unselected callback path accepted: %v", err)
			}
			if !reflect.DeepEqual(policy, session.FrontchannelCookiePolicy{}) {
				t.Fatal("invalid callback returned a usable policy")
			}
		})
	}
}

func TestFrontchannelCookieLifetimeRoundsDownWithoutRenewal(t *testing.T) {
	policy, err := session.NewFrontchannelCookiePolicy("/v1/oauth/callback/form-post")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		remaining time.Duration
		seconds   int
	}{
		{name: "maximum", remaining: 5 * time.Minute, seconds: 300},
		{name: "fraction below maximum", remaining: 5*time.Minute - time.Nanosecond, seconds: 299},
		{name: "whole second", remaining: time.Second, seconds: 1},
		{name: "fraction above second", remaining: time.Second + 999*time.Millisecond, seconds: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			expires := now.Add(test.remaining)
			cookie, err := policy.Attributes(now, expires)
			if err != nil {
				t.Fatal(err)
			}
			assertFrontchannelCookieScope(t, cookie, "/v1/oauth/callback/form-post")
			wantExpires := now.Add(time.Duration(test.seconds) * time.Second)
			if cookie.MaxAge != test.seconds || !cookie.Expires.Equal(wantExpires) || cookie.Expires.After(expires) {
				t.Fatalf("remaining lifetime was not rounded down: MaxAge=%d Expires=%s", cookie.MaxAge, cookie.Expires)
			}
		})
	}

	originalExpires := now.Add(5 * time.Minute)
	first, err := policy.Attributes(now, originalExpires)
	if err != nil {
		t.Fatal(err)
	}
	retryAt := now.Add(90*time.Second + 400*time.Millisecond)
	retry, err := policy.Attributes(retryAt, originalExpires)
	if err != nil {
		t.Fatal(err)
	}
	if retry.MaxAge != 209 || retry.Expires.After(originalExpires) || retry.Expires.After(first.Expires) {
		t.Fatal("retry refreshed the original correlation lifetime")
	}
	repeated, err := policy.Attributes(retryAt, originalExpires)
	if err != nil || !reflect.DeepEqual(repeated, retry) {
		t.Fatal("attribute calculation changed the policy or original lifetime", err)
	}
	cookie, err := policy.Attributes(originalExpires, originalExpires)
	if !errors.Is(err, session.ErrExpired) || !reflect.DeepEqual(cookie, http.Cookie{}) {
		t.Fatal("retry at original expiry renewed the cookie", err)
	}
}

func TestFrontchannelCookieRejectsInvalidOrExpiredTimesWithoutAttributes(t *testing.T) {
	policy, err := session.NewFrontchannelCookiePolicy("/saml2/provider/acs")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		now     time.Time
		expires time.Time
		wantErr error
	}{
		{name: "zero now", expires: now.Add(time.Minute), wantErr: session.ErrInvalidTime},
		{name: "zero expiry", now: now, wantErr: session.ErrInvalidTime},
		{name: "invalid now year", now: time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), expires: now, wantErr: session.ErrInvalidTime},
		{name: "invalid expiry year", now: now, expires: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), wantErr: session.ErrInvalidTime},
		{name: "over maximum", now: now, expires: now.Add(5*time.Minute + time.Nanosecond), wantErr: session.ErrInvalidTime},
		{name: "expired", now: now, expires: now.Add(-time.Second), wantErr: session.ErrExpired},
		{name: "at expiry", now: now, expires: now, wantErr: session.ErrExpired},
		{name: "less than one second", now: now, expires: now.Add(time.Second - time.Nanosecond), wantErr: session.ErrExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			cookie, err := policy.Attributes(test.now, test.expires)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("want %v, got %v", test.wantErr, err)
			}
			if !reflect.DeepEqual(cookie, http.Cookie{}) {
				t.Fatal("failed lifetime validation returned cookie attributes")
			}
		})
	}
}

func TestFrontchannelCookieZeroPolicyFailsClosed(t *testing.T) {
	var policy session.FrontchannelCookiePolicy
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	cookie, err := policy.Attributes(now, now.Add(time.Minute))
	if !errors.Is(err, session.ErrInvalidPolicy) || !reflect.DeepEqual(cookie, http.Cookie{}) {
		t.Fatal("zero policy returned issuance attributes", err)
	}
	cookie, err = policy.DeletionAttributes()
	if !errors.Is(err, session.ErrInvalidPolicy) || !reflect.DeepEqual(cookie, http.Cookie{}) {
		t.Fatal("zero policy returned deletion attributes", err)
	}
}

func TestFrontchannelCookieSerializationAndDeletionRetainExactScope(t *testing.T) {
	for _, path := range []string{"/v1/oauth/callback/form-post", "/saml2/Provider_01-test/acs"} {
		t.Run(path, func(t *testing.T) {
			policy, err := session.NewFrontchannelCookiePolicy(path)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.FixedZone("offset", 2*60*60))
			cookie, err := policy.Attributes(now, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			deleted, err := policy.DeletionAttributes()
			if err != nil {
				t.Fatal(err)
			}
			for name, attributes := range map[string]http.Cookie{"issuance": cookie, "deletion": deleted} {
				t.Run(name, func(t *testing.T) {
					assertFrontchannelCookieScope(t, attributes, path)
					if err := attributes.Valid(); err != nil {
						t.Fatalf("invalid runtime cookie: %v", err)
					}
					recorder := httptest.NewRecorder()
					http.SetCookie(recorder, &attributes)
					response := recorder.Result()
					defer response.Body.Close()
					parsed := response.Cookies()
					if len(parsed) != 1 {
						t.Fatalf("want one serialized cookie, got %d", len(parsed))
					}
					assertFrontchannelCookieScope(t, *parsed[0], path)
					if parsed[0].MaxAge != attributes.MaxAge || !parsed[0].Expires.Equal(attributes.Expires) || len(parsed[0].Unparsed) != 0 {
						t.Fatal("net/http roundtrip changed cookie lifetime or attributes")
					}
				})
			}
			if deleted.MaxAge >= 0 || deleted.Expires.IsZero() || !deleted.Expires.Before(now) {
				t.Fatal("deletion did not expire the exact selected cookie")
			}
			if cookie.Expires.Location() != time.UTC {
				t.Fatal("frontchannel cookie expiry was not normalized to UTC")
			}
		})
	}
}

func TestFrontchannelCookieDoesNotWeakenNormalSessionCookiePolicy(t *testing.T) {
	for _, configuration := range []session.CookieConfig{
		{Name: "__Host-identity_session", SameSite: http.SameSiteNoneMode},
		{Name: "__Secure-identity_frontchannel", SameSite: http.SameSiteLaxMode},
	} {
		if _, err := session.NewCookiePolicy(configuration); !errors.Is(err, session.ErrInvalidPolicy) {
			t.Fatal("normal session policy accepted cross-site correlation scope", err)
		}
	}
	remember, err := session.ResolveRememberPolicy(session.PersistentSession, config())
	if err != nil {
		t.Fatal(err)
	}
	for _, sameSite := range []http.SameSite{http.SameSiteLaxMode, http.SameSiteStrictMode} {
		policy, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: sameSite})
		if err != nil {
			t.Fatal(err)
		}
		now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
		cookie, err := policy.Attributes(remember, now, now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if cookie.Name != "__Host-identity_session" || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != sameSite || cookie.Partitioned || cookie.Value != "" || cookie.MaxAge != 3600 {
			t.Fatal("frontchannel profile changed normal session attributes")
		}
	}
}

func assertFrontchannelCookieScope(t *testing.T, cookie http.Cookie, path string) {
	t.Helper()
	if cookie.Name != "__Secure-identity_frontchannel" || cookie.Value != "" || cookie.Path != path || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || cookie.Partitioned {
		t.Fatal("cookie does not have the exact credential-free frontchannel scope")
	}
}
