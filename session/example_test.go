package session_test

import (
	"fmt"
	"github.com/faustbrian/go-identity/session"
	"net/http"
	"time"
)

func ExampleResolveRememberPolicy() {
	policy, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{
		Default: session.PersistentSession, AbsoluteTTL: 7 * 24 * time.Hour,
		IdleTTL: 24 * time.Hour, RefreshAfter: 12 * time.Hour, FreshFor: 24 * time.Hour,
	})
	if err != nil {
		panic(err)
	}
	// Retain this resolved value unchanged through any MFA continuation.
	cookies, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	lifetime, err := policy.Evaluate(now, now, now, now)
	if err != nil {
		panic(err)
	}
	attributes, err := cookies.Attributes(policy, now, lifetime.AbsoluteExpiresAt)
	if err != nil {
		panic(err)
	}
	// Value is empty: this example issues no credential.
	fmt.Println(policy.AbsoluteTTL(), attributes.MaxAge, attributes.Expires.IsZero())
	// Output: 24h0m0s 0 true
}
