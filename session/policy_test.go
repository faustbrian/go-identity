package session_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
)

func config() session.LifetimeConfig {
	return session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: 7 * 24 * time.Hour, IdleTTL: 24 * time.Hour, RefreshAfter: 12 * time.Hour, FreshFor: 24 * time.Hour}
}

func TestRememberChoiceResolvedOnce(t *testing.T) {
	c := config()
	p, err := session.ResolveRememberPolicy(session.RememberDefault, c)
	if err != nil || p.Choice() != session.PersistentSession || p.AbsoluteTTL() != 7*24*time.Hour {
		t.Fatalf("persistent default: %v", err)
	}
	p, err = session.ResolveRememberPolicy(session.BrowserSession, c)
	if err != nil || p.Choice() != session.BrowserSession || p.AbsoluteTTL() != 24*time.Hour {
		t.Fatalf("browser choice: %v", err)
	}
	// A continued authentication carries the resolved value, not a new default.
	c.Default = session.PersistentSession
	if p.Choice() != session.BrowserSession || p.AbsoluteTTL() != 24*time.Hour {
		t.Fatal("resolved policy changed")
	}
	c.Default = session.BrowserSession
	p, err = session.ResolveRememberPolicy(session.RememberDefault, c)
	if err != nil || p.Choice() != session.BrowserSession {
		t.Fatal("browser default ignored")
	}
	for _, change := range []func(*session.LifetimeConfig){
		func(c *session.LifetimeConfig) { c.Default = session.RememberDefault },
		func(c *session.LifetimeConfig) { c.AbsoluteTTL = 0 },
		func(c *session.LifetimeConfig) { c.AbsoluteTTL = 31 * 24 * time.Hour },
		func(c *session.LifetimeConfig) { c.IdleTTL = 4 * time.Minute },
		func(c *session.LifetimeConfig) { c.IdleTTL = c.AbsoluteTTL + time.Second },
		func(c *session.LifetimeConfig) { c.RefreshAfter = 0 },
		func(c *session.LifetimeConfig) { c.RefreshAfter = c.IdleTTL + time.Second },
		func(c *session.LifetimeConfig) { c.FreshFor = 14 * time.Minute },
		func(c *session.LifetimeConfig) { c.FreshFor = 25 * time.Hour },
	} {
		bad := config()
		change(&bad)
		if _, e := session.ResolveRememberPolicy(session.BrowserSession, bad); !errors.Is(e, session.ErrInvalidPolicy) {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, e := session.ResolveRememberPolicy(session.RememberChoice(99), config()); !errors.Is(e, session.ErrInvalidPolicy) {
		t.Fatal("invalid choice accepted")
	}
	if _, e := (session.RememberPolicy{}).Evaluate(time.Now(), time.Now(), time.Now(), time.Now()); !errors.Is(e, session.ErrInvalidPolicy) {
		t.Fatal("zero policy accepted")
	}
}

func TestLifetimeNeverExtendsAbsoluteOrAuthenticationTime(t *testing.T) {
	p, _ := session.ResolveRememberPolicy(session.PersistentSession, config())
	issued := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	state, e := p.Evaluate(issued.Add(13*time.Hour), issued, issued.Add(12*time.Hour), issued)
	if e != nil || state.AbsoluteExpiresAt != issued.Add(7*24*time.Hour) || state.ExpiresAt != issued.Add(36*time.Hour) || state.RefreshDue || !state.Fresh {
		t.Fatalf("unexpected lifetime: %+v %v", state, e)
	}
	state, e = p.Evaluate(issued.Add(12*time.Hour), issued, issued, issued)
	if e != nil || !state.RefreshDue {
		t.Fatal("refresh equality ignored")
	}
	state, e = p.Evaluate(issued.Add(24*time.Hour), issued, issued.Add(23*time.Hour), issued)
	if e != nil || state.Fresh {
		t.Fatal("freshness renewed by activity")
	}
	for _, at := range []time.Time{issued.Add(24 * time.Hour), issued.Add(7 * 24 * time.Hour)} {
		if _, e = p.Evaluate(at, issued, issued, issued); !errors.Is(e, session.ErrExpired) {
			t.Fatal("expired session accepted")
		}
	}
	state, e = p.Evaluate(issued.Add(7*24*time.Hour-time.Hour), issued, issued.Add(7*24*time.Hour-2*time.Hour), issued)
	if e != nil || state.ExpiresAt != state.AbsoluteExpiresAt {
		t.Fatal("idle expiry exceeded absolute")
	}
	for _, times := range [][4]time.Time{
		{time.Time{}, issued, issued, issued}, {issued.Add(-time.Second), issued, issued, issued},
		{issued, issued, issued.Add(time.Second), issued}, {issued, issued, issued, issued.Add(time.Second)},
		{issued, issued, issued.Add(-time.Second), issued},
		{issued, issued.AddDate(10000, 0, 0), issued, issued},
		{time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)},
	} {
		if _, e = p.Evaluate(times[0], times[1], times[2], times[3]); !errors.Is(e, session.ErrInvalidTime) {
			t.Fatal("invalid timeline accepted")
		}
	}
}

func TestPolicyCapsDoNotEnlargeSelectedLifetime(t *testing.T) {
	c := config()
	c.IdleTTL = 48 * time.Hour
	c.RefreshAfter = 36 * time.Hour
	p, e := session.ResolveRememberPolicy(session.BrowserSession, c)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s, e := p.Evaluate(now, now, now, now)
	if e != nil || s.ExpiresAt != now.Add(24*time.Hour) {
		t.Fatal("browser cap lost")
	}
	c.AbsoluteTTL = time.Hour
	c.IdleTTL = time.Hour
	c.RefreshAfter = time.Hour
	p, e = session.ResolveRememberPolicy(session.BrowserSession, c)
	if e != nil || p.AbsoluteTTL() != time.Hour {
		t.Fatal("short browser policy enlarged")
	}
	c = config()
	c.AbsoluteTTL = 30 * 24 * time.Hour
	p, _ = session.ResolveRememberPolicy(session.PersistentSession, c)
	cp, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	a, e := cp.Attributes(p, now, now.Add(8*24*time.Hour))
	if e != nil || a.MaxAge != 7*24*60*60 || a.Expires != now.Add(7*24*time.Hour) {
		t.Fatal("persistent cookie cap lost")
	}
	if _, e = cp.Attributes(p, now, time.Time{}); !errors.Is(e, session.ErrInvalidTime) {
		t.Fatal("zero expiry accepted")
	}
}

func TestLifetimeRetainsAuthenticationCompletedBeforeIssuance(t *testing.T) {
	p, _ := session.ResolveRememberPolicy(session.BrowserSession, config())
	issued := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	authenticated := issued.Add(-time.Minute)
	now := authenticated.Add(24 * time.Hour)
	got, err := p.Evaluate(now, issued, issued, authenticated)
	if err != nil || got.Fresh || got.AbsoluteExpiresAt != issued.Add(24*time.Hour) {
		t.Fatal("issuance must not renew proof freshness", err)
	}
}

func FuzzCookiePolicy(f *testing.F) {
	for _, name := range []string{"__Host-session", "__Host-", "__Host-x\r\n", "__Host-x;", "__Host-é"} {
		f.Add(name, uint8(http.SameSiteLaxMode))
	}
	f.Fuzz(func(t *testing.T, name string, mode uint8) {
		p, e := session.NewCookiePolicy(session.CookieConfig{Name: name, SameSite: http.SameSite(mode)})
		if e != nil {
			if !errors.Is(e, session.ErrInvalidPolicy) {
				t.Fatal("unstable error")
			}
			return
		}
		a, e := p.DeletionAttributes()
		if e != nil || a.Valid() != nil || a.Name != name || !a.Secure || !a.HttpOnly || a.Domain != "" || a.Path != "/" || a.Partitioned {
			t.Fatal("accepted unsafe attributes")
		}
	})
}

func TestCookieAttributesFollowResolvedPolicy(t *testing.T) {
	c, e := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := session.ResolveRememberPolicy(session.PersistentSession, config())
	a, e := c.Attributes(p, now, now.Add(2*time.Hour+900*time.Millisecond))
	if e != nil || a.MaxAge != 7200 || a.Expires.After(now.Add(2*time.Hour)) || a.Path != "/" || a.Domain != "" || !a.Secure || !a.HttpOnly || a.Partitioned || a.SameSite != http.SameSiteLaxMode {
		t.Fatalf("persistent attributes: %+v %v", a, e)
	}
	p, _ = session.ResolveRememberPolicy(session.BrowserSession, config())
	a, e = c.Attributes(p, now, now.Add(time.Hour))
	if e != nil || a.MaxAge != 0 || !a.Expires.IsZero() {
		t.Fatal("browser cookie persisted")
	}
	for _, expiry := range []time.Time{now, now.Add(-time.Second), now.Add(500 * time.Millisecond)} {
		if _, e = c.Attributes(p, now, expiry); !errors.Is(e, session.ErrExpired) {
			t.Fatal("unusable lifetime accepted")
		}
	}
	if _, e = c.Attributes(session.RememberPolicy{}, now, now.Add(time.Hour)); !errors.Is(e, session.ErrInvalidPolicy) {
		t.Fatal("zero remember policy accepted")
	}
	if _, e = (session.CookiePolicy{}).Attributes(p, now, now.Add(time.Hour)); !errors.Is(e, session.ErrInvalidPolicy) {
		t.Fatal("zero cookie policy accepted")
	}
	if _, e = c.Attributes(p, time.Time{}, now); !errors.Is(e, session.ErrInvalidTime) {
		t.Fatal("zero time accepted")
	}
	if _, e = c.Attributes(p, now, now.Add(25*time.Hour)); !errors.Is(e, session.ErrInvalidTime) {
		t.Fatal("browser cap exceeded")
	}
	clear, e := c.DeletionAttributes()
	if e != nil || clear.MaxAge != -1 || clear.Expires.After(now) || !clear.Secure || !clear.HttpOnly {
		t.Fatal("unsafe deletion")
	}
	if _, e = (session.CookiePolicy{}).DeletionAttributes(); !errors.Is(e, session.ErrInvalidPolicy) {
		t.Fatal("zero deletion accepted")
	}
	for _, bad := range []session.CookieConfig{
		{Name: "identity_session", SameSite: http.SameSiteLaxMode}, {Name: "__Host-", SameSite: http.SameSiteLaxMode},
		{Name: "__Host-injected\r\n", SameSite: http.SameSiteLaxMode}, {Name: "__Host-x", SameSite: http.SameSiteNoneMode},
		{Name: "__Host-x", SameSite: http.SameSiteDefaultMode},
	} {
		if _, e = session.NewCookiePolicy(bad); !errors.Is(e, session.ErrInvalidPolicy) {
			t.Fatal("unsafe cookie config accepted")
		}
	}
	if _, e = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-strict", SameSite: http.SameSiteStrictMode}); e != nil {
		t.Fatal(e)
	}
}

func TestPersistentCookieAndServerIdleHaveDistinctDeadlines(t *testing.T) {
	p, _ := session.ResolveRememberPolicy(session.PersistentSession, config())
	c, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	lifetime, e := p.Evaluate(now, now, now, now)
	if e != nil {
		t.Fatal(e)
	}
	a, e := c.Attributes(p, now, lifetime.AbsoluteExpiresAt)
	if e != nil || a.MaxAge != 604800 || lifetime.ExpiresAt != now.Add(24*time.Hour) || a.Expires != now.Add(7*24*time.Hour) {
		t.Fatal("cookie persistence confused with server idle expiry")
	}
	if _, e = p.Evaluate(now.Add(24*time.Hour), now, now, now); !errors.Is(e, session.ErrExpired) {
		t.Fatal("persistent cookie bypassed idle expiry")
	}
}
