package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestCookieCacheWireRetainsOriginalCredentialAndDeadline(t *testing.T) {
	codec, request, clock, _, _, _, _, original, _ := encryptedFixture(t)
	credentialPolicy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	cachePolicy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_cache", SameSite: http.SameSiteLaxMode})
	cache, e := session.NewCookieCache(codec, session.CookieCacheConfig{Credential: credentialPolicy, Cache: cachePolicy, MaximumCookieBytes: 3800})
	if e != nil {
		t.Fatal(e)
	}
	cookie, e := cache.Put(context.Background(), original)
	if e != nil {
		t.Fatal(e)
	}
	header, e := cookie.HeaderValue()
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := http.ParseSetCookie(header)
	if e != nil || parsed.Name != "__Host-identity_cache" || parsed.MaxAge != 0 || !parsed.Expires.IsZero() || len(header) > 3800 || !parsed.Secure || !parsed.HttpOnly || parsed.Path != "/" || parsed.Domain != "" || parsed.SameSite != http.SameSiteLaxMode || !strings.HasSuffix(header, "; Priority=High") {
		t.Fatal("unsafe cache header", e)
	}
	got, e := cache.Get(context.Background(), request, []string{parsed.Value})
	if e != nil || !got.Authenticated || !got.ValidUntil().Equal(original.ValidUntil()) {
		t.Fatal("wire roundtrip renewed custody", e)
	}
	clock.now = original.ValidUntil()
	denied, e := cache.Get(context.Background(), request, []string{parsed.Value})
	if e != nil || denied.Authenticated {
		t.Fatal("expired cache source accepted", e)
	}
}

type cacheKeyProvider struct {
	inner  envelope.KeyProvider
	before func(context.Context) error
}

func (p cacheKeyProvider) GenerateDataKey(ctx context.Context, reference string, aad envelope.Context) (envelope.DataKey, error) {
	if e := p.before(ctx); e != nil {
		return envelope.DataKey{}, e
	}
	return p.inner.GenerateDataKey(ctx, reference, aad)
}
func (p cacheKeyProvider) DecryptDataKey(ctx context.Context, reference string, wrapped []byte, aad envelope.Context) ([]byte, error) {
	return p.inner.DecryptDataKey(ctx, reference, wrapped, aad)
}

func TestCookieCacheLatencyLifetimeAndProviderDeadline(t *testing.T) {
	for _, scenario := range []string{"latency", "near-expiry", "fractional-expiry", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			service, request, clock, observed, serviceConfig, reader := validationFixture(t)
			spec, _ := observed.Session.Bindings()
			spec.Remember, _ = session.ResolveRememberPolicy(session.PersistentSession, config())
			observed.Session, _ = session.NewSession(spec)
			if scenario == "near-expiry" || scenario == "fractional-expiry" {
				lifetime, _ := observed.Session.Lifetime(clock.now)
				remaining := 150 * time.Second
				if scenario == "fractional-expiry" {
					remaining = 500 * time.Millisecond
				}
				clock.now = lifetime.ExpiresAt.Add(-remaining)
				observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
			}
			if scenario == "deadline" {
				serviceConfig.MaximumDuration = 10 * time.Millisecond
				service, _ = session.NewSessionService(reader, serviceConfig)
			}
			result, e := service.Get(context.Background(), request)
			if e != nil || !result.Authenticated {
				t.Fatal("fixture get", e)
			}
			started := clock.now
			keys, _ := keyring.New(map[string][]byte{"cache-v1": make([]byte, 32)})
			provider := cacheKeyProvider{inner: keys, before: func(ctx context.Context) error {
				if scenario == "latency" {
					clock.now = clock.now.Add(4 * time.Second)
				}
				if scenario == "deadline" {
					<-ctx.Done()
					return ctx.Err()
				}
				return nil
			}}
			crypto, _ := envelope.NewService(provider)
			codec, _ := session.NewEncryptedCacheCodec(service, crypto, session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache-v1", MaximumAge: 5 * time.Minute, MaximumBytes: 32768})
			credential, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteStrictMode})
			companion, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_cache", SameSite: http.SameSiteStrictMode})
			cache, _ := session.NewCookieCache(codec, session.CookieCacheConfig{Credential: credential, Cache: companion, MaximumCookieBytes: 3800})
			out, e := cache.Put(context.Background(), result)
			if scenario == "deadline" {
				var deadline identity.DeadlineExceededError
				if !errors.As(e, &deadline) {
					t.Fatal("provider deadline swallowed", e)
				}
				if wire, e := out.HeaderValue(); e == nil || wire != "" {
					t.Fatal("deadline emitted header")
				}
				return
			}
			if scenario == "fractional-expiry" {
				if e != session.ErrExpired {
					t.Fatal("fraction became browser cookie", e)
				}
				if wire, e := out.HeaderValue(); e == nil || wire != "" {
					t.Fatal("fraction emitted header")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			wire, _ := out.HeaderValue()
			parsed, _ := http.ParseSetCookie(wire)
			expected := 296
			if scenario == "near-expiry" {
				expected = 150
			}
			if parsed.MaxAge != expected || parsed.SameSite != http.SameSiteStrictMode {
				t.Fatal("wrong remaining lifetime or strict policy")
			}
			expectedExpiry := started.Add(5 * time.Minute)
			if scenario == "near-expiry" {
				expectedExpiry = started.Add(150 * time.Second)
			}
			if !parsed.Expires.Equal(expectedExpiry) {
				t.Fatal("latency or session expiry extended persistence")
			}
			got, e := cache.Get(context.Background(), request, []string{parsed.Value})
			if e != nil || !got.Authenticated || !got.ValidUntil().Equal(result.ValidUntil()) {
				t.Fatal("cookie changed original validity", e)
			}
		})
	}
}

func browserCacheFixture(t *testing.T, choice session.RememberChoice) (*session.CookieCache, *session.EncryptedCacheCodec, session.GetRequest, *mutableIssueClock, *session.SessionObservation, session.ServiceConfig, session.EncryptedCacheConfig, session.GetResult) {
	t.Helper()
	codec, request, clock, observed, serviceConfig, _, profile, _, _ := encryptedFixture(t)
	spec, _ := observed.Session.Bindings()
	var e error
	spec.Remember, e = session.ResolveRememberPolicy(choice, config())
	if e != nil {
		t.Fatal(e)
	}
	observed.Session, e = session.NewSession(spec)
	if e != nil {
		t.Fatal(e)
	}
	result, e := codec.Get(context.Background(), request, nil)
	if e != nil || !result.Authenticated {
		t.Fatal("fixture admission", e)
	}
	credential, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	companion, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_cache", SameSite: http.SameSiteLaxMode})
	cache, e := session.NewCookieCache(codec, session.CookieCacheConfig{Credential: credential, Cache: companion, MaximumCookieBytes: 3800})
	if e != nil {
		t.Fatal(e)
	}
	return cache, codec, request, clock, observed, serviceConfig, profile, result
}

func TestCookieCachePersistentSizeBoundaryAndDeletion(t *testing.T) {
	cache, codec, _, clock, _, _, _, result := browserCacheFixture(t, session.PersistentSession)
	out, e := cache.Put(context.Background(), result)
	if e != nil {
		t.Fatal(e)
	}
	header, _ := out.HeaderValue()
	parsed, e := http.ParseSetCookie(header)
	if e != nil || parsed.MaxAge != 300 || !parsed.Expires.Equal(clock.now.Add(5*time.Minute)) {
		t.Fatal("persistent deadline", e)
	}
	credential, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	companion, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_cache", SameSite: http.SameSiteLaxMode})
	exact, e := session.NewCookieCache(codec, session.CookieCacheConfig{Credential: credential, Cache: companion, MaximumCookieBytes: len(header)})
	if e != nil {
		t.Fatal(e)
	}
	same, e := exact.Put(context.Background(), result)
	if e != nil {
		t.Fatal("exact limit", e)
	}
	value, _ := same.HeaderValue()
	if len(value) != len(header) {
		t.Fatal("encoded boundary changed")
	}
	smaller, _ := session.NewCookieCache(codec, session.CookieCacheConfig{Credential: credential, Cache: companion, MaximumCookieBytes: len(header) - 1})
	bad, e := smaller.Put(context.Background(), result)
	if e != session.ErrInvalidInput {
		t.Fatal("oversized header accepted", e)
	}
	if value, e := bad.HeaderValue(); e != session.ErrInvalidInput || value != "" {
		t.Fatal("oversize leaked header")
	}
	deleted, e := cache.Deletion()
	if e != nil {
		t.Fatal(e)
	}
	deletion, _ := deleted.HeaderValue()
	gone, e := http.ParseSetCookie(deletion)
	if e != nil || gone.Name != parsed.Name || gone.Path != parsed.Path || gone.Domain != parsed.Domain || gone.SameSite != parsed.SameSite || !gone.Secure || !gone.HttpOnly || gone.MaxAge != -1 || gone.Value != "" || !gone.Expires.Before(clock.now) || !strings.HasSuffix(deletion, "; Priority=High") {
		t.Fatal("unsafe deletion", e)
	}
	// Removing a companion header does not mutate server admission or authority.
	if result.ValidateAt(clock.now) != nil {
		t.Fatal("deletion changed authority")
	}
}

func TestCookieCacheJarRoundTripAndHostIsolation(t *testing.T) {
	cache, _, request, _, _, _, _, result := browserCacheFixture(t, session.BrowserSession)
	cookie, e := cache.Put(context.Background(), result)
	if e != nil {
		t.Fatal(e)
	}
	header, _ := cookie.HeaderValue()
	parsed, _ := http.ParseSetCookie(header)
	jar, e := cookiejar.New(nil)
	if e != nil {
		t.Fatal(e)
	}
	origin, _ := url.Parse("https://identity.example.test/")
	jar.SetCookies(origin, []*http.Cookie{parsed})
	cookies := jar.Cookies(origin)
	if len(cookies) != 1 || cookies[0].Name != parsed.Name {
		t.Fatal("secure browser jar lost companion")
	}
	insecure, _ := url.Parse("http://identity.example.test/")
	foreign, _ := url.Parse("https://other.example.test/")
	subdomain, _ := url.Parse("https://sub.identity.example.test/")
	for _, site := range []*url.URL{insecure, foreign, subdomain} {
		if len(jar.Cookies(site)) != 0 {
			t.Fatal("host or secure scope widened")
		}
	}
	got, e := cache.Get(context.Background(), request, []string{cookies[0].Value})
	if e != nil || !got.Authenticated {
		t.Fatal("jar wire failed", e)
	}
	deleted, _ := cache.Deletion()
	wire, _ := deleted.HeaderValue()
	gone, _ := http.ParseSetCookie(wire)
	jar.SetCookies(origin, []*http.Cookie{gone})
	if len(jar.Cookies(origin)) != 0 {
		t.Fatal("companion removal failed")
	}
}

func TestCookieCacheOutageRefreshAndCanonicalFraming(t *testing.T) {
	cache, _, request, clock, _, serviceConfig, profile, result := browserCacheFixture(t, session.BrowserSession)
	sealed, e := cache.Put(context.Background(), result)
	if e != nil {
		t.Fatal(e)
	}
	header, _ := sealed.HeaderValue()
	parsed, _ := http.ParseSetCookie(header)
	reads := 0
	outageReader := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		reads++
		return session.SessionObservation{}, session.ErrUnavailable
	})
	source, _ := session.NewSessionService(outageReader, serviceConfig)
	// Recreate the configured wrapping keys in a separate real envelope service.
	_, _, _, _, _, crypto, _, _, _ := encryptedFixture(t)
	restored, _ := session.NewEncryptedCacheCodec(source, crypto, profile)
	credential, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	companion, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_cache", SameSite: http.SameSiteLaxMode})
	outage, _ := session.NewCookieCache(restored, session.CookieCacheConfig{Credential: credential, Cache: companion, MaximumCookieBytes: 3800})
	warm, e := outage.Get(context.Background(), request, []string{parsed.Value})
	if e != nil || !warm.Authenticated || reads != 0 {
		t.Fatal("warm outage", e)
	}
	for _, bad := range []string{parsed.Value + "=", parsed.Value[:10] + "\n" + parsed.Value[10:], "broken!", strings.Repeat("A", 3801), ""} {
		before := reads
		got, e := outage.Get(context.Background(), request, []string{bad})
		if e != session.ErrUnavailable || got.Authenticated || reads != before+1 {
			t.Fatal("noncanonical cache did not use primary", e)
		}
	}
	before := reads
	if got, e := outage.Get(context.Background(), request, []string{parsed.Value, parsed.Value}); e != session.ErrInvalidInput || got.Authenticated || reads != before {
		t.Fatal("duplicate cookie accepted", e)
	}
	if got, e := cache.Get(context.Background(), request, nil); e != nil || !got.Authenticated {
		t.Fatal("absent optional cache rejected primary", e)
	}
	resealed, e := outage.Put(context.Background(), warm)
	if e != nil {
		t.Fatal(e)
	}
	resealWire, _ := resealed.HeaderValue()
	resealCookie, _ := http.ParseSetCookie(resealWire)
	clock.now = result.ValidUntil()
	if got, e := outage.Get(context.Background(), request, []string{resealCookie.Value}); e != session.ErrUnavailable || got.Authenticated {
		t.Fatal("cookie refresh renewed authority", e)
	}
}

func TestCookieCacheRejectsBearerAndOriginalCredentialSubstitution(t *testing.T) {
	cache, codec, request, _, observed, serviceConfig, _, result := browserCacheFixture(t, session.BrowserSession)
	sealed, e := cache.Put(context.Background(), result)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := sealed.HeaderValue()
	companion, _ := http.ParseSetCookie(wire)
	foreign := request
	foreign.TenantID = "other"
	if got, e := cache.Get(context.Background(), foreign, []string{companion.Value}); e != nil || got.Authenticated {
		t.Fatal("foreign tenant authenticated", e)
	}
	token, _ := session.NewToken(32)
	substituted := request
	substituted.Credential, _ = session.NewCredential(session.CredentialCookie, token)
	if got, e := cache.Get(context.Background(), substituted, []string{companion.Value}); e != nil || got.Authenticated {
		t.Fatal("foreign credential authenticated", e)
	}
	bearer := request
	bearer.Credential, _ = session.NewCredential(session.CredentialBearer, token)
	if got, e := cache.Get(context.Background(), bearer, []string{companion.Value}); e != session.ErrInvalidInput || got.Authenticated {
		t.Fatal("bearer read cookies", e)
	}
	// A genuine bearer Get result still cannot be turned into a cookie cache.
	spec, _ := observed.Session.Bindings()
	spec.Lookup, _ = token.Digest(serviceConfig.LookupKeys[0], string(spec.TenantID))
	observed.Session, e = session.NewSession(spec)
	if e != nil {
		t.Fatal(e)
	}
	accepted, e := codec.Get(context.Background(), bearer, nil)
	if e != nil || !accepted.Authenticated {
		t.Fatal("bearer fixture", e)
	}
	if out, e := cache.Put(context.Background(), accepted); e != session.ErrUnauthenticated {
		t.Fatal("bearer custody converted", e)
	} else if wire, e := out.HeaderValue(); e == nil || wire != "" {
		t.Fatal("bearer cache leaked")
	}
}

func TestCookieCacheConfigurationCustodyCancellationAndConcurrency(t *testing.T) {
	cache, codec, request, clock, _, _, _, result := browserCacheFixture(t, session.BrowserSession)
	credential, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	companion, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_cache", SameSite: http.SameSiteLaxMode})
	strict, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_cache", SameSite: http.SameSiteStrictMode})
	for _, cfg := range []session.CookieCacheConfig{{}, {Credential: credential, Cache: credential, MaximumCookieBytes: 3800}, {Credential: credential, Cache: strict, MaximumCookieBytes: 3800}, {Credential: credential, Cache: companion, MaximumCookieBytes: 511}, {Credential: credential, Cache: companion, MaximumCookieBytes: 3801}} {
		if _, e := session.NewCookieCache(codec, cfg); e != session.ErrInvalidInput {
			t.Fatal("unsafe profile accepted", e)
		}
	}
	if _, e := session.NewCookieCache(nil, session.CookieCacheConfig{Credential: credential, Cache: companion, MaximumCookieBytes: 3800}); e != session.ErrInvalidInput {
		t.Fatal("nil codec")
	}
	if _, e := cache.Put(context.Background(), session.GetResult{Authenticated: true, Session: result.Session}); e != session.ErrUnauthenticated {
		t.Fatal("fabricated custody", e)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	var cancellation identity.CancelledError
	if _, e := cache.Put(cancelled, result); !errors.As(e, &cancellation) {
		t.Fatal("cancelled put", e)
	}
	if got, e := cache.Get(cancelled, request, nil); !errors.As(e, &cancellation) || got.Authenticated {
		t.Fatal("cancelled get", e)
	}
	if _, e := cache.Put(nil, result); e != session.ErrInvalidInput {
		t.Fatal("nil ctx")
	}
	if got, e := cache.Get(context.Background(), session.GetRequest{}, nil); e != session.ErrInvalidInput || got.Authenticated {
		t.Fatal("missing original cookie", e)
	}
	cookie, e := cache.Put(context.Background(), result)
	if e != nil {
		t.Fatal(e)
	}
	header, _ := cookie.HeaderValue()
	parsed, _ := http.ParseSetCookie(header)
	for _, v := range []any{cookie, &cookie, cache} {
		if b, e := json.Marshal(v); e == nil || len(b) != 0 {
			t.Fatal("implicit export")
		}
	}
	if fmt.Sprintf("%#v", cookie) != "session.CacheCookie(redacted)" || fmt.Sprintf("%#v", cache) != "session.CookieCache(redacted)" {
		t.Fatal("diagnostic leak")
	}
	if b, e := cookie.MarshalText(); e != session.ErrSecretSerialization || b != nil {
		t.Fatal("text leak")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			got, e := cache.Get(context.Background(), request, []string{parsed.Value})
			if e != nil || !got.Authenticated {
				t.Error("concurrent get", e)
			}
			if _, e := cache.Put(context.Background(), result); e != nil {
				t.Error("concurrent put", e)
			}
		})
	}
	wg.Wait()
	clock.now = result.ValidUntil()
	if out, e := cache.Put(context.Background(), result); e != session.ErrUnauthenticated {
		t.Fatal("expired put", e)
	} else if wire, e := out.HeaderValue(); e == nil || wire != "" {
		t.Fatal("expired header leaked")
	}
}
