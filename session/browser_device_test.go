package session_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func browserDeviceCodec(t testing.TB) *session.BrowserDeviceCodec {
	t.Helper()
	key, err := session.NewBrowserDeviceKey(1, []byte(strings.Repeat("d", 32)))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := session.NewBrowserDeviceCodec(session.BrowserDeviceConfig{Namespace: "example-test", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func TestBrowserDeviceTamperingAndRetainedKeys(t *testing.T) {
	c := browserDeviceCodec(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	issued, err := c.Issue(context.Background(), now, "tenant-a", "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := http.ParseSetCookie(issued.CookieHeader())
	wire, _ := base64.RawURLEncoding.DecodeString(cookie.Value)
	for i := range wire {
		changed := append([]byte(nil), wire...)
		changed[i] ^= 1
		out, err := c.Resolve(context.Background(), now, "tenant-a", "https://tenant.example", base64.RawURLEncoding.EncodeToString(changed))
		if !errors.Is(err, session.ErrBrowserDeviceDenied) || out.DeviceID() != "" {
			t.Fatal("tampering admitted")
		}
	}
	old, _ := session.NewBrowserDeviceKey(1, []byte(strings.Repeat("d", 32)))
	material := []byte(strings.Repeat("e", 32))
	newKey, _ := session.NewBrowserDeviceKey(2, material)
	material[0] = 0
	policy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteStrictMode})
	config := session.BrowserDeviceConfig{Namespace: "example-test", Keys: []session.BrowserDeviceKey{old, newKey}, ActiveVersion: 2, Lifetime: 24 * time.Hour, Cookie: policy}
	rotated, err := session.NewBrowserDeviceCodec(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Keys[0] = session.BrowserDeviceKey{}
	observed, err := rotated.Resolve(context.Background(), now.Add(time.Hour), "tenant-a", "https://tenant.example", cookie.Value)
	if err != nil || observed.DeviceID() != issued.DeviceID() || observed.ExpiresAt() != issued.ExpiresAt() {
		t.Fatal("retention or copying changed custody")
	}
	fresh, err := rotated.Issue(context.Background(), now, "tenant-a", "https://tenant.example")
	if err != nil || fresh.DeviceID() == issued.DeviceID() {
		t.Fatal("new browser reused correlation")
	}
	freshCookie, _ := http.ParseSetCookie(fresh.CookieHeader())
	if freshCookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie policy changed")
	}
	if _, err := rotated.Resolve(context.Background(), now, "tenant-a", "https://tenant.example", freshCookie.Value); err != nil {
		t.Fatal(err)
	}
	config.Keys = []session.BrowserDeviceKey{newKey}
	retired, _ := session.NewBrowserDeviceCodec(config)
	if _, err := retired.Resolve(context.Background(), now, "tenant-a", "https://tenant.example", cookie.Value); !errors.Is(err, session.ErrBrowserDeviceDenied) {
		t.Fatal("retired key accepted")
	}
	config.Keys = []session.BrowserDeviceKey{old, newKey}
	config.Namespace = "other-environment"
	other, _ := session.NewBrowserDeviceCodec(config)
	if _, err := other.Resolve(context.Background(), now, "tenant-a", "https://tenant.example", cookie.Value); !errors.Is(err, session.ErrBrowserDeviceDenied) {
		t.Fatal("environment substitution accepted")
	}
}

func TestBrowserDevicePolicyCancellationAndRedaction(t *testing.T) {
	key, _ := session.NewBrowserDeviceKey(1, []byte(strings.Repeat("d", 32)))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	base := session.BrowserDeviceConfig{Namespace: "example-test", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: cookie}
	for _, mutate := range []func(*session.BrowserDeviceConfig){
		func(c *session.BrowserDeviceConfig) { c.Namespace = "" },
		func(c *session.BrowserDeviceConfig) { c.Lifetime = time.Hour - time.Second },
		func(c *session.BrowserDeviceConfig) { c.Lifetime = 7*24*time.Hour + time.Second },
		func(c *session.BrowserDeviceConfig) { c.Lifetime += time.Nanosecond },
		func(c *session.BrowserDeviceConfig) { c.Keys = nil },
		func(c *session.BrowserDeviceConfig) { c.Keys = []session.BrowserDeviceKey{{}} },
		func(c *session.BrowserDeviceConfig) { c.Keys = []session.BrowserDeviceKey{key, key} },
		func(c *session.BrowserDeviceConfig) { c.Keys = make([]session.BrowserDeviceKey, 17) },
		func(c *session.BrowserDeviceConfig) { c.ActiveVersion = 0 },
		func(c *session.BrowserDeviceConfig) { c.ActiveVersion = 2 },
		func(c *session.BrowserDeviceConfig) { c.Cookie = session.CookiePolicy{} },
	} {
		config := base
		mutate(&config)
		if _, err := session.NewBrowserDeviceCodec(config); !errors.Is(err, session.ErrInvalidPolicy) {
			t.Fatal("invalid policy admitted")
		}
	}
	for _, material := range [][]byte{nil, make([]byte, 31), make([]byte, 32), make([]byte, 65)} {
		if _, err := session.NewBrowserDeviceKey(1, material); !errors.Is(err, session.ErrInvalidPolicy) {
			t.Fatal("invalid key admitted")
		}
	}
	if _, err := session.NewBrowserDeviceKey(0, []byte(strings.Repeat("d", 32))); err == nil {
		t.Fatal("zero key version admitted")
	}
	c, _ := session.NewBrowserDeviceCodec(base)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	issued, _ := c.Issue(context.Background(), now, "tenant-a", "https://tenant.example")
	cookieWire, _ := http.ParseSetCookie(issued.CookieHeader())
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		if out, err := c.Issue(ctx, now, "tenant-a", "https://tenant.example"); !errors.Is(err, session.ErrBrowserDeviceDenied) || out.DeviceID() != "" {
			t.Fatal("cancelled issue accepted")
		}
		if out, err := c.Resolve(ctx, now, "tenant-a", "https://tenant.example", cookieWire.Value); !errors.Is(err, session.ErrBrowserDeviceDenied) || out.DeviceID() != "" {
			t.Fatal("cancelled resolve accepted")
		}
	}
	var zero *session.BrowserDeviceCodec
	if _, err := zero.Issue(context.Background(), now, "tenant-a", "https://tenant.example"); err == nil {
		t.Fatal("zero codec issued")
	}
	for _, origin := range []string{"http://localhost", "https://tenant.example/", "https://tenant.example?", "https://user@tenant.example", "https://tenant.example#fragment", strings.Repeat("a", 2049)} {
		if _, err := c.Issue(context.Background(), now, "tenant-a", origin); !errors.Is(err, session.ErrBrowserDeviceDenied) {
			t.Fatal("invalid origin issued")
		}
	}
	for _, at := range []time.Time{{}, time.Unix(0, 0), time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)} {
		if _, err := c.Issue(context.Background(), at, "tenant-a", "https://tenant.example"); !errors.Is(err, session.ErrBrowserDeviceDenied) {
			t.Fatal("invalid timeline issued")
		}
	}
	for _, value := range []any{key, base, c, issued} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			text := fmt.Sprintf(verb, value)
			if strings.Contains(text, cookieWire.Value) || strings.Contains(text, issued.DeviceID()) || strings.Contains(text, "example-test") {
				t.Fatal("sensitive diagnostic leaked")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("implicit serialization admitted")
		}
		if v, ok := value.(slog.LogValuer); !ok || v.LogValue().String() != "[REDACTED]" {
			t.Fatal("structured diagnostic leaked")
		}
	}
}

func TestBrowserDeviceConcurrentImmutableReuse(t *testing.T) {
	c := browserDeviceCodec(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 500000000, time.UTC)
	issued, err := c.Issue(context.Background(), now, "tenant-a", "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := http.ParseSetCookie(issued.CookieHeader())
	if issued.ExpiresAt().After(now.Add(24 * time.Hour)) {
		t.Fatal("rounding extended lifetime")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				out, err := c.Resolve(context.Background(), now, "tenant-a", "https://tenant.example", cookie.Value)
				if err != nil || out.DeviceID() != issued.DeviceID() || out.ExpiresAt() != issued.ExpiresAt() {
					t.Error("concurrent custody changed")
				}
			}
		})
	}
	wg.Wait()
}

func FuzzBrowserDeviceCustody(f *testing.F) {
	c := browserDeviceCodec(f)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	issued, err := c.Issue(context.Background(), now, "tenant-a", "https://tenant.example")
	if err != nil {
		f.Fatal(err)
	}
	cookie, _ := http.ParseSetCookie(issued.CookieHeader())
	for _, seed := range []string{cookie.Value, "", strings.Repeat("x", 114), strings.Repeat("x", 4097), cookie.Value + "="} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		out, err := c.Resolve(context.Background(), now, "tenant-a", "https://tenant.example", token)
		if err != nil {
			if !errors.Is(err, session.ErrBrowserDeviceDenied) || out.DeviceID() != "" || out.CookieHeader() != "" || !out.ExpiresAt().IsZero() {
				t.Fatal("denial retained custody")
			}
			return
		}
		// Fuzz workers initialize their own random seed cookie. A legitimate
		// parent-process seed still verifies under the same test key, but need
		// not identify the worker's separately issued browser.
		if len(token) != 114 || len(out.DeviceID()) != 64 || !out.ExpiresAt().After(now) || out.ExpiresAt().After(now.Add(24*time.Hour)) || out.CookieHeader() != "" {
			t.Fatal("invalid successful custody")
		}
		again, err := c.Resolve(context.Background(), now, "tenant-a", "https://tenant.example", token)
		if err != nil || again.DeviceID() != out.DeviceID() || again.ExpiresAt() != out.ExpiresAt() {
			t.Fatal("resolution changed original custody")
		}
		if _, err := c.Resolve(context.Background(), now, "tenant-b", "https://tenant.example", token); !errors.Is(err, session.ErrBrowserDeviceDenied) {
			t.Fatal("scope substitution admitted")
		}
	})
}

func TestBrowserDeviceOriginalCustodyAndExpiry(t *testing.T) {
	c := browserDeviceCodec(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	tenant := identity.TenantID("tenant-a")
	origin := "https://tenant.example"
	issued, err := c.Issue(context.Background(), now, tenant, origin)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := http.ParseSetCookie(issued.CookieHeader())
	if err != nil || cookie.Name != "__Host-identity_device" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 86400 {
		t.Fatal("unsafe device cookie")
	}
	if issued.DeviceID() == "" || !issued.ExpiresAt().Equal(now.Add(24*time.Hour)) {
		t.Fatal("missing original custody")
	}
	observed, err := c.Resolve(context.Background(), now.Add(time.Hour), tenant, origin, cookie.Value)
	if err != nil || observed.DeviceID() != issued.DeviceID() || observed.ExpiresAt() != issued.ExpiresAt() || observed.CookieHeader() != "" {
		t.Fatal("resolve renewed or changed device custody")
	}
	for _, tc := range []struct {
		at            time.Time
		tenant        identity.TenantID
		origin, token string
	}{
		{now.Add(24 * time.Hour), tenant, origin, cookie.Value},
		{now.Add(-time.Second), tenant, origin, cookie.Value},
		{now, "tenant-b", origin, cookie.Value},
		{now, tenant, "https://other.example", cookie.Value},
		{now, tenant, origin, cookie.Value + "="},
		{now, tenant, origin, strings.Repeat("x", 4097)},
	} {
		out, err := c.Resolve(context.Background(), tc.at, tc.tenant, tc.origin, tc.token)
		if err == nil || out.DeviceID() != "" || out.CookieHeader() != "" || !out.ExpiresAt().IsZero() {
			t.Fatal("invalid device custody admitted")
		}
	}
}

func TestBrowserDeviceUnexportedConsumerCustodyDoesNotLeak(t *testing.T) {
	c := browserDeviceCodec(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	issued, err := c.Issue(context.Background(), now, "tenant-a", "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := http.ParseSetCookie(issued.CookieHeader())
	// fmt does not invoke nested Format on an unexported consumer field.
	wrapper := struct{ device session.BrowserDevice }{device: issued}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		text := fmt.Sprintf(verb, wrapper)
		if strings.Contains(text, cookie.Value) || strings.Contains(text, issued.DeviceID()) {
			t.Fatal("nested unexported custody leaked")
		}
	}
}
