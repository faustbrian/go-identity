package identityhttp_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// The shared-store seam delegates actual counting to the primitive's owned
// implementation; only its unavailable/unknown boundary is controlled here.
type safeShared struct {
	*memory.Store
	mode atomic.Int32
}

func (*safeShared) Name() string { return "test-shared" }
func (b *safeShared) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	if r.Policy.Consistency() != ratelimit.ConsistencyStrong {
		return ratelimit.Decision{}, ratelimit.ErrInvalidPolicy
	}
	switch b.mode.Load() {
	case 1:
		return ratelimit.Decision{}, ratelimit.ErrUnavailable
	case 2:
		return ratelimit.Decision{}, ratelimit.UnknownOutcome(nil)
	}
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return b.Store.AdmitStrict(ctx, r)
}

func safeFacts(t *testing.T, ip string) identityhttp.NetworkFacts {
	t.Helper()
	n, err := identityhttp.NewNetworkResolver(networkConfig())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/v1/session/get", nil)
	r.Host = "tenant.example"
	r.RemoteAddr = ip + ":1234"
	f, err := n.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func safeLimiter(t *testing.T) (*identityhttp.SafeRateLimiter, *safeShared, *atomic.Int32) {
	return safeLimiterSize(t, 1024)
}

func safeLimiterSize(t *testing.T, maximumKeys int, changes ...func(*identityhttp.SafeRateConfig)) (*identityhttp.SafeRateLimiter, *safeShared, *atomic.Int32) {
	t.Helper()
	store, err := memory.New(memory.Options{MaxKeys: 1024, Shards: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	b := &safeShared{Store: store}
	events := &atomic.Int32{}
	config := identityhttp.SafeRateConfig{Shared: b, Namespace: "test-http", MaximumDuration: time.Second, EmergencyMaximumKeys: maximumKeys,
		Now: func() time.Time { return time.Unix(1800000000, 0) },
		Degraded: func(ctx context.Context, e identityhttp.SafeRateEvent) error {
			if _, ok := ctx.Deadline(); !ok || e.OperationID != "identity.session.get" {
				t.Error("unbounded/unattributable event")
			}
			events.Add(1)
			return nil
		}}
	for _, change := range changes {
		change(&config)
	}
	l, err := identityhttp.NewSafeRateLimiter(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, b, events
}

func TestSafeRateTrustedIPAndSubjectBudgets(t *testing.T) {
	l, _, _ := safeLimiter(t)
	f := safeFacts(t, "198.51.100.1")
	for i := 0; i < 100; i++ {
		if r, err := l.Admit(context.Background(), f, "identity.session.get", ""); err != nil || !r.Allowed || r.Degraded {
			t.Fatal("shared IP admission", i, err)
		}
	}
	if r, err := l.Admit(context.Background(), f, "identity.session.get", ""); !errors.Is(err, identityhttp.ErrRateLimited) || r.Allowed || r.RetryAfter <= 0 {
		t.Fatal("IP budget bypass", err)
	}
	l2, _, _ := safeLimiter(t)
	for i := 0; i < 301; i++ {
		f = safeFacts(t, fmt.Sprintf("198.51.100.%d", i/80+1))
		r, err := l2.Admit(context.Background(), f, "identity.session.get", "user-a")
		if i < 300 && (err != nil || !r.Allowed) {
			t.Fatal("subject early rejection", i, err)
		}
		if i == 300 && (!errors.Is(err, identityhttp.ErrRateLimited) || r.Allowed) {
			t.Fatal("subject budget bypass", err)
		}
	}
}

func TestSafeRateOutageAndAmbiguity(t *testing.T) {
	l, b, events := safeLimiter(t)
	f := safeFacts(t, "198.51.100.9")
	b.mode.Store(1)
	for i := 0; i < 21; i++ {
		r, err := l.Admit(context.Background(), f, "identity.session.get", "user-a")
		if !r.Degraded || (i < 20 && (err != nil || !r.Allowed)) || (i == 20 && (!errors.Is(err, identityhttp.ErrRateLimited) || r.Allowed)) {
			t.Fatal("emergency budget", i, err)
		}
	}
	if events.Load() != 21 {
		t.Fatal("missing degraded events")
	}
	b.mode.Store(2)
	if r, err := l.Admit(context.Background(), safeFacts(t, "198.51.100.10"), "identity.session.get", ""); !errors.Is(err, identityhttp.ErrRateUnavailable) || r.Allowed || r.Degraded || events.Load() != 21 {
		t.Fatal("ambiguous dispatch became fallback authority", err)
	}
	l.Close()
	if r, err := l.Admit(context.Background(), f, "identity.session.get", ""); err == nil || r.Allowed {
		t.Fatal("closed limiter admitted")
	}
}

func TestSafeRateSaturationCannotResetLiveEmergencyBudget(t *testing.T) {
	l, b, _ := safeLimiterSize(t, 1)
	b.mode.Store(1)
	f := safeFacts(t, "198.51.100.1")
	for i := 0; i < 20; i++ {
		if r, err := l.Admit(context.Background(), f, "identity.session.get", ""); err != nil || !r.Allowed {
			t.Fatal("initial emergency admission", err)
		}
	}
	if r, err := l.Admit(context.Background(), safeFacts(t, "198.51.100.2"), "identity.session.get", ""); !errors.Is(err, identityhttp.ErrRateUnavailable) || r.Allowed {
		t.Fatal("cardinality pressure evicted a live counter", err)
	}
	if r, err := l.Admit(context.Background(), f, "identity.session.get", ""); !errors.Is(err, identityhttp.ErrRateLimited) || r.Allowed {
		t.Fatal("live emergency budget reset", err)
	}
}

func TestSafeRateCancellationInvalidIdentityAndEventFailure(t *testing.T) {
	l, _, _ := safeLimiter(t)
	f := safeFacts(t, "198.51.100.7")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, err := l.Admit(ctx, f, "identity.session.get", ""); !errors.Is(err, context.Canceled) || r.Allowed {
		t.Fatal("cancelled request admitted", err)
	}
	for _, id := range []string{"unknown", "identity.password.signin"} {
		if r, err := l.Admit(context.Background(), f, id, ""); !errors.Is(err, identityhttp.ErrInvalidInput) || r.Allowed {
			t.Fatal("non-safe operation admitted", err)
		}
	}
	if r, err := l.Admit(context.Background(), identityhttp.NetworkFacts{}, "identity.session.get", ""); err == nil || r.Allowed {
		t.Fatal("untrusted network facts admitted")
	}
	if r, err := l.Admit(context.Background(), f, "identity.session.get", "bad user"); err == nil || r.Allowed {
		t.Fatal("invalid authenticated subject admitted")
	}
	for _, change := range []func(*identityhttp.SafeRateConfig){
		func(c *identityhttp.SafeRateConfig) { c.Now = func() time.Time { return time.Time{} } },
		func(c *identityhttp.SafeRateConfig) { c.Now = func() time.Time { panic("private clock failure") } },
		func(c *identityhttp.SafeRateConfig) {
			c.Degraded = func(context.Context, identityhttp.SafeRateEvent) error { return errors.New("private observer failure") }
		},
		func(c *identityhttp.SafeRateConfig) {
			c.Degraded = func(context.Context, identityhttp.SafeRateEvent) error { panic("private observer failure") }
		},
	} {
		owner, b, _ := safeLimiterSize(t, 1024, change)
		b.mode.Store(1)
		if r, err := owner.Admit(context.Background(), f, "identity.session.get", ""); !errors.Is(err, identityhttp.ErrRateUnavailable) || r.Allowed || err.Error() != "identity.http.rate_unavailable" {
			t.Fatal("failure admitted or leaked", err)
		}
	}
}

func TestSafeRateConcurrentEmergencyAdmission(t *testing.T) {
	l, b, events := safeLimiter(t)
	b.mode.Store(1)
	f := safeFacts(t, "198.51.100.7")
	var allowed atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 100; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			r, err := l.Admit(context.Background(), f, "identity.session.get", "")
			if err == nil && r.Allowed {
				allowed.Add(1)
			} else if !errors.Is(err, identityhttp.ErrRateLimited) {
				t.Error("unexpected concurrent result", err)
			}
		}()
	}
	group.Wait()
	if allowed.Load() != 20 || events.Load() != 100 {
		t.Fatal("concurrent admission exceeds exact budget")
	}
}

func TestSafeRateReclaimsOnlyExpiredEmergencyBudgets(t *testing.T) {
	var now atomic.Int64
	now.Store(1800000000)
	l, b, _ := safeLimiterSize(t, 1, func(c *identityhttp.SafeRateConfig) { c.Now = func() time.Time { return time.Unix(now.Load(), 0) } })
	b.mode.Store(1)
	f := safeFacts(t, "198.51.100.1")
	if _, err := l.Admit(context.Background(), f, "identity.session.get", ""); err != nil {
		t.Fatal(err)
	}
	now.Add(59)
	other := safeFacts(t, "198.51.100.2")
	if r, err := l.Admit(context.Background(), other, "identity.session.get", ""); err == nil || r.Allowed {
		t.Fatal("live counter reclaimed")
	}
	now.Add(1)
	if r, err := l.Admit(context.Background(), other, "identity.session.get", ""); err != nil || !r.Allowed {
		t.Fatal("expired counter not reclaimed", err)
	}
}

func TestSafeRateRefillsContinuouslyWithoutWindowReset(t *testing.T) {
	for _, tc := range []struct {
		name             string
		capacity, refill int
		subject, outage  bool
	}{
		{"ip", 100, 1, false, false}, {"subject", 300, 5, true, false}, {"emergency", 20, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var now atomic.Int64
			now.Store(1800000059)
			l, backend, _ := safeLimiterSize(t, 1024, func(c *identityhttp.SafeRateConfig) { c.Now = func() time.Time { return time.Unix(now.Load(), 0) } })
			if tc.outage {
				backend.mode.Store(1)
			}
			f := safeFacts(t, "198.51.100.7")
			user := ""
			if tc.subject {
				user = "user-a"
			}
			for i := 0; i < tc.capacity; i++ {
				if tc.subject {
					f = safeFacts(t, fmt.Sprintf("198.51.100.%d", i/80+1))
				}
				if _, err := l.Admit(context.Background(), f, "identity.session.get", identity.UserID(user)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.subject {
				f = safeFacts(t, "198.51.100.8")
			}
			now.Add(1) // crossing a wall-clock minute must not reset the full budget
			for i := 0; i < tc.refill; i++ {
				if r, err := l.Admit(context.Background(), f, "identity.session.get", identity.UserID(user)); err != nil || !r.Allowed {
					t.Fatal("continuous refill missing", err)
				}
			}
			if r, err := l.Admit(context.Background(), f, "identity.session.get", identity.UserID(user)); !errors.Is(err, identityhttp.ErrRateLimited) || r.Allowed {
				t.Fatal("wall-clock boundary reset exhausted budget", err)
			}
		})
	}
}
