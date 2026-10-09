package identityhttp_test

import (
	"context"
	"errors"
	"math"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

type originalFlowBackend func(context.Context, ratelimit.Request) (ratelimit.Decision, error)

func (originalFlowBackend) Name() string { return "original-flow-test" }
func (f originalFlowBackend) Admit(c context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	return f(c, r)
}
func (f originalFlowBackend) AdmitStrict(c context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	return f(c, r)
}

func TestOriginalFlowRateSharesExactIPBudgetAndRefill(t *testing.T) {
	var millis atomic.Int64
	millis.Store(1800000000000)
	now := func() time.Time { return time.UnixMilli(millis.Load()) }
	l, shared := authLimiter(t, now)
	other, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: shared, Namespace: "http-auth", Now: now, IdentifierKey: [32]byte{1}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	c := networkConfig()
	c.TenantHosts = append(c.TenantHosts, identityhttp.TenantHost{Host: "other.example", TenantID: "tenant-b"})
	network, _ := identityhttp.NewNetworkResolver(c)
	for i := 0; i < 21; i++ {
		r := httptest.NewRequest("POST", "/v1/session/preauth-issue", nil)
		r.Host, r.RemoteAddr = "tenant.example", "198.51.100.1:1234"
		owner := l
		if i%2 == 1 {
			r.Host, owner = "other.example", other
		}
		facts, err := network.Resolve(r)
		if err != nil {
			t.Fatal(err)
		}
		out, err := owner.AdmitOriginalFlow(context.Background(), facts)
		if i < 20 && (err != nil || !out.Allowed) || i == 20 && (!errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != 30*time.Second) {
			t.Fatal("original-flow IP budget reset or wrong ceiling", i, err)
		}
	}
	facts := safeFacts(t, "198.51.100.1")
	millis.Add(15000)
	if out, err := l.AdmitOriginalFlow(context.Background(), facts); !errors.Is(err, identityhttp.ErrRateLimited) || out.RetryAfter != 15*time.Second {
		t.Fatal("premature continuous refill")
	}
	millis.Add(15000)
	if out, err := l.AdmitOriginalFlow(context.Background(), facts); err != nil || !out.Allowed {
		t.Fatal("continuous refill not admitted")
	}
	if out, err := l.AdmitOriginalFlow(context.Background(), safeFacts(t, "198.51.100.2")); err != nil || !out.Allowed {
		t.Fatal("different IP conflated")
	}
	if out, err := l.Admit(context.Background(), facts, identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: "person@example.invalid"}); err != nil || !out.Allowed {
		t.Fatal("original-flow and signin profiles conflated")
	}
}

func TestOriginalFlowRateConcurrentCeiling(t *testing.T) {
	l, _ := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	facts := safeFacts(t, "198.51.100.1")
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			out, err := l.AdmitOriginalFlow(context.Background(), facts)
			if err == nil && out.Allowed {
				admitted.Add(1)
			} else if !errors.Is(err, identityhttp.ErrRateLimited) {
				t.Error("unexpected concurrent denial", err)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 20 {
		t.Fatal("concurrent original-flow ceiling violated")
	}
}

func TestOriginalFlowRateFailsClosedAndBoundsRetries(t *testing.T) {
	l, shared := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	facts := safeFacts(t, "198.51.100.1")
	for _, mode := range []int32{1, 2} {
		shared.mode.Store(mode)
		if out, err := l.AdmitOriginalFlow(context.Background(), facts); !errors.Is(err, identityhttp.ErrRateUnavailable) || out != (identityhttp.AuthRateResult{}) {
			t.Fatal("outage or ambiguity admitted original flow")
		}
	}
	shared.mode.Store(0)
	probe := &authRateProbe{safeShared: shared}
	probeOwner, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: probe, Namespace: "flow-retry", Now: func() time.Time { return time.Unix(1800000000, 0) }, IdentifierKey: [32]byte{1}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { probeOwner.Close() })
	for _, tc := range []struct{ delay, want time.Duration }{{0, time.Second}, {time.Second + 1, 2 * time.Second}, {time.Duration(math.MaxInt64), time.Hour}} {
		probe.delay = tc.delay
		if out, err := probeOwner.AdmitOriginalFlow(context.Background(), facts); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != tc.want {
			t.Fatal("original-flow retry overflow or invalid rounding")
		}
	}
	if len(probe.requests) != 3 || probe.requests[0].Policy.Capacity() != 20 || probe.requests[0].Policy.Period() != 10*time.Minute || probe.requests[0].Policy.Consistency() != ratelimit.ConsistencyStrong {
		t.Fatal("wrong primitive admission profile")
	}
}

func TestOriginalFlowRatePreservesCancellationAndOwnership(t *testing.T) {
	facts := safeFacts(t, "198.51.100.1")
	var calls atomic.Int32
	backend := originalFlowBackend(func(ctx context.Context, _ ratelimit.Request) (ratelimit.Decision, error) {
		calls.Add(1)
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("backend call unbounded")
		}
		<-ctx.Done()
		return ratelimit.Decision{}, ctx.Err()
	})
	l, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "flow-bound", Now: time.Now, IdentifierKey: [32]byte{1}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if out, err := l.AdmitOriginalFlow(ctx, facts); !errors.Is(err, identityhttp.ErrRateUnavailable) || out != (identityhttp.AuthRateResult{}) || calls.Load() != 1 {
		t.Fatal("earlier deadline not preserved")
	}
	for _, tc := range []struct {
		owner *identityhttp.AuthRateLimiter
		ctx   context.Context
		facts identityhttp.NetworkFacts
	}{{nil, context.Background(), facts}, {l, nil, facts}, {l, context.Background(), identityhttp.NetworkFacts{}}, {l, ctx, facts}} {
		if out, err := tc.owner.AdmitOriginalFlow(tc.ctx, tc.facts); err == nil || out != (identityhttp.AuthRateResult{}) {
			t.Fatal("invalid or canceled input admitted")
		}
	}
	l.Close()
	if out, err := l.AdmitOriginalFlow(context.Background(), facts); err == nil || out.Allowed || calls.Load() != 1 {
		t.Fatal("closed owner reached borrowed backend")
	}
}

func TestOriginalFlowRateRejectsPanicAndLateClose(t *testing.T) {
	facts := safeFacts(t, "198.51.100.1")
	for _, mode := range []string{"backend-panic", "clock-panic", "zero-clock", "late-close"} {
		t.Run(mode, func(t *testing.T) {
			var owner *identityhttp.AuthRateLimiter
			backend := originalFlowBackend(func(_ context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
				if mode == "backend-panic" {
					panic("test backend panic")
				}
				owner.Close()
				return ratelimit.Decision{Allowed: true, Limit: r.Policy.Limit(), Reason: ratelimit.ReasonAllowed, Reset: r.Now.Add(time.Minute)}, nil
			})
			now := func() time.Time {
				if mode == "clock-panic" {
					panic("test clock panic")
				}
				if mode == "zero-clock" {
					return time.Time{}
				}
				return time.Unix(1800000000, 0)
			}
			var err error
			owner, err = identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "flow-failure", Now: now, IdentifierKey: [32]byte{1}, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { owner.Close() })
			if out, err := owner.AdmitOriginalFlow(context.Background(), facts); !errors.Is(err, identityhttp.ErrRateUnavailable) || out != (identityhttp.AuthRateResult{}) {
				t.Fatal("panic, invalid clock or in-flight closure admitted")
			}
		})
	}
}

func TestOriginalFlowRateUsesFullIPv6AndRejectsPublicRealm(t *testing.T) {
	l, _ := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	network, err := identityhttp.NewNetworkResolver(networkConfig())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.Host, r.RemoteAddr = "tenant.example", "[2001:db8::1]:1234"
	facts, err := network.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if out, err := l.AdmitOriginalFlow(context.Background(), facts); err != nil || !out.Allowed {
			t.Fatal("IPv6 unexpectedly denied")
		}
	}
	r.RemoteAddr = "[2001:db8::2]:1234"
	facts, err = network.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := l.AdmitOriginalFlow(context.Background(), facts); err != nil || !out.Allowed {
		t.Fatal("IPv6 subnet aggregation")
	}
	r.Host = networkConfig().PublicHosts[0]
	facts, err = network.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := l.AdmitOriginalFlow(context.Background(), facts); !errors.Is(err, identityhttp.ErrInvalidInput) || out != (identityhttp.AuthRateResult{}) {
		t.Fatal("public realm admitted tenant flow")
	}
}
