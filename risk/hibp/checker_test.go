package hibp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	httpclient "github.com/faustbrian/go-http-client/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	password "github.com/faustbrian/go-password/v2"
)

type testClock struct{ nanos atomic.Int64 }

func (c *testClock) Now() time.Time { return time.Unix(0, c.nanos.Load()).UTC() }

func testConfig() Config {
	return Config{UserAgent: "golib-identity-reference/test (+https://example.com/security)", AddPadding: true,
		CacheEntries: 100, CacheTTL: time.Hour, ResponseBytes: 1024, MaxBreachCount: 1000000000,
		OutboundConcurrency: 1, Timeout: 10 * time.Second, PolicyVersion: "v1", MaxWaiters: 8, MaxCandidateBytes: 1024, CacheBytes: 1 << 20}
}

func requestFor(t *testing.T, raw string) CheckRequest {
	t.Helper()
	s, e := password.NewSecret([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Destroy)
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	return CheckRequest{OperationID: "identity.password.register", TenantID: "tenant", Action: risk.Action("identity.password.register"),
		Purpose: "create", SubjectScope: "subject", PolicyVersion: "v1", ReplayID: id, Candidate: s}
}

// Only dialing is rerouted. The original HTTPS URL, authority and Host reach a
// real local TLS server. Its test-only certificate is verified as example.com.
func checkerFixture(t *testing.T, handler http.HandlerFunc) (*Client, *testClock) {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	transport := s.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	h, e := httpclient.New(httpclient.Config{Transport: transport})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = h.Close() })
	c := &testClock{}
	c.nanos.Store(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC).UnixNano())
	x, e := New(testConfig(), h, c)
	if e != nil {
		t.Fatal(e)
	}
	client := x.(*Client)
	t.Cleanup(func() {
		if e := client.Close(context.Background()); e != nil {
			t.Error(e)
		}
	})
	return client, c
}

func TestCheckerExactBytesCacheAndBinding(t *testing.T) {
	var calls atomic.Int32
	r := requestFor(t, " \x00password\xff ")
	candidate, e := deriveCandidate(context.Background(), r.Candidate, 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer candidate.clear()
	c, clock := checkerFixture(t, func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		if req.Host != "api.pwnedpasswords.com" || req.URL.Path != "/range/"+string(candidate.prefix[:]) || req.URL.RawQuery != "" || req.Header.Get("Add-Padding") != "true" || req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != "" {
			t.Error("non-private request")
		}
		fmt.Fprintf(w, "%s:17\r\n", candidate.suffix[:])
	})
	first, e := c.Check(context.Background(), r)
	if e != nil || first.Outcome != OutcomeMatch || first.BreachCount != 17 || first.ReplayID != r.ReplayID {
		t.Fatalf("bad first result: %v %v", first, e)
	}
	r.TenantID = "other"
	r.SubjectScope = "other-subject"
	r.ReplayID, _ = identity.NewCommandID()
	clock.nanos.Add(int64(time.Hour - time.Nanosecond))
	second, e := c.Check(context.Background(), r)
	if e != nil || second.TenantID != r.TenantID || second.SubjectScope != r.SubjectScope || second.ReplayID != r.ReplayID || second.CheckedAt != first.CheckedAt || calls.Load() != 1 {
		t.Fatalf("cache rebinding failed: %v %v", second, e)
	}
	clock.nanos.Add(1)
	if _, e := c.Check(context.Background(), r); e != nil || calls.Load() != 2 {
		t.Fatal("exact expiry did not refetch", e)
	}
	if e := r.Candidate.Use(func(b []byte) error {
		if string(b) != " \x00password\xff " {
			t.Error("owner changed")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestCheckerFailureNeverCachesSuccess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"redirect", 302, "", ErrProviderUnavailable}, {"throttle", 429, "", ErrProviderUnavailable},
		{"malformed", 200, "malformed", ErrMalformedRange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.Header().Set("Location", "https://example.com/elsewhere")
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.body)
					return
				}
				fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
			})
			r := requestFor(t, "synthetic")
			result, e := c.Check(context.Background(), r)
			if !errors.Is(e, tc.want) || result.Outcome == OutcomeNoMatch || result.Outcome == OutcomeMatch {
				t.Fatalf("failure became usable: %v %v", result, e)
			}
			result, e = c.Check(context.Background(), r)
			if e != nil || result.Outcome != OutcomeNoMatch || calls.Load() != 2 {
				t.Fatal("failure cached or redirect followed", e)
			}
		})
	}
}

type checkReply struct {
	result CheckResult
	err    error
}

func launch(c *Client, ctx context.Context, request CheckRequest) <-chan checkReply {
	done := make(chan checkReply, 1)
	go func() { r, e := c.Check(ctx, request); done <- checkReply{r, e} }()
	return done
}
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("bounded fixture wait exceeded")
		var zero T
		return zero
	}
}

// Enrollment is not observable on the wire. Inspect only owned synchronization
// state to establish the barrier; assertions still exercise public outcomes.
func awaitEnrollment(t *testing.T, c *Client, callers uint32) {
	t.Helper()
	ceiling := time.Now().Add(5 * time.Second)
	for time.Now().Before(ceiling) {
		c.mu.Lock()
		n := 0
		for _, f := range c.flights {
			n += f.waiters
		}
		c.mu.Unlock()
		if n == int(callers) {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("waiters did not enroll")
}

func TestCheckerCoalescesDistinctCandidatesAndIndependentCancellation(t *testing.T) {
	// Fixed synthetic collision; suffixes differ, prefix-only provider data may
	// be shared but candidate match counts and scope cannot be shared.
	a := requestFor(t, "hibp-synthetic-748")
	b := requestFor(t, "hibp-synthetic-1195")
	b.TenantID = "second-tenant"
	da, _ := deriveCandidate(context.Background(), a.Candidate, 1024)
	defer da.clear()
	db, _ := deriveCandidate(context.Background(), b.Candidate, 1024)
	defer db.clear()
	if da.prefix != db.prefix || da.suffix == db.suffix {
		t.Fatal("invalid collision fixture")
	}
	arrived, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(arrived)
		}
		select {
		case <-release:
			fmt.Fprintf(w, "%s:13\n%s:29\n", da.suffix[:], db.suffix[:])
		case <-r.Context().Done():
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := launch(c, ctx, a)
	receive(t, arrived)
	second := launch(c, context.Background(), b)
	awaitEnrollment(t, c, 2)
	cancel()
	if r := receive(t, first); !errors.Is(r.err, context.Canceled) || r.result.Outcome != OutcomeCancelled {
		t.Fatal("first cancellation lost")
	}
	close(release)
	r := receive(t, second)
	if r.err != nil || r.result.BreachCount != 29 || r.result.TenantID != b.TenantID || r.result.ReplayID != b.ReplayID || calls.Load() != 1 {
		t.Fatal("surviving caller lost or scope/match shared", r.err)
	}
	r1, e := c.Check(context.Background(), a)
	if e != nil || r1.BreachCount != 13 || r1.ReplayID != a.ReplayID || calls.Load() != 1 {
		t.Fatal("cached data did not match locally", e)
	}
}

func TestCheckerAllWaitersCancelAndFreshRetry(t *testing.T) {
	arrived, cancelled := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(arrived)
			<-r.Context().Done()
			close(cancelled)
			return
		}
		fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
	})
	r := requestFor(t, "cancelled-synthetic")
	ctx, cancel := context.WithCancel(context.Background())
	first := launch(c, ctx, r)
	receive(t, arrived)
	cancel()
	receive(t, first)
	receive(t, cancelled)
	result, e := c.Check(context.Background(), r)
	if e != nil || result.Outcome != OutcomeNoMatch || calls.Load() != 2 {
		t.Fatal("abandoned flight absorbed retry", e)
	}
}

func TestCheckerQueuedCancellationCapacityAndShutdown(t *testing.T) {
	arrived, cancelled := make(chan struct{}, 8), make(chan struct{}, 8)
	var calls atomic.Int32
	c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		arrived <- struct{}{}
		<-r.Context().Done()
		cancelled <- struct{}{}
	})
	a := requestFor(t, "running-synthetic")
	b := requestFor(t, "queued-synthetic")
	running := launch(c, context.Background(), a)
	receive(t, arrived)
	ctx, cancel := context.WithCancel(context.Background())
	queued := launch(c, ctx, b)
	awaitEnrollment(t, c, 2)
	cancel()
	if r := receive(t, queued); !errors.Is(r.err, context.Canceled) {
		t.Fatal("queued cancellation lost")
	}
	queued = launch(c, context.Background(), b)
	awaitEnrollment(t, c, 2)
	if e := c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if r := receive(t, running); !errors.Is(r.err, ErrClosed) {
		t.Fatal("running call survived shutdown")
	}
	if r := receive(t, queued); !errors.Is(r.err, ErrClosed) {
		t.Fatal("queued call survived shutdown")
	}
	receive(t, cancelled)
	if calls.Load() != 1 {
		t.Fatal("queued request bypassed outbound bound or shutdown")
	}
	if _, e := c.Check(context.Background(), a); !errors.Is(e, ErrClosed) {
		t.Fatal("closed client admitted work")
	}
}

func TestCheckerAdmissionAndInvalidScopeDoNotSend(t *testing.T) {
	arrived := make(chan struct{})
	c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) { close(arrived); <-r.Context().Done() })
	c.config.MaxWaiters = 1 // configure before sharing; exercise exact capacity.
	r := requestFor(t, "capacity-synthetic")
	first := launch(c, context.Background(), r)
	receive(t, arrived)
	if _, e := c.Check(context.Background(), r); !errors.Is(e, ErrOverloaded) {
		t.Fatal("unbounded caller admission")
	}
	invalid := r
	invalid.PolicyVersion = "different"
	if _, e := c.Check(context.Background(), invalid); !errors.Is(e, ErrInvalidRequest) {
		t.Fatal("foreign policy admitted")
	}
	if e := c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	receive(t, first)
}

func TestCheckerLRUDisabledCacheAndClockRegression(t *testing.T) {
	var calls atomic.Int32
	c, clock := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
	})
	requests := make([]CheckRequest, 0, 101)
	seen := make(map[[5]byte]bool)
	for i := 0; len(requests) < 101; i++ {
		r := requestFor(t, fmt.Sprintf("lru-synthetic-%d", i))
		d, e := deriveCandidate(context.Background(), r.Candidate, 1024)
		if e != nil {
			t.Fatal(e)
		}
		if !seen[d.prefix] {
			seen[d.prefix] = true
			requests = append(requests, r)
		}
		d.clear()
	}
	for _, r := range requests[:100] {
		if _, e := c.Check(context.Background(), r); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := c.Check(context.Background(), requests[0]); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Check(context.Background(), requests[100]); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Check(context.Background(), requests[0]); e != nil || calls.Load() != 101 {
		t.Fatal("touched entry not retained", e)
	}
	if _, e := c.Check(context.Background(), requests[1]); e != nil || calls.Load() != 102 {
		t.Fatal("LRU entry not evicted", e)
	}
	clock.nanos.Add(-1)
	if _, e := c.Check(context.Background(), requests[0]); !errors.Is(e, ErrProviderUnavailable) || calls.Load() != 102 {
		t.Fatal("clock regression admitted stale evidence")
	}

	disabled, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
	disabled.config.DisableCache = true
	for range 2 {
		if _, e := disabled.Check(context.Background(), requests[0]); e != nil {
			t.Fatal(e)
		}
	}
	disabled.mu.Lock()
	count := len(disabled.cache)
	disabled.mu.Unlock()
	if count != 0 {
		t.Fatal("disabled cache retains suffixes")
	}
}

func TestCheckerProviderDeadlineAndPartialBody(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			cancelled := make(chan struct{})
			c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if partial {
					w.Header().Set("Content-Length", "1000")
					fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
					return
				}
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				close(cancelled)
			})
			c.config.Timeout = time.Second
			r, e := c.Check(context.Background(), requestFor(t, "deadline-synthetic"))
			if !errors.Is(e, ErrProviderUnavailable) || r.Outcome != OutcomeUnavailable {
				t.Fatal("partial/timeout became usable", e)
			}
			if !partial {
				receive(t, cancelled)
			}
			c.mu.Lock()
			entries := len(c.cache)
			c.mu.Unlock()
			if entries != 0 {
				t.Fatal("failure cached")
			}
		})
	}
}

func TestCheckerInvalidConfigurationAndRedaction(t *testing.T) {
	valid := testConfig()
	for _, mutate := range []func(*Config){
		func(c *Config) { c.ResponseBytes = 2<<20 + 1 },
		func(c *Config) { c.CacheBytes = 0 }, func(c *Config) { c.MaxWaiters = 1025 },
		func(c *Config) { c.Timeout = 0 }, func(c *Config) { c.UserAgent = "\n" },
		func(c *Config) { c.PolicyVersion = "" },
	} {
		cfg := valid
		mutate(&cfg)
		if cfg.valid() {
			t.Fatal("invalid profile accepted")
		}
	}
	c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "invalid") })
	r := requestFor(t, "redaction-synthetic-secret")
	_, e := c.Check(context.Background(), r)
	var classified *CheckError
	if !errors.As(e, &classified) || classified.Outcome != OutcomeMalformed {
		t.Fatal("untyped failure")
	}
	encoded, err := json.Marshal(r)
	if err == nil {
		t.Fatal("candidate serialized", string(encoded))
	}
	for _, rendered := range []string{fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", e), e.Error()} {
		if strings.Contains(rendered, "redaction-synthetic-secret") || strings.Contains(rendered, "/range/") {
			t.Fatal("sensitive rendering")
		}
	}
}

func TestCheckerPaddingProfilesAreExplicitAndIsolated(t *testing.T) {
	r := requestFor(t, "synthetic-padding-profile")
	// Equal candidate bytes with independent ownership permit simultaneous Use.
	unpaddedRequest := requestFor(t, "synthetic-padding-profile")
	derived, e := deriveCandidate(context.Background(), r.Candidate, 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer derived.clear()
	var paddedReads, unpaddedReads atomic.Int32
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	padded, wall := checkerFixture(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.Host != "api.pwnedpasswords.com" || req.URL.Path != "/range/"+string(derived.prefix[:]) || req.URL.RawQuery != "" || req.ContentLength != 0 || req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != "" || req.Header.Get("User-Agent") != testConfig().UserAgent {
			t.Error("padding changed the fixed prefix-only endpoint")
		}
		arrived <- struct{}{}
		select {
		case <-release:
		case <-req.Context().Done():
			return
		}
		values := req.Header.Values("Add-Padding")
		if len(values) == 1 && values[0] == "true" {
			paddedReads.Add(1)
			fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
		} else if len(values) == 0 {
			unpaddedReads.Add(1)
			fmt.Fprintf(w, "%s:7\n", derived.suffix[:])
		} else {
			t.Error("invalid padding header selection")
		}
	})
	cfg := testConfig()
	cfg.AddPadding = false
	checker, e := New(cfg, padded.http, wall)
	if e != nil {
		t.Fatal("explicit unpadded profile rejected", e)
	}
	unpadded := checker.(*Client)
	t.Cleanup(func() {
		if e := unpadded.Close(context.Background()); e != nil {
			t.Error(e)
		}
	})
	type result struct {
		value CheckResult
		err   error
	}
	cleanResults, matchResults := make(chan result, 1), make(chan result, 1)
	go func() { v, err := padded.Check(context.Background(), r); cleanResults <- result{v, err} }()
	go func() {
		v, err := unpadded.Check(context.Background(), unpaddedRequest)
		matchResults <- result{v, err}
	}()
	receive(t, arrived)
	receive(t, arrived)
	close(release)
	released = true
	cleanFirst, matchFirst := receive(t, cleanResults), receive(t, matchResults)
	if cleanFirst.err != nil || cleanFirst.value.Outcome != OutcomeNoMatch || matchFirst.err != nil || matchFirst.value.Outcome != OutcomeMatch || matchFirst.value.BreachCount != 7 {
		t.Fatal("concurrent cross-profile flight substitution")
	}
	for range 2 {
		clean, e := padded.Check(context.Background(), r)
		if e != nil || clean.Outcome != OutcomeNoMatch {
			t.Fatal("recommended padded profile changed", e)
		}
		match, e := unpadded.Check(context.Background(), r)
		if e != nil || match.Outcome != OutcomeMatch || match.BreachCount != 7 {
			t.Fatal("cross-profile provider cache substitution", e)
		}
	}
	if paddedReads.Load() != 1 || unpaddedReads.Load() != 1 {
		t.Fatal("padding profiles did not retain independent caches")
	}
	if err := r.Candidate.Use(func(b []byte) error {
		if string(b) != "synthetic-padding-profile" {
			t.Error("padding selection changed borrowed candidate")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUnpaddedCheckerRejectsCompleteMalformedRangeWithoutCaching(t *testing.T) {
	for _, tail := range []string{"invalid\n", strings.Repeat("X", 1024)} {
		t.Run(fmt.Sprintf("tail-%d", len(tail)), func(t *testing.T) {
			r := requestFor(t, "synthetic-unpadded-malformed")
			derived, err := deriveCandidate(context.Background(), r.Candidate, 1024)
			if err != nil {
				t.Fatal(err)
			}
			defer derived.clear()
			var calls atomic.Int32
			borrowed, wall := checkerFixture(t, func(w http.ResponseWriter, req *http.Request) {
				if len(req.Header.Values("Add-Padding")) != 0 {
					t.Error("unpadded request included padding header")
				}
				if calls.Add(1) == 1 {
					fmt.Fprintf(w, "%s:7\n%s", derived.suffix[:], tail)
					return
				}
				fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
			})
			cfg := testConfig()
			cfg.AddPadding = false
			checker, err := New(cfg, borrowed.http, wall)
			if err != nil {
				t.Fatal(err)
			}
			client := checker.(*Client)
			t.Cleanup(func() {
				if err := client.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			failed, err := client.Check(context.Background(), r)
			if !errors.Is(err, ErrMalformedRange) || failed.Outcome != OutcomeMalformed || failed.BreachCount != 0 || !failed.ProviderValidUntil.IsZero() {
				t.Fatal("matching prefix bypassed full unpadded range validation")
			}
			clean, err := client.Check(context.Background(), r)
			if err != nil || clean.Outcome != OutcomeNoMatch || calls.Load() != 2 {
				t.Fatal("malformed unpadded response was cached", err)
			}
		})
	}
}

func TestCheckerCacheBudgetIncludesBackingCapacity(t *testing.T) {
	c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		for i := 1; i <= 21; i++ {
			fmt.Fprintf(w, "%035X:1\n", i)
		}
	})
	c.config.CacheBytes = 1024
	if _, e := c.Check(context.Background(), requestFor(t, "capacity-rows-synthetic")); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) != 0 {
		t.Fatal("cache budget excluded retained backing capacity")
	}
}

type reorderedClock struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	base    time.Time
}

func (c *reorderedClock) Now() time.Time {
	if c.calls.Add(1) == 1 {
		close(c.entered)
		<-c.release
		return c.base
	}
	return c.base.Add(time.Second)
}

func TestCheckerConcurrentClockSamplesDoNotBecomeRegressions(t *testing.T) {
	c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
	w := &reorderedClock{entered: make(chan struct{}), release: make(chan struct{}), base: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)}
	c.clock = w
	r := requestFor(t, "reordered-clock-synthetic")
	first := launch(c, context.Background(), r)
	receive(t, w.entered)
	second, e := c.Check(context.Background(), r)
	if e != nil || second.Outcome != OutcomeNoMatch {
		close(w.release)
		t.Fatal("second clock observer failed", e)
	}
	close(w.release)
	if r := receive(t, first); r.err != nil || r.result.Outcome != OutcomeNoMatch {
		t.Fatal("forward clock sample reordered into false regression", r.err)
	}
}
