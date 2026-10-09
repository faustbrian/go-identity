package identityhttp_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

func authLimiter(t *testing.T, clock func() time.Time) (*identityhttp.AuthRateLimiter, *safeShared) {
	t.Helper()
	store, err := memory.New(memory.Options{MaxKeys: 4096, Shards: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	shared := &safeShared{Store: store}
	l, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: shared, Namespace: "http-auth", Now: clock, IdentifierKey: [32]byte{1}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, shared
}

func TestAuthRateCanonicalSigninIdentifierAndIP(t *testing.T) {
	now := func() time.Time { return time.Unix(1800000000, 0) }
	l, _ := authLimiter(t, now)
	for i := 0; i < 11; i++ {
		// Changing operation/IP cannot reset the shared signin identifier budget.
		op := "identity.otp.signin"
		if i%2 == 1 {
			op = "identity.password.signin"
		}
		out, err := l.Admit(context.Background(), safeFacts(t, fmt.Sprintf("198.51.100.%d", i+1)), identityhttp.AuthRateRequest{OperationID: op, Identifier: "person@example.invalid"})
		if i < 10 && (err != nil || !out.Allowed) {
			t.Fatal("identifier denied early", i, err)
		}
		if i == 10 && (!errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != time.Minute) {
			t.Fatal("identifier budget bypass", err, out)
		}
	}
	l2, _ := authLimiter(t, now)
	for i := 0; i < 21; i++ {
		out, err := l2.Admit(context.Background(), safeFacts(t, "198.51.100.1"), identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: fmt.Sprintf("person%d@example.invalid", i)})
		if i < 20 && (err != nil || !out.Allowed) {
			t.Fatal("IP denied early", i, err)
		}
		if i == 20 && (!errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != 30*time.Second) {
			t.Fatal("IP bypass", err, out)
		}
	}
}

func TestAuthRateSplitSigninPreservesOneSharedDebitPerDimension(t *testing.T) {
	l, _ := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	ctx := context.Background()
	facts := safeFacts(t, "198.51.100.1")
	for i := 0; i < 20; i++ {
		if out, err := l.AdmitSigninIP(ctx, facts, "identity.otp.signin"); err != nil || !out.Allowed {
			t.Fatal("split IP denied early", i, err)
		}
		if out, err := l.AdmitSigninIdentifier(ctx, facts, identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: fmt.Sprintf("original%d@example.invalid", i)}); err != nil || !out.Allowed {
			t.Fatal("identifier denied or IP double-debited", i, err)
		}
	}
	if out, err := l.AdmitSigninIP(ctx, facts, "identity.password.signin"); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed {
		t.Fatal("split IP differs from existing signin bucket")
	}
	l2, _ := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	for i := 0; i < 10; i++ {
		if out, err := l2.AdmitSigninIdentifier(ctx, facts, identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: "same@example.invalid"}); err != nil || !out.Allowed {
			t.Fatal(err)
		}
	}
	if out, err := l2.Admit(ctx, safeFacts(t, "198.51.100.2"), identityhttp.AuthRateRequest{OperationID: "identity.password.signin", Identifier: "same@example.invalid"}); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed {
		t.Fatal("split identifier differs from existing bucket")
	}
}

func TestAuthRateSplitSigninRejectsInvalidAndUnavailable(t *testing.T) {
	l, b := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	ctx := context.Background()
	facts := safeFacts(t, "198.51.100.1")
	for _, op := range []string{"", "unknown", "identity.otp.send"} {
		if _, err := l.AdmitSigninIP(ctx, facts, op); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid signin selector accepted")
		}
	}
	if _, err := l.AdmitSigninIdentifier(ctx, facts, identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: "valid@example.invalid", UserID: "claimed"}); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("subject override accepted")
	}
	b.mode.Store(1)
	if out, err := l.AdmitSigninIP(ctx, facts, "identity.otp.signin"); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed {
		t.Fatal("IP outage allowed")
	}
	if out, err := l.AdmitSigninIdentifier(ctx, facts, identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: "valid@example.invalid"}); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed {
		t.Fatal("identifier outage allowed")
	}
	if _, err := (*identityhttp.AuthRateLimiter)(nil).AdmitSigninIP(ctx, facts, "identity.otp.signin"); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil accepted")
	}
}

func TestAuthRateDeliveryIdentifierSubjectAndContinuousRefill(t *testing.T) {
	var millis atomic.Int64
	millis.Store(1800000000000)
	l, _ := authLimiter(t, func() time.Time { return time.UnixMilli(millis.Load()) })
	facts := safeFacts(t, "198.51.100.1")
	request := identityhttp.AuthRateRequest{OperationID: "identity.otp.send", Identifier: "person@example.invalid", UserID: "user-a"}
	for i := 0; i < 5; i++ {
		if out, err := l.Admit(context.Background(), facts, request); err != nil || !out.Allowed {
			t.Fatal(err)
		}
	}
	if out, err := l.Admit(context.Background(), facts, request); !errors.Is(err, identityhttp.ErrRateLimited) || out.RetryAfter != 12*time.Minute {
		t.Fatal("delivery budget", err, out)
	}
	millis.Add(6 * 60 * 1000)
	if out, err := l.Admit(context.Background(), facts, request); !errors.Is(err, identityhttp.ErrRateLimited) || out.RetryAfter != 6*time.Minute {
		t.Fatal("premature continuous refill", err, out)
	}
	millis.Add(6 * 60 * 1000)
	if out, err := l.Admit(context.Background(), facts, request); err != nil || !out.Allowed {
		t.Fatal("continuous refill unavailable", err)
	}
	l2, _ := authLimiter(t, func() time.Time { return time.UnixMilli(millis.Load()) })
	for i := 0; i < 11; i++ {
		out, err := l2.Admit(context.Background(), safeFacts(t, fmt.Sprintf("198.51.100.%d", i+1)), identityhttp.AuthRateRequest{OperationID: "identity.otp.send", Identifier: fmt.Sprintf("other%d@example.invalid", i), UserID: "user-a"})
		if i < 10 && (err != nil || !out.Allowed) {
			t.Fatal("subject denied early", err)
		}
		if i == 10 && (!errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed) {
			t.Fatal("subject budget bypass", err)
		}
	}
}

func TestAuthRateFailsClosedWithoutEmergencyOrSecretDisclosure(t *testing.T) {
	l, b := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	f := safeFacts(t, "198.51.100.1")
	r := identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: "private@example.invalid"}
	for _, mode := range []int32{1, 2} {
		b.mode.Store(mode)
		if out, err := l.Admit(context.Background(), f, r); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed || out.RetryAfter != 0 {
			t.Fatal("outage granted admission", err)
		}
	}
	b.mode.Store(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := l.Admit(ctx, f, r); err == nil || out.Allowed {
		t.Fatal("cancellation admitted")
	}
	for _, bad := range []identityhttp.AuthRateRequest{{OperationID: "identity.session.get", Identifier: r.Identifier}, {OperationID: r.OperationID}, {OperationID: r.OperationID, Identifier: "bad\nidentifier"}} {
		if out, err := l.Admit(context.Background(), f, bad); !errors.Is(err, identityhttp.ErrInvalidInput) || out.Allowed {
			t.Fatal("invalid rate selection admitted", err)
		}
	}
	if strings.Contains(fmt.Sprintf("%+v %#+v", r, l), r.Identifier) {
		t.Fatal("diagnostics disclosed identifier")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if l.Configured() {
		t.Fatal("closed owner configured")
	}
	if out, err := l.Admit(context.Background(), f, r); err == nil || out.Allowed {
		t.Fatal("closed owner admitted")
	}
}

func TestAuthRateConcurrentIdentifierCeiling(t *testing.T) {
	l, _ := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		f := safeFacts(t, fmt.Sprintf("198.51.100.%d", i+1))
		wg.Go(func() {
			out, err := l.Admit(context.Background(), f, identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: "person@example.invalid"})
			if err == nil && out.Allowed {
				allowed.Add(1)
			} else if !errors.Is(err, identityhttp.ErrRateLimited) {
				t.Error("unexpected denial", err)
			}
		})
	}
	wg.Wait()
	if allowed.Load() != 10 {
		t.Fatal("concurrent identifier ceiling", allowed.Load())
	}
}

type authRateProbe struct {
	*safeShared
	delay    time.Duration
	requests []ratelimit.Request
}

func (b *authRateProbe) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	b.requests = append(b.requests, r)
	if b.delay >= 0 {
		err, _ := ratelimit.NewBackendError(ratelimit.ErrRejected)
		return ratelimit.Decision{Limit: r.Policy.Limit(), Reason: ratelimit.ReasonLimited, Reset: r.Now.Add(time.Hour), RetryAfter: b.delay}, err
	}
	return b.safeShared.AdmitStrict(ctx, r)
}

func TestAuthRateRetryCeilingCannotOverflow(t *testing.T) {
	_, shared := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	probe := &authRateProbe{safeShared: shared}
	l, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: probe, Namespace: "retry-probe", Now: func() time.Time { return time.Unix(1800000000, 0) }, IdentifierKey: [32]byte{1}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	for _, tc := range []struct{ delay, want time.Duration }{{0, time.Second}, {time.Second + 1, 2 * time.Second}, {time.Duration(math.MaxInt64), time.Hour}} {
		probe.delay = tc.delay
		out, err := l.Admit(context.Background(), safeFacts(t, "198.51.100.1"), identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: "person@example.invalid"})
		if !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != tc.want {
			t.Fatal("retry bound violated", tc.delay, out, err)
		}
	}
}

func TestAuthRateTenantIsolationAndPersistedKeyPrivacy(t *testing.T) {
	_, shared := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	probe := &authRateProbe{safeShared: shared, delay: -1}
	l, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: probe, Namespace: "tenant-probe", Now: func() time.Time { return time.Unix(1800000000, 0) }, IdentifierKey: [32]byte{1}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	c := networkConfig()
	c.TenantHosts = append(c.TenantHosts, identityhttp.TenantHost{Host: "other.example", TenantID: "tenant-b"})
	n, err := identityhttp.NewNetworkResolver(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"tenant.example", "other.example"} {
		for i := 0; i < 10; i++ {
			r := httptest.NewRequest("POST", "/v1/otp/signin", nil)
			r.Host = host
			r.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i+1)
			f, err := n.Resolve(r)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := l.Admit(context.Background(), f, identityhttp.AuthRateRequest{OperationID: "identity.otp.signin", Identifier: "person@example.invalid"}); err != nil || !out.Allowed {
				t.Fatal("tenant budget conflated", host, i, err)
			}
		}
	}
	for _, request := range probe.requests {
		key := request.Key.String()
		if strings.Contains(key, "person") || strings.Contains(key, "tenant-a") || strings.Contains(key, "198.51.100") || request.Policy.Consistency() != ratelimit.ConsistencyStrong {
			t.Fatal("unsafe persisted dimension")
		}
	}
	if probe.requests[1].Key.String() == probe.requests[21].Key.String() {
		t.Fatal("tenant identifier digests collided")
	}
}
