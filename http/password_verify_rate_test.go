package identityhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// Risk plan: password verification has no original challenge or request key.
// Both trusted IP and current subject must debit atomically on every attempt;
// retry/unknown must not reuse or retry an admission command. The native rate
// adapter owns atomic persistence; this test observes its explicit public port.
func passwordVerifyLimiter(t *testing.T) (*identityhttp.PasswordVerificationRateLimiter, *secretShared) {
	t.Helper()
	b := &secretShared{}
	l, err := identityhttp.NewPasswordVerificationRateLimiter(identityhttp.PasswordVerificationRateConfig{
		Shared: b, Namespace: "verify-test", Key: [32]byte{1},
		Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, b
}

func TestPasswordVerificationRateDebitsAtomicOriginalDimensions(t *testing.T) {
	l, b := passwordVerifyLimiter(t)
	facts := safeFacts(t, "198.51.100.1")
	r := identityhttp.PasswordVerificationRateRequest{UserID: "verified-primary-user"}
	if out, err := l.Admit(context.Background(), facts, r); err != nil || !out.Allowed {
		t.Fatal(out, err)
	}
	first := b.last
	if len(first.Requests) != 2 || len(first.CommandID) != 64 {
		t.Fatal("missing atomic admission")
	}
	for i, bucket := range first.Requests {
		capacity := uint64(20)
		if i == 1 {
			capacity = 10
		}
		if bucket.Policy.Capacity() != capacity || bucket.Policy.Period() != 10*time.Minute || bucket.Policy.Algorithm() != ratelimit.TokenBucket || bucket.Policy.Consistency() != ratelimit.ConsistencyStrong || bucket.Policy.FailureMode() != ratelimit.FailClosed || bucket.Cost != 1 {
			t.Fatal("wrong canonical verify policy")
		}
		if strings.Contains(bucket.Key.String(), string(r.UserID)) || strings.Contains(bucket.Key.String(), "198.51.100.1") {
			t.Fatal("raw rate dimensions exposed")
		}
	}
	if out, err := l.Admit(context.Background(), facts, r); err != nil || !out.Allowed || b.last.CommandID == first.CommandID || b.last.Requests[1].Key != first.Requests[1].Key {
		t.Fatal("attempt did not receive fresh debit against same budget", err)
	}
	if _, err := l.Admit(context.Background(), safeFacts(t, "198.51.100.2"), r); err != nil || b.last.Requests[0].Key == first.Requests[0].Key || b.last.Requests[1].Key != first.Requests[1].Key {
		t.Fatal("changing IP reset subject budget", err)
	}
	r.UserID = "another-primary-user"
	if _, err := l.Admit(context.Background(), facts, r); err != nil || b.last.Requests[0].Key != first.Requests[0].Key || b.last.Requests[1].Key == first.Requests[1].Key {
		t.Fatal("subject isolation or shared IP budget lost", err)
	}
}

func TestPasswordVerificationRateFailsClosedWithoutRetry(t *testing.T) {
	l, b := passwordVerifyLimiter(t)
	r := identityhttp.PasswordVerificationRateRequest{UserID: "verified-primary-user"}
	facts := safeFacts(t, "198.51.100.1")
	b.mode = 1
	if out, err := l.Admit(context.Background(), facts, r); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != 3*time.Second {
		t.Fatal(out, err)
	}
	for _, mode := range []int{2, 3, 4, 5} {
		b.mode = mode
		before := b.calls
		if out, err := l.Admit(context.Background(), facts, r); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed || out.RetryAfter != 0 || b.calls != before+1 {
			t.Fatal("unavailable admission retried or allowed", out, err)
		}
	}
	b.mode = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := b.calls
	if _, err := l.Admit(ctx, facts, r); !errors.Is(err, identityhttp.ErrRateUnavailable) || b.calls != before {
		t.Fatal("canceled input dispatched")
	}
	ctx, cancel = context.WithCancel(context.Background())
	b.cancel = cancel
	if out, err := l.Admit(ctx, facts, r); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed {
		t.Fatal("canceled admission continued", out, err)
	}
	b.cancel = nil
	if err := l.Close(); err != nil || l.Configured() {
		t.Fatal("close", err)
	}
	before = b.calls
	if _, err := l.Admit(context.Background(), facts, r); !errors.Is(err, identityhttp.ErrInvalidInput) || b.calls != before {
		t.Fatal("closed owner dispatched")
	}
}

func TestPasswordVerificationRateRejectsInputAndRedacts(t *testing.T) {
	l, b := passwordVerifyLimiter(t)
	facts := safeFacts(t, "198.51.100.1")
	for _, user := range []string{"", "contains space", strings.Repeat("x", 129)} {
		if _, err := l.Admit(context.Background(), facts, identityhttp.PasswordVerificationRateRequest{UserID: identity.UserID(user)}); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid subject accepted")
		}
	}
	r := identityhttp.PasswordVerificationRateRequest{UserID: "verified-primary-user"}
	if _, err := l.Admit(nil, facts, r); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil context")
	}
	if _, err := l.Admit(context.Background(), identityhttp.NetworkFacts{}, r); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("untrusted facts")
	}
	if _, err := (*identityhttp.PasswordVerificationRateLimiter)(nil).Admit(context.Background(), facts, r); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil owner")
	}
	if b.calls != 0 {
		t.Fatal("invalid input dispatched")
	}
	for _, value := range []any{r, l, identityhttp.PasswordVerificationRateConfig{Key: [32]byte{1}}} {
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatal("implicit sensitive serialization")
		}
		if strings.Contains(fmt.Sprintf("%#v", value), "verified-primary-user") {
			t.Fatal("sensitive formatting")
		}
	}
}

func TestPasswordVerificationRateValidatesCompositionAndClock(t *testing.T) {
	valid := identityhttp.PasswordVerificationRateConfig{Shared: &secretShared{}, Namespace: "verify-test", Key: [32]byte{1}, Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second}
	for _, change := range []func(*identityhttp.PasswordVerificationRateConfig){
		func(c *identityhttp.PasswordVerificationRateConfig) { c.Shared = nil },
		func(c *identityhttp.PasswordVerificationRateConfig) { c.Namespace = "" },
		func(c *identityhttp.PasswordVerificationRateConfig) { c.Key = [32]byte{} },
		func(c *identityhttp.PasswordVerificationRateConfig) { c.Now = nil },
		func(c *identityhttp.PasswordVerificationRateConfig) {
			c.MaximumDuration = time.Millisecond - time.Nanosecond
		},
		func(c *identityhttp.PasswordVerificationRateConfig) {
			c.MaximumDuration = 2*time.Second + time.Nanosecond
		},
	} {
		c := valid
		change(&c)
		if l, err := identityhttp.NewPasswordVerificationRateLimiter(c); l != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid composition accepted")
		}
	}
	for _, now := range []func() time.Time{func() time.Time { return time.Time{} }, func() time.Time { panic("private-clock-detail") }} {
		c := valid
		c.Now = now
		l, err := identityhttp.NewPasswordVerificationRateLimiter(c)
		if err != nil {
			t.Fatal(err)
		}
		if out, err := l.Admit(context.Background(), safeFacts(t, "198.51.100.1"), identityhttp.PasswordVerificationRateRequest{UserID: "verified-primary-user"}); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed {
			t.Fatal("bad clock admitted")
		}
		l.Close()
	}
	if valid.Shared.(*secretShared).calls != 0 {
		t.Fatal("constructor or failed clock dispatched")
	}
	if (*identityhttp.PasswordVerificationRateLimiter)(nil).Configured() || !errors.Is((*identityhttp.PasswordVerificationRateLimiter)(nil).Close(), identityhttp.ErrInvalidInput) {
		t.Fatal("zero owner valid")
	}
}
