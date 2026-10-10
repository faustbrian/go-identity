package identityhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestChallengeVerificationRatePreservesOriginalDimensions(t *testing.T) {
	b := &secretShared{}
	l, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.PasswordVerificationRateConfig{Shared: b, Namespace: "verify-test", Key: [32]byte{1}, Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	facts := safeFacts(t, "198.51.100.1")
	r := identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.email.verification-confirm", UserID: "original-user", ChallengeID: "original-issued-grant", ChallengeLifetime: 24 * time.Hour}
	if out, err := l.AdmitIP(context.Background(), facts); err != nil || !out.Allowed || len(b.last.Requests) != 1 || b.last.Requests[0].Policy.Capacity() != 20 || b.last.Requests[0].Policy.Period() != 10*time.Minute {
		t.Fatal("missing pre-proof IP budget", err)
	}
	ip := b.last.Requests[0].Key
	if out, err := l.AdmitChallenge(context.Background(), facts, r); err != nil || !out.Allowed || len(b.last.Requests) != 2 {
		t.Fatal("missing authenticated original challenge budget", err)
	}
	first := b.last
	if first.Requests[0].Policy.Capacity() != 10 || first.Requests[0].Policy.Period() != 10*time.Minute || first.Requests[1].Policy.Capacity() != 10 || first.Requests[1].Policy.Period() != 24*time.Hour {
		t.Fatal("original policy rewritten")
	}
	for _, bucket := range first.Requests {
		if strings.Contains(bucket.Key.String(), string(r.UserID)) || strings.Contains(bucket.Key.String(), r.ChallengeID) {
			t.Fatal("raw source dimensions leaked")
		}
	}
	if _, err := l.Admit(context.Background(), facts, r); err != nil || len(b.last.Requests) != 3 || b.last.Requests[0].Key != ip || b.last.Requests[1].Key != first.Requests[0].Key || b.last.Requests[2].Key != first.Requests[1].Key || b.last.CommandID == first.CommandID {
		t.Fatal("combined attempt changed budgets or reused debit", err)
	}
	r.ChallengeID = "another-issued-grant"
	if _, err := l.AdmitChallenge(context.Background(), facts, r); err != nil || b.last.Requests[0].Key != first.Requests[0].Key || b.last.Requests[1].Key == first.Requests[1].Key {
		t.Fatal("new grant reset subject budget", err)
	}
	// Native OTP issuance preserves integral microseconds, not just seconds.
	// Its original policy must survive transport admission without rounding.
	r.ChallengeLifetime = 30*time.Second + 500*time.Millisecond
	if _, err := l.AdmitChallenge(context.Background(), facts, r); err != nil || b.last.Requests[1].Policy.Period() != r.ChallengeLifetime {
		t.Fatal("valid native challenge lifetime changed or rejected", err)
	}
}

func TestChallengeVerificationRateSharesPasswordBucketsAndCustody(t *testing.T) {
	b := &secretShared{}
	c := identityhttp.PasswordVerificationRateConfig{Shared: b, Namespace: "verify-test", Key: [32]byte{1}, Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second}
	l, err := identityhttp.NewChallengeVerificationRateLimiter(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	p, err := identityhttp.NewPasswordVerificationRateLimiter(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	f := safeFacts(t, "198.51.100.1")
	if _, err := p.Admit(context.Background(), f, identityhttp.PasswordVerificationRateRequest{UserID: "original-user"}); err != nil {
		t.Fatal(err)
	}
	password := b.last
	r := identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.email.verification-confirm", UserID: "original-user", ChallengeID: "original-grant", ChallengeLifetime: time.Hour}
	if _, err := l.Admit(context.Background(), f, r); err != nil || b.last.Requests[0].Key != password.Requests[0].Key || b.last.Requests[1].Key != password.Requests[1].Key {
		t.Fatal("sibling flow reset shared budgets", err)
	}
	for _, v := range []any{r, l, c} {
		if strings.Contains(fmt.Sprintf("%#v", v), "original-user") {
			t.Fatal("sensitive diagnostics")
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("implicit sensitive export")
		}
	}
	before := b.calls
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Admit(ctx, f, r); !errors.Is(err, identityhttp.ErrRateUnavailable) || b.calls != before {
		t.Fatal("cancelled admission dispatched")
	}
	if _, err := l.AdmitIP(nil, f); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil context")
	}
	if _, err := l.AdmitIP(context.Background(), identityhttp.NetworkFacts{}); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("invalid network")
	}
	if _, err := (*identityhttp.ChallengeVerificationRateLimiter)(nil).AdmitIP(context.Background(), f); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil owner")
	}
	b.cancel = func() { l.Close() }
	if out, err := l.Admit(context.Background(), f, r); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed {
		t.Fatal("closure after debit admitted")
	}
	before = b.calls
	if _, err := l.Admit(context.Background(), f, r); !errors.Is(err, identityhttp.ErrInvalidInput) || b.calls != before || l.Configured() {
		t.Fatal("closed owner dispatched")
	}
}

func TestChallengeVerificationRateRejectsUnsafeSourceAndFailure(t *testing.T) {
	b := &secretShared{}
	l, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.PasswordVerificationRateConfig{Shared: b, Namespace: "verify-test", Key: [32]byte{1}, Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := safeFacts(t, "198.51.100.1")
	r := identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.email.verification-confirm", UserID: "original-user", ChallengeID: "original-grant", ChallengeLifetime: time.Hour}
	for _, change := range []func(*identityhttp.ChallengeVerificationRateRequest){
		func(r *identityhttp.ChallengeVerificationRateRequest) { r.OperationID = "identity.password.verify" },
		func(r *identityhttp.ChallengeVerificationRateRequest) { r.OperationID = "identity.password.signup" },
		func(r *identityhttp.ChallengeVerificationRateRequest) { r.UserID = "" },
		func(r *identityhttp.ChallengeVerificationRateRequest) { r.ChallengeID = "" },
		func(r *identityhttp.ChallengeVerificationRateRequest) { r.ChallengeLifetime = 0 },
		func(r *identityhttp.ChallengeVerificationRateRequest) {
			r.ChallengeLifetime = 24*time.Hour + time.Second
		},
		func(r *identityhttp.ChallengeVerificationRateRequest) { r.ChallengeLifetime = time.Second + 1 },
	} {
		bad := r
		change(&bad)
		if _, err := l.Admit(context.Background(), f, bad); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("unsafe source admitted", err)
		}
	}
	if b.calls != 0 {
		t.Fatal("invalid input dispatched")
	}
	for _, mode := range []int{1, 2, 3, 4, 5} {
		b.mode = mode
		before := b.calls
		out, err := l.Admit(context.Background(), f, r)
		if err == nil || out.Allowed || b.calls != before+1 {
			t.Fatal("failure retried or allowed")
		}
		if mode == 1 && (!errors.Is(err, identityhttp.ErrRateLimited) || out.RetryAfter != 4*time.Second) {
			t.Fatal("wrong longest bounded delay", out, err)
		}
	}
}
