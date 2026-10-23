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

// Risk plan: test fixed policy/dimension mapping at the atomic backend port,
// original opaque key correlation, rejection/unknown conservation, bounded
// contexts and pre-dispatch rejection. Native SQL atomicity/replay is separately
// proven at rate-limit520c49f; this seam does not invent a counter algorithm.
type secretShared struct {
	ratelimit.StrictBackend
	last   ratelimit.AtomicBatchRequest
	calls  int
	mode   int
	cancel context.CancelFunc
}

func (*secretShared) Name() string { return "secret-test" }
func (b *secretShared) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded admission")
	}
	b.last = r
	b.calls++
	if b.mode == 2 {
		return ratelimit.AtomicBatchDecision{}, ratelimit.UnknownOutcome(nil)
	}
	if b.mode == 3 {
		return ratelimit.AtomicBatchDecision{}, ratelimit.ErrUnavailable
	}
	if b.mode == 4 {
		panic("synthetic-private-provider-text")
	}
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: b.mode != 1, Decisions: make([]ratelimit.Decision, len(r.Requests))}
	for i, request := range r.Requests {
		out.Decisions[i] = ratelimit.Decision{Allowed: out.Allowed, Remaining: request.Policy.Limit() - request.Cost, Limit: request.Policy.Limit(), Reset: request.Now.Add(request.Policy.Period()), Reason: ratelimit.ReasonAllowed}
		if b.mode == 1 {
			out.Decisions[i].Allowed = false
			out.Decisions[i].Remaining = 0
			out.Decisions[i].Reason = ratelimit.ReasonLimited
			out.Decisions[i].RetryAfter = time.Duration(i+1)*time.Second + time.Millisecond
		}
	}
	if b.mode == 5 {
		out.Decisions = out.Decisions[:1]
	}
	if b.cancel != nil {
		b.cancel()
	}
	if b.mode == 1 {
		return out, ratelimit.ErrRejected
	}
	return out, nil
}

func secretLimiter(t *testing.T) (*identityhttp.KeyedSecretRateLimiter, *secretShared) {
	t.Helper()
	b := &secretShared{}
	l, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: b, Namespace: "secret-test", Key: [32]byte{1}, Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, b
}
func secretRequest(t *testing.T) identityhttp.KeyedSecretRateRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("synthetic-original-retry"))
	if err != nil {
		t.Fatal(err)
	}
	return identityhttp.KeyedSecretRateRequest{OperationID: "identity.password.change", UserID: "user-secret", IdempotencyKey: key}
}

func TestKeyedSecretRateMapsFixedAtomicPolicyAndOriginalKey(t *testing.T) {
	l, b := secretLimiter(t)
	r := secretRequest(t)
	facts := safeFacts(t, "198.51.100.1")
	if out, err := l.Admit(context.Background(), facts, r); err != nil || !out.Allowed {
		t.Fatal(out, err)
	}
	first := b.last
	if len(first.Requests) != 2 || first.CommandID == "" {
		t.Fatal("missing atomic dimensions")
	}
	for _, bucket := range first.Requests {
		if bucket.Policy.Capacity() != 10 || bucket.Policy.Period() != 10*time.Minute || bucket.Policy.Algorithm() != ratelimit.TokenBucket || bucket.Policy.Consistency() != ratelimit.ConsistencyStrong || bucket.Policy.FailureMode() != ratelimit.FailClosed || bucket.Cost != 1 {
			t.Fatal("wrong canonical policy")
		}
		if strings.Contains(bucket.Key.String(), string(r.UserID)) || strings.Contains(bucket.Key.String(), "198.51.100.1") {
			t.Fatal("raw dimension disclosure")
		}
	}
	r = secretRequest(t) // New owner, exact original bytes: same scoped debit command.
	if _, err := l.Admit(context.Background(), facts, r); err != nil || b.last.CommandID != first.CommandID {
		t.Fatal("original-key correlation lost", err)
	}
	if _, err := l.Admit(context.Background(), safeFacts(t, "198.51.100.2"), r); err != nil || b.last.CommandID != first.CommandID || b.last.Requests[0].Key == first.Requests[0].Key {
		t.Fatal("changed IP must conflict against original command intent, not mint a new debit", err)
	}
	r.OperationID = "identity.username.update"
	if _, err := l.Admit(context.Background(), facts, r); err != nil || b.last.CommandID == first.CommandID || b.last.Requests[1].Key != first.Requests[1].Key {
		t.Fatal("operation scoping reset shared subject budget", err)
	}
	r.ChallengeID = "challenge-original"
	r.ChallengeLifetime = 3 * time.Minute
	if _, err := l.Admit(context.Background(), facts, r); err != nil || len(b.last.Requests) != 3 || b.last.Requests[2].Policy.Capacity() != 5 || b.last.Requests[2].Policy.Period() != r.ChallengeLifetime {
		t.Fatal("original challenge dimension missing", err)
	}
}

func TestPasskeyRemovalRepeatProfileRetainsOriginalKeyRateCustody(t *testing.T) {
	l, b := secretLimiter(t)
	r := secretRequest(t)
	r.OperationID = "identity.passkey.delete"
	facts := safeFacts(t, "198.51.100.1")
	if out, err := l.Admit(t.Context(), facts, r); err != nil || !out.Allowed {
		t.Fatal("native keyed removal denied", err)
	}
	first := b.last
	if len(first.Requests) != 2 || first.CommandID == "" {
		t.Fatal("missing shared removal dimensions")
	}
	if out, err := l.Admit(t.Context(), facts, r); err != nil || !out.Allowed || b.last.CommandID != first.CommandID {
		t.Fatal("original deletion retry changed debit", err)
	}
	r.OperationID = "identity.password.change"
	if _, err := l.Admit(t.Context(), facts, r); err != nil || b.last.CommandID == first.CommandID || b.last.Requests[1].Key != first.Requests[1].Key {
		t.Fatal("deletion isolated shared subject budget", err)
	}
	before := b.calls
	for _, operation := range []string{"identity.session.revoke-one", "identity.password.reset-inspect"} {
		r.OperationID = operation
		if _, err := l.Admit(t.Context(), facts, r); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("removal exception leaked into repeat", operation, err)
		}
	}
	if b.calls != before {
		t.Fatal("unsupported repeat debited")
	}
}

func TestKeyedSecretRateDenialUnknownAndCancellation(t *testing.T) {
	l, b := secretLimiter(t)
	r := secretRequest(t)
	facts := safeFacts(t, "198.51.100.1")
	b.mode = 1
	if out, err := l.Admit(context.Background(), facts, r); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != 3*time.Second {
		t.Fatal("longest rounded rejection lost", out, err)
	}
	for _, mode := range []int{2, 3, 4, 5} {
		b.mode = mode
		if out, err := l.Admit(context.Background(), facts, r); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed || out.RetryAfter != 0 || strings.Contains(err.Error(), "synthetic-private") {
			t.Fatal("failure permitted protected work", out, err)
		}
	}
	b.mode = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := b.calls
	if _, err := l.Admit(ctx, facts, r); !errors.Is(err, identityhttp.ErrRateUnavailable) || b.calls != before {
		t.Fatal("pre-cancellation dispatched")
	}
	ctx, cancel = context.WithCancel(context.Background())
	b.cancel = cancel
	if out, err := l.Admit(ctx, facts, r); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed {
		t.Fatal("canceled protected continuation allowed", out, err)
	}
	b.cancel = nil
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if l.Configured() {
		t.Fatal("closed owner valid")
	}
}

func TestKeyedSecretRateRejectsUnboundInputBeforeDispatch(t *testing.T) {
	l, b := secretLimiter(t)
	facts := safeFacts(t, "198.51.100.1")
	for _, modify := range []func(*identityhttp.KeyedSecretRateRequest){
		func(r *identityhttp.KeyedSecretRateRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *identityhttp.KeyedSecretRateRequest) { r.UserID = "" },
		func(r *identityhttp.KeyedSecretRateRequest) { r.OperationID = "identity.password.signin" },
		func(r *identityhttp.KeyedSecretRateRequest) { r.OperationID = "unknown" },
		func(r *identityhttp.KeyedSecretRateRequest) { r.ChallengeLifetime = time.Minute },
		func(r *identityhttp.KeyedSecretRateRequest) { r.ChallengeID = "challenge" },
	} {
		r := secretRequest(t)
		modify(&r)
		if _, err := l.Admit(context.Background(), facts, r); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid accepted", err)
		}
	}
	if b.calls != 0 {
		t.Fatal("invalid input reached backend")
	}
	if out, err := (*identityhttp.KeyedSecretRateLimiter)(nil).Admit(context.Background(), facts, secretRequest(t)); out.Allowed || !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil limiter")
	}
	if _, err := l.Admit(nil, facts, secretRequest(t)); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil context")
	}
	r := secretRequest(t)
	if raw, err := json.Marshal(r); err == nil || len(raw) != 0 {
		t.Fatal("implicit request serialization")
	}
	if strings.Contains(fmt.Sprintf("%#v", r), "user-secret") {
		t.Fatal("formatting disclosed subject")
	}
}
