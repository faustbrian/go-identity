package organizationhttp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organization "github.com/faustbrian/go-organization"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// AdminRateEvent is required denial auditing without request secrets, tenant,
// actor, network address, submitted fields or underlying diagnostics. Reason
// is exactly limited or unavailable. This event is not a protected domain audit.
type AdminRateEvent struct {
	Operation organization.Operation
	Reason    string
}

// AdminRateConfig selects canonical rate.admin through the existing native
// strict atomic backend, not a local counter algorithm. Share one namespace/key
// and backend with all selected administrative routes; changing either resets
// effective budgets. Shared, prompt Now and synchronous Denied remain borrowed,
// bounded and concurrency-safe. Denied must durably audit every rejected or
// unavailable admission within ctx; errors/panics deny. MaximumDuration is
// 1ms..2s. No callback may retain requests or start detached work.
type AdminRateConfig struct {
	Shared          ratelimit.StrictAtomicBatchBackend
	Namespace       string
	Key             [32]byte
	Now             func() time.Time
	MaximumDuration time.Duration
	Denied          func(context.Context, AdminRateEvent) error
}

// AdminRateResult is one observation, never a reusable authority. RetryAfter
// is bounded ceiling seconds only for a known audited limit rejection.
type AdminRateResult struct {
	Allowed    bool
	RetryAfter time.Duration
}

// AdminRateLimiter borrows the sole native rate owner. It starts no goroutines,
// owns no backend shutdown and supports concurrent independent calls/Close.
// Its closed private state prevents recursive formatting from traversing keys.
type AdminRateLimiter struct{ state func() *adminRateState }
type adminRateState struct {
	shared   *ratelimit.StrictService
	config   AdminRateConfig
	policies [3]ratelimit.Policy
	closed   atomic.Bool
}

// NewAdminRateLimiter freezes the canonical policy without admission IO. The
// identity-platform API_OPERATIONS.md rate.admin row owns actor30/minute,
// tenant100/minute and trusted full-IP60/minute, atomic shared fail-closed
// admission plus mandatory secret-free denial auditing. Only this finite
// organization's create/update/member-add/update/remove/invitation-send/resend profile is
// selected here.
func NewAdminRateLimiter(c AdminRateConfig) (out *AdminRateLimiter, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, identityhttp.ErrInvalidInput
		}
	}()
	if c.Now == nil || c.Denied == nil || c.Key == ([32]byte{}) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 2*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := adminRateKey(c.Namespace, "admin-actor", "validation"); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	shared, err := ratelimit.NewStrictService(c.Shared)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	s := &adminRateState{shared: shared, config: c}
	for i, dimension := range []struct {
		kind     string
		capacity uint64
	}{{"actor", 30}, {"tenant", 100}, {"ip", 60}} {
		p, err := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: "identity-http-admin-" + dimension.kind, Revision: "identity-http-admin-1", Algorithm: ratelimit.TokenBucket, Capacity: dimension.capacity, Period: time.Minute, MaxCost: 1, Consistency: ratelimit.ConsistencyStrong})
		if err != nil {
			return nil, identityhttp.ErrInvalidInput
		}
		s.policies[i] = p
	}
	return &AdminRateLimiter{state: func() *adminRateState { return s }}, nil
}

// Configured inspects construction/closure only; it is not health or admission.
func (l *AdminRateLimiter) Configured() bool {
	return l != nil && l.state != nil && !l.state().closed.Load()
}

// Admit charges one HTTP attempt using a fresh owner-generated native debit
// identity. It never invents an Idempotency-Key, caches a free keyed retry,
// reconciles ambiguity by redispatch or performs domain work. The authenticated
// actor must come from current session custody and facts from NetworkResolver.
// Full IP and actor/tenant buckets are HMAC-protected and shared across routes.
func (l *AdminRateLimiter) Admit(ctx context.Context, facts identityhttp.NetworkFacts, op organization.Operation, user identity.UserID) (AdminRateResult, error) {
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != identityhttp.RealmTenant || !selectedMutation(op) || op == organization.InvitationAccept || op == organization.LeaveMember || !boundedID(string(user)) {
		return AdminRateResult{}, identityhttp.ErrInvalidInput
	}
	s := l.state()
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	out, err := s.admit(ctx, facts, user)
	if err == nil {
		return out, nil
	}
	reason := "unavailable"
	if errors.Is(err, identityhttp.ErrRateLimited) {
		reason = "limited"
	}
	if !s.audit(ctx, AdminRateEvent{Operation: op, Reason: reason}) {
		return AdminRateResult{}, identityhttp.ErrRateUnavailable
	}
	return out, err
}
func (s *adminRateState) audit(ctx context.Context, e AdminRateEvent) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return s.config.Denied(ctx, e) == nil
}
func (s *adminRateState) admit(ctx context.Context, facts identityhttp.NetworkFacts, user identity.UserID) (out AdminRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AdminRateResult{}, identityhttp.ErrRateUnavailable
		}
	}()
	if ctx.Err() != nil || s.closed.Load() {
		return out, identityhttp.ErrRateUnavailable
	}
	now := s.config.Now()
	if now.IsZero() {
		return out, identityhttp.ErrRateUnavailable
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return out, identityhttp.ErrRateUnavailable
	}
	values := []string{s.digest("actor", string(facts.TenantID()), string(user)), s.digest("tenant", string(facts.TenantID())), s.digest("ip", facts.ClientIP().String())}
	requests := make([]ratelimit.Request, 3)
	for i, kind := range []string{"admin-actor", "admin-tenant", "admin-ip"} {
		key, err := adminRateKey(s.config.Namespace, kind, values[i])
		if err != nil {
			return out, identityhttp.ErrRateUnavailable
		}
		requests[i] = ratelimit.Request{Policy: s.policies[i], Key: key, Cost: 1, Now: now}
	}
	decision, backendErr := s.shared.AdmitAtomicBatch(ctx, ratelimit.AtomicBatchRequest{CommandID: s.digest("attempt", string(id)), Requests: requests})
	if ctx.Err() != nil || s.closed.Load() {
		return out, identityhttp.ErrRateUnavailable
	}
	if errors.Is(backendErr, ratelimit.ErrRejected) {
		var retry time.Duration
		for _, d := range decision.Decisions {
			if d.Reason == ratelimit.ReasonLimited {
				retry = max(retry, d.RetryAfter)
			}
		}
		retry = min(max(retry, time.Second), time.Minute)
		out.RetryAfter = (retry + time.Second - 1) / time.Second * time.Second
		return out, identityhttp.ErrRateLimited
	}
	if backendErr != nil || !decision.Allowed {
		return out, identityhttp.ErrRateUnavailable
	}
	out.Allowed = true
	return out, nil
}
func (s *adminRateState) digest(parts ...string) string {
	h := hmac.New(sha256.New, s.config.Key[:])
	for _, part := range append([]string{s.config.Namespace, "identity-http-admin-v1"}, parts...) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func adminRateKey(namespace, kind, value string) (ratelimit.Key, error) {
	return ratelimit.NewKey(ratelimit.KeySpec{Namespace: namespace, Version: "identity-http-1", Subject: ratelimit.Subject{Kind: kind, Value: value}, Hash: true})
}

// Close denies future work without closing the caller's shared backend.
func (l *AdminRateLimiter) Close() error {
	if l != nil && l.state != nil {
		l.state().closed.Store(true)
	}
	return nil
}

// Format redacts immutable key policy and borrowed callbacks.
func (AdminRateConfig) Format(s fmt.State, _ rune) {
	s.Write([]byte("organizationhttp.AdminRateConfig(redacted)"))
}

// MarshalJSON prevents implicit key/policy export.
func (AdminRateConfig) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText prevents implicit runtime export.
func (AdminRateConfig) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// LogValue redacts runtime policy.
func (AdminRateConfig) LogValue() slog.Value {
	return slog.StringValue("organizationhttp.AdminRateConfig(redacted)")
}

// Format prevents traversal of live native owners.
func (AdminRateLimiter) Format(s fmt.State, _ rune) {
	s.Write([]byte("organizationhttp.AdminRateLimiter(redacted)"))
}

// MarshalJSON prevents implicit owner export.
func (AdminRateLimiter) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText prevents implicit owner export.
func (AdminRateLimiter) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// LogValue redacts borrowed owners.
func (AdminRateLimiter) LogValue() slog.Value {
	return slog.StringValue("organizationhttp.AdminRateLimiter(redacted)")
}
