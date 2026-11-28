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
// actor, network address, submitted fields or underlying diagnostics. Operation
// retains the exact selected organization, directory-sync, SCIM-create,
// impersonation-deny, impersonation-quorum or user-status ID. Reason is exactly
// limited or unavailable. This event is not a protected domain audit.
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
// admission plus mandatory secret-free denial auditing. Admit selects only its
// finite organization profile; AdmitDirectorySync selects directory-sync start
// and cancel, AdmitSCIMConnectionCreate selects only SCIM connection create,
// AdmitImpersonationDeny selects only impersonation deny, and
// AdmitImpersonationQuorum selects only the quorum read, and AdmitUserStatus
// selects only administrative user ban/unban. All use the same budgets and
// mandatory denial auditor.
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
	return l.admitOperation(ctx, facts, op, user)
}

// AdmitDirectorySync admits only identity.sso.directory-sync-start and
// identity.sso.directory-sync-cancel using this owner's existing atomic actor,
// tenant and full-IP budgets. The authenticated user and resolver-owned tenant
// facts have the same custody requirements as Admit. A nil error means Allowed;
// audited limit rejection returns bounded ceiling seconds in retryAfter. Other
// failures return no retry hint and deny admission. Denial auditing records the
// exact directory operation, never a substitute organization operation.
func (l *AdminRateLimiter) AdmitDirectorySync(ctx context.Context, facts identityhttp.NetworkFacts, operationID string, user identity.UserID) (retryAfter time.Duration, err error) {
	if operationID != "identity.sso.directory-sync-start" && operationID != "identity.sso.directory-sync-cancel" {
		return 0, identityhttp.ErrInvalidInput
	}
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != identityhttp.RealmTenant || !boundedID(string(user)) {
		return 0, identityhttp.ErrInvalidInput
	}
	out, err := l.admitOperation(ctx, facts, organization.Operation(operationID), user)
	if err != nil {
		return out.RetryAfter, err
	}
	if !out.Allowed {
		return 0, identityhttp.ErrRateUnavailable
	}
	return 0, nil
}

// AdmitUserStatus admits only identity.admin.user-ban and
// identity.admin.user-unban using this owner's existing atomic actor, tenant
// and trusted full-IP budgets, as selected by http/catalog.json's rate.admin.
// The caller must supply resolver-owned tenant facts and the actual current
// authenticated ordinary user, not the target user; admission grants no
// administrative authority. Each call charges a fresh attempt. Nil error means
// admitted; an audited limit returns ErrRateLimited and bounded ceiling seconds
// in retryAfter. Backend ambiguity or failed auditing returns ErrRateUnavailable
// without a retry hint. Invalid inputs and nil/closed owners return
// ErrInvalidInput before backend access. Audits retain the exact operation;
// aliases and generic organization/directory admission remain unsupported.
func (l *AdminRateLimiter) AdmitUserStatus(ctx context.Context, facts identityhttp.NetworkFacts, operationID string, user identity.UserID) (retryAfter time.Duration, err error) {
	if operationID != "identity.admin.user-ban" && operationID != "identity.admin.user-unban" {
		return 0, identityhttp.ErrInvalidInput
	}
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != identityhttp.RealmTenant || !boundedID(string(user)) {
		return 0, identityhttp.ErrInvalidInput
	}
	out, err := l.admitOperation(ctx, facts, organization.Operation(operationID), user)
	if err != nil {
		return out.RetryAfter, err
	}
	if !out.Allowed {
		return 0, identityhttp.ErrRateUnavailable
	}
	return 0, nil
}

// AdmitImpersonationDeny admits exactly identity.impersonation.deny through
// this owner's existing atomic actor, tenant and full-IP budgets. The caller
// must supply resolver-owned tenant facts and the actual current authenticated
// user; this method grants no impersonation authority. Each call charges a
// fresh attempt. Nil error means admitted; an audited limit returns
// ErrRateLimited and bounded ceiling seconds in retryAfter. Backend ambiguity
// or failed denial auditing returns ErrRateUnavailable without a retry hint.
// Nil/closed owners, invalid facts/context or malformed user IDs return
// ErrInvalidInput before backend access. Denial audits retain the exact
// impersonation operation; no fallback or operation override is accepted.
func (l *AdminRateLimiter) AdmitImpersonationDeny(ctx context.Context, facts identityhttp.NetworkFacts, user identity.UserID) (retryAfter time.Duration, err error) {
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != identityhttp.RealmTenant || !boundedID(string(user)) {
		return 0, identityhttp.ErrInvalidInput
	}
	out, err := l.admitOperation(ctx, facts, "identity.impersonation.deny", user)
	if err != nil {
		return out.RetryAfter, err
	}
	if !out.Allowed {
		return 0, identityhttp.ErrRateUnavailable
	}
	return 0, nil
}

// AdmitImpersonationQuorum admits exactly identity.impersonation.quorum using
// the same atomic actor, tenant and trusted full-IP budgets as administrative
// mutations, as required by http/catalog.json's rate.admin selection. Resolver-
// owned tenant facts and the actual current authenticated user are required;
// admission grants no read authority. Each call charges a fresh attempt. Nil
// error means admitted; audited limits return ErrRateLimited with bounded
// ceiling seconds. Backend ambiguity or failed auditing returns
// ErrRateUnavailable without a retry hint. Invalid inputs and nil/closed owners
// return ErrInvalidInput before backend access. Audits retain the exact quorum
// operation, without changing generic organization or directory admission.
func (l *AdminRateLimiter) AdmitImpersonationQuorum(ctx context.Context, facts identityhttp.NetworkFacts, user identity.UserID) (retryAfter time.Duration, err error) {
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != identityhttp.RealmTenant || !boundedID(string(user)) {
		return 0, identityhttp.ErrInvalidInput
	}
	out, err := l.admitOperation(ctx, facts, "identity.impersonation.quorum", user)
	if err != nil {
		return out.RetryAfter, err
	}
	if !out.Allowed {
		return 0, identityhttp.ErrRateUnavailable
	}
	return 0, nil
}

// AdmitSCIMConnectionCreate admits exactly identity.scim.connection-create
// through this owner's existing atomic actor, tenant and trusted-IP budgets.
// The caller must supply resolver-owned tenant facts and a user obtained from
// the actual current authenticated session; this method grants no creation
// authority. Each call consumes a fresh attempt even for an exact keyed retry.
// Known, successfully audited limits return ErrRateLimited and bounded
// RetryAfter; backend ambiguity and failed auditing return ErrRateUnavailable
// without a retry hint. Nil/closed owners, invalid facts/context or malformed
// user IDs return ErrInvalidInput before backend access. No operation override,
// process-local fallback, backend lifecycle or policy change is introduced.
func (l *AdminRateLimiter) AdmitSCIMConnectionCreate(ctx context.Context, facts identityhttp.NetworkFacts, user identity.UserID) (AdminRateResult, error) {
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != identityhttp.RealmTenant || !boundedID(string(user)) {
		return AdminRateResult{}, identityhttp.ErrInvalidInput
	}
	return l.admitOperation(ctx, facts, "identity.scim.connection-create", user)
}

func (l *AdminRateLimiter) admitOperation(ctx context.Context, facts identityhttp.NetworkFacts, op organization.Operation, user identity.UserID) (AdminRateResult, error) {
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
