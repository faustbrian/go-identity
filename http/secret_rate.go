package identityhttp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	identity "github.com/faustbrian/go-identity"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// KeyedSecretRateConfig selects shared fixed rate.secret buckets for canonical
// keyed and original-command operations. Shared must be a concurrency-safe native atomic
// owner (PostgreSQL requires its additive atomic schema); no per-item fallback
// exists. Shared and prompt concurrency-safe Now remain borrowed and must
// outlive calls. Namespace/Key are immutable deployment rate identity, not
// credential keys. Do not silently rotate them: doing so resets budgets and
// changes original debit-command correlation. MaximumDuration is 1ms..2s;
// earlier caller deadlines win. Constructors perform no admission/storage IO.
type KeyedSecretRateConfig struct {
	Shared          ratelimit.StrictAtomicBatchBackend
	Namespace       string
	Key             [32]byte
	Now             func() time.Time
	MaximumDuration time.Duration
}

// KeyedSecretRateRequest borrows exactly the owning operation's original key.
// UserID must be the current authenticated/capability subject, never a claimed
// body field. Optional ChallengeID and ChallengeLifetime must come together
// from the original challenge owner; lifetime is the immutable original policy,
// not remaining expiry or a request-selected duration. This input authenticates
// none of those facts and is not transport parsing. It has no alternate key.
// Non-keyed operations are unsupported: they require their own stable native
// debit correlation and must not manufacture an Idempotency-Key header.
type KeyedSecretRateRequest struct {
	OperationID       string
	UserID            identity.UserID
	IdempotencyKey    identity.IdempotencyKey
	ChallengeID       string
	ChallengeLifetime time.Duration
}

// OriginalCommandSecretRateRequest retains the stable native command of a
// canonical one-time secret operation. It must not manufacture an idempotency
// header or request key. UserID comes from current authenticated custody;
// challenge ID/lifetime come from the original native challenge owner, not
// claimed transport fields or a renewed expiry. Structure grants no authority.
type OriginalCommandSecretRateRequest struct {
	OperationID       string
	UserID            identity.UserID
	CommandID         identity.CommandID
	ChallengeID       string
	ChallengeLifetime time.Duration
}

// KeyedSecretRateLimiter enforces all applicable buckets through one explicit
// atomic dispatch and native retained outcome. It adds no counter algorithm,
// workflow journal, local fallback, automatic retry or goroutine. Share one
// owner across routes and requests. Independent calls/Close are safe; zero is
// invalid. Rate admission neither grants authentication/authorization nor
// bypasses the protected workflow's cumulative risk/abuse policy.
type KeyedSecretRateLimiter struct {
	shared             *ratelimit.StrictService
	config             KeyedSecretRateConfig
	operations         map[string]bool
	originalOperations map[string]bool
	closed             *atomic.Bool
}

// NewKeyedSecretRateLimiter freezes canonical keyed rate.secret selection.
// Every request requires trusted IP10/10m and tenant/subject10/10m; an original
// challenge adds5/lifetime. Buckets span selected operations, not per-route
// copies. Construction selects no route, advertised feature or HTTP metadata.
func NewKeyedSecretRateLimiter(c KeyedSecretRateConfig) (*KeyedSecretRateLimiter, error) {
	if c.Key == ([32]byte{}) || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 2*time.Second {
		return nil, ErrInvalidInput
	}
	if _, err := rateKey(c.Namespace, "secret-ip", "validation"); err != nil {
		return nil, ErrInvalidInput
	}
	shared, err := ratelimit.NewStrictService(c.Shared)
	if err != nil {
		return nil, ErrInvalidInput
	}
	operations := make(map[string]bool)
	originalOperations := make(map[string]bool)
	for id, row := range readCatalog() {
		if row.Rate == "rate.secret" && row.Idempotency == "keyed" && row.Exposure != "direct" {
			operations[id] = true
		}
		// Recovery-set rotation has an explicit native command, not a request
		// key. Preserve that command's debit without broadening other rotations.
		originalCommand := row.Idempotency == "once" || id == "identity.mfa.recovery-regenerate" && row.Idempotency == "rotate"
		if row.Rate == "rate.secret" && originalCommand && row.Exposure != "direct" {
			originalOperations[id] = true
		}
	}
	return &KeyedSecretRateLimiter{shared: shared, config: c, operations: operations, originalOperations: originalOperations, closed: &atomic.Bool{}}, nil
}

// Configured reports structural, observed nonterminal owner validity without
// IO. It is not health, authority or admission; Close may race afterward.
func (l *KeyedSecretRateLimiter) Configured() bool {
	return l != nil && l.shared != nil && l.closed != nil && !l.closed.Load()
}

// Admit performs one bounded atomic debit, never protected domain work. Same
// original key bytes/tenant/subject/operation preserve command identity; changed
// IP/challenge/policy is compared against the native original intent, not given
// a fresh command. Unknown outcomes reconcile only through the same input/key.
// Original challenge dimensions are caller-owned trusted facts, not overrides.
// Known denial returns ErrRateLimited and the longest exhausted delay, ceiling
// seconds clamped1..3600. Invalid input or an already closed/nil/zero owner
// denies before dispatch with ErrInvalidInput. Operational, ambiguous,
// contradictory, panicking, canceled or closure-after-dispatch paths fail closed
// with ErrRateUnavailable, never raw backend diagnostics. Cancellation after
// admission may leave a known debit: failure is not refund/rollback evidence.
// Hooks/domain work must separately honor the original cancellation and risk.
func (l *KeyedSecretRateLimiter) Admit(ctx context.Context, facts NetworkFacts, r KeyedSecretRateRequest) (out AuthRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthRateResult{}, ErrRateUnavailable
		}
	}()
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != RealmTenant || !l.operations[r.OperationID] || !ascii(string(r.UserID), 128, false) || r.ChallengeID == "" && r.ChallengeLifetime != 0 || r.ChallengeID != "" && (!ascii(r.ChallengeID, 128, false) || r.ChallengeLifetime <= 0) {
		return out, ErrInvalidInput
	}
	digest, keyErr := r.IdempotencyKey.Digest(l.config.Key)
	if keyErr != nil {
		return out, ErrInvalidInput
	}
	command := l.digest("command", l.config.Namespace, string(facts.TenantID()), string(r.UserID), r.OperationID, hex.EncodeToString(digest[:]))
	return l.admitSecret(ctx, facts, r.UserID, r.ChallengeID, r.ChallengeLifetime, command)
}

// AdmitOriginalCommand enforces the same shared secret buckets for canonical
// one-time operations. Original command/tenant/subject/operation retain debit
// identity across retry. Changed network/challenge inputs must reconcile with
// the atomic backend's original intent, not receive a successor debit command.
// It performs no challenge authentication, reservation or domain mutation.
func (l *KeyedSecretRateLimiter) AdmitOriginalCommand(ctx context.Context, facts NetworkFacts, r OriginalCommandSecretRateRequest) (AuthRateResult, error) {
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != RealmTenant || !l.originalOperations[r.OperationID] || !ascii(string(r.UserID), 128, false) || r.ChallengeID == "" && r.ChallengeLifetime != 0 || r.ChallengeID != "" && (!ascii(r.ChallengeID, 128, false) || r.ChallengeLifetime <= 0) {
		return AuthRateResult{}, ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return AuthRateResult{}, ErrInvalidInput
	}
	command := l.digest("original-command", l.config.Namespace, string(facts.TenantID()), string(r.UserID), r.OperationID, string(r.CommandID))
	return l.admitSecret(ctx, facts, r.UserID, r.ChallengeID, r.ChallengeLifetime, command)
}

func (l *KeyedSecretRateLimiter) admitSecret(ctx context.Context, facts NetworkFacts, user identity.UserID, challenge string, lifetime time.Duration, command string) (out AuthRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthRateResult{}, ErrRateUnavailable
		}
	}()
	type bucket struct {
		kind, value string
		capacity    uint64
		period      time.Duration
	}
	buckets := []bucket{{"secret-ip", facts.ClientIP().String(), 10, 10 * time.Minute}, {"secret-subject", l.digest("subject", string(facts.TenantID()), string(user)), 10, 10 * time.Minute}}
	if challenge != "" {
		buckets = append(buckets, bucket{"secret-challenge", l.digest("challenge", string(facts.TenantID()), challenge), 5, lifetime})
	}
	requests := make([]ratelimit.Request, len(buckets))
	for i, b := range buckets {
		key, keyErr := rateKey(l.config.Namespace, b.kind, b.value)
		policy, policyErr := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: "identity-http-" + b.kind, Revision: "identity-http-secret-1", Algorithm: ratelimit.TokenBucket, Capacity: b.capacity, Period: b.period, MaxCost: 1, Consistency: ratelimit.ConsistencyStrong})
		if keyErr != nil || policyErr != nil {
			return out, ErrInvalidInput
		}
		requests[i] = ratelimit.Request{Policy: policy, Key: key, Cost: 1}
	}
	ctx, cancel := context.WithTimeout(ctx, l.config.MaximumDuration)
	defer cancel()
	if ctx.Err() != nil {
		return out, ErrRateUnavailable
	}
	now := l.config.Now()
	if now.IsZero() {
		return out, ErrRateUnavailable
	}
	for i := range requests {
		requests[i].Now = now
	}
	decision, backendErr := l.shared.AdmitAtomicBatch(ctx, ratelimit.AtomicBatchRequest{CommandID: command, Requests: requests})
	if ctx.Err() != nil || l.closed.Load() {
		return out, ErrRateUnavailable
	}
	if errors.Is(backendErr, ratelimit.ErrRejected) {
		var retry time.Duration
		for _, bucket := range decision.Decisions {
			if bucket.Reason == ratelimit.ReasonLimited {
				retry = max(retry, bucket.RetryAfter)
			}
		}
		retry = min(max(retry, time.Second), time.Hour)
		out.RetryAfter = (retry + time.Second - 1) / time.Second * time.Second
		return out, ErrRateLimited
	}
	if backendErr != nil || !decision.Allowed {
		return out, ErrRateUnavailable
	}
	out.Allowed = true
	return out, nil
}

func (l *KeyedSecretRateLimiter) digest(parts ...string) string {
	mac := hmac.New(sha256.New, l.config.Key[:])
	mac.Write([]byte("identity.http.secret-rate.v1\x00"))
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		mac.Write(size[:])
		mac.Write([]byte(part))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// Close terminally denies new calls without closing borrowed storage. It is
// idempotent. Drain handlers before releasing dependencies; committed debits
// are not undone, and previously returned admission is not revoked.
func (l *KeyedSecretRateLimiter) Close() error {
	if l == nil || l.closed == nil {
		return ErrInvalidInput
	}
	l.closed.Store(true)
	return nil
}

// Format redacts runtime key/callback/backend configuration for every verb.
func (KeyedSecretRateConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.KeyedSecretRateConfig(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (KeyedSecretRateConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText denies implicit configuration text/map-key export.
func (KeyedSecretRateConfig) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// LogValue redacts deployment configuration.
func (KeyedSecretRateConfig) LogValue() slog.Value {
	return slog.StringValue("identityhttp.KeyedSecretRateConfig(redacted)")
}

// Format redacts original subject, key and challenge custody.
func (KeyedSecretRateRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.KeyedSecretRateRequest(redacted)")
}

// MarshalJSON denies implicit request export.
func (KeyedSecretRateRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText denies implicit request text/map-key export.
func (KeyedSecretRateRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// LogValue redacts original admission input.
func (KeyedSecretRateRequest) LogValue() slog.Value {
	return slog.StringValue("identityhttp.KeyedSecretRateRequest(redacted)")
}

// Format prevents traversal of retained keys and borrowed owners.
func (KeyedSecretRateLimiter) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.KeyedSecretRateLimiter(redacted)")
}

// MarshalJSON denies implicit runtime composition export.
func (KeyedSecretRateLimiter) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText denies implicit runtime composition text export.
func (KeyedSecretRateLimiter) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// LogValue redacts retained runtime composition.
func (KeyedSecretRateLimiter) LogValue() slog.Value {
	return slog.StringValue("identityhttp.KeyedSecretRateLimiter(redacted)")
}
