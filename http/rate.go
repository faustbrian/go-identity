package identityhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"time"

	identity "github.com/faustbrian/go-identity"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// ErrRateLimited denies a request whose applicable rate bucket is exhausted.
var ErrRateLimited = errors.New("identity.http.rate_limited")

// ErrRateUnavailable denies unavailable, ambiguous or invalid rate evidence.
// Backend diagnostics and subject identifiers are never retained.
var ErrRateUnavailable = errors.New("identity.http.rate_unavailable")

// SafeRateEvent attributes one emergency-store decision to a canonical
// operation. It contains no network address, tenant, subject or credential.
type SafeRateEvent struct {
	OperationID string
	Allowed     bool
}

// SafeRateConfig selects the canonical rate.safe profile, not custom limits.
// Shared is a borrowed concurrency-safe strong backend from the rate primitive;
// it must outlive calls. Namespace isolates a deployment (primitive key grammar).
// Now is a trusted, prompt concurrency-safe clock. Degraded must synchronously
// record each fallback decision within ctx and return an error on failure.
// No callback may retain ctx or launch detached work. MaximumDuration is
// 1ms..2s; earlier caller deadlines win. EmergencyMaximumKeys is 1..1000000.
// Use one shared limiter per process/namespace, not one per route or request;
// constructing independent instances creates independent emergency budgets.
type SafeRateConfig struct {
	Shared               ratelimit.StrictBackend
	Namespace            string
	Now                  func() time.Time
	Degraded             func(context.Context, SafeRateEvent) error
	MaximumDuration      time.Duration
	EmergencyMaximumKeys int
}

// SafeRateResult is one admission observation, never a reusable authority.
// Allowed is true only with nil error. Degraded identifies local fallback;
// RetryAfter is populated on a known limit denial, not on infrastructure errors.
type SafeRateResult struct {
	Allowed, Degraded bool
	RetryAfter        time.Duration
}

// SafeRateLimiter composes primitive-owned counters without a second rate
// algorithm. It borrows Shared, owns bounded process-local emergency storage,
// and starts no goroutines. Independent calls and Close are concurrency-safe.
// Zero is invalid. Bucket admission is ordered, not a refund transaction:
// an IP debit may remain when a later subject bucket denies or becomes unknown.
type SafeRateLimiter struct {
	shared, emergency  *ratelimit.StrictService
	store              *memory.Store
	config             SafeRateConfig
	ip, subject, local ratelimit.Policy
	closed             *atomic.Bool
	operations         map[string]bool
}

// Configured reports constructor validity and observed nonterminal local
// ownership without IO or callbacks. Nil/zero/closed owners are false. Close
// may race immediately afterward; true is not health, admission or a lease.
// Independent inspections, Admit and Close are concurrency-safe.
func (l *SafeRateLimiter) Configured() bool {
	return l != nil && l.shared != nil && l.store != nil && l.closed != nil && !l.closed.Load()
}

// NewSafeRateLimiter validates and freezes policy without storage IO. Shared
// must actually provide strong consistency; the primitive enforces the selected
// policy on each operation. The emergency store is deliberately process-local,
// bounded and fail-closed on saturation. No optional identity feature is imported.
func NewSafeRateLimiter(c SafeRateConfig) (*SafeRateLimiter, error) {
	if c.Now == nil || c.Degraded == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 2*time.Second || c.EmergencyMaximumKeys < 1 || c.EmergencyMaximumKeys > memory.MaxConfiguredKeys {
		return nil, ErrInvalidInput
	}
	if _, err := rateKey(c.Namespace, "ip", "validation"); err != nil {
		return nil, ErrInvalidInput
	}
	shared, err := ratelimit.NewStrictService(c.Shared)
	if err != nil {
		return nil, ErrInvalidInput
	}
	store, err := memory.New(memory.Options{MaxKeys: c.EmergencyMaximumKeys, Shards: 1, RejectOnCapacity: true})
	if err != nil {
		return nil, ErrInvalidInput
	}
	emergency, err := ratelimit.NewStrictService(store)
	if err != nil {
		store.Close()
		return nil, ErrInvalidInput
	}
	policy := func(id string, capacity uint64, consistency ratelimit.Consistency) ratelimit.Policy {
		p, _ := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: id, Revision: "identity-http-safe-1", Algorithm: ratelimit.TokenBucket, Capacity: capacity, Period: time.Minute, Consistency: consistency})
		return p
	}
	operations := make(map[string]bool)
	for id, row := range readCatalog() {
		if row.Rate == "rate.safe" {
			operations[id] = true
		}
	}
	return &SafeRateLimiter{shared: shared, emergency: emergency, store: store, config: c, operations: operations, closed: &atomic.Bool{},
		ip:      policy("identity-http-safe-ip", 100, ratelimit.ConsistencyStrong),
		subject: policy("identity-http-safe-subject", 300, ratelimit.ConsistencyStrong),
		local:   policy("identity-http-safe-emergency", 20, ratelimit.ConsistencyProcessLocal)}, nil
}

// Admit enforces trusted IP100/minute and, for a nonempty authenticated user,
// tenant-scoped subject300/minute. facts must come from NetworkResolver and
// user must come from current authenticated owner custody, never request input.
// operationID must name a canonical rate.safe row; no fallback for unknown rows.
// IP keys use the exact normalized full address, never subnet aggregation.
// Counters span all rate.safe operations, not independently per operation.
// Known shared-store unavailability selects IP20/minute emergency admission and
// emits a required bounded degradation event. Ambiguous dispatch, cancellation,
// malformed replies or event failure deny without fallback authority. This
// method does not authenticate, refresh proof, execute a handler or retry work.
func (l *SafeRateLimiter) Admit(ctx context.Context, facts NetworkFacts, operationID string, user identity.UserID) (out SafeRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = SafeRateResult{}, ErrRateUnavailable
		}
	}()
	if l == nil || l.shared == nil || l.closed == nil || l.closed.Load() || ctx == nil || !facts.Valid() || len(user) > 128 {
		return out, ErrInvalidInput
	}
	if !l.operations[operationID] || (user != "" && (facts.Realm() != RealmTenant || !ascii(string(user), 128, false))) {
		return out, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, l.config.MaximumDuration)
	defer cancel()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	now := l.config.Now()
	if now.IsZero() {
		return out, ErrRateUnavailable
	}
	ip, err := rateKey(l.config.Namespace, "ip", facts.ClientIP().String())
	if err != nil {
		return out, ErrRateUnavailable
	}
	request := ratelimit.Request{Policy: l.ip, Key: ip, Cost: 1, Now: now}
	decision, err := l.shared.Admit(ctx, request)
	if err == nil && user != "" {
		// Length framing prevents cross-tenant collisions even when IDs contain
		// separators. Hash before the primitive's bounded key parser so valid
		// maximum-length identity IDs cannot exceed its subject-size bound.
		tenant := string(facts.TenantID())
		digest := sha256.Sum256([]byte(strconv.Itoa(len(tenant)) + ":" + tenant + string(user)))
		key, keyErr := rateKey(l.config.Namespace, "subject", hex.EncodeToString(digest[:]))
		if keyErr != nil {
			return out, ErrRateUnavailable
		}
		decision, err = l.shared.Admit(ctx, ratelimit.Request{Policy: l.subject, Key: key, Cost: 1, Now: now})
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if errors.Is(err, ratelimit.ErrUnavailable) {
		request.Policy = l.local
		decision, err = l.emergency.Admit(ctx, request)
		if errors.Is(err, ratelimit.ErrUnavailable) && ctx.Err() == nil && !l.closed.Load() {
			// Reclaim only counters idle for a complete policy period. The owned
			// primitive never evicts active budgets. Sweep is bounded by the
			// configured cardinality and performs no IO or caller callbacks.
			removed, sweepErr := l.store.Sweep(now, time.Minute)
			if sweepErr == nil && removed > 0 && ctx.Err() == nil {
				decision, err = l.emergency.Admit(ctx, request)
			}
		}
		if ctx.Err() != nil {
			return SafeRateResult{}, ctx.Err()
		}
		if err != nil && !errors.Is(err, ratelimit.ErrRejected) {
			return SafeRateResult{}, ErrRateUnavailable
		}
		if eventErr := l.config.Degraded(ctx, SafeRateEvent{OperationID: operationID, Allowed: decision.Allowed}); eventErr != nil || ctx.Err() != nil || l.closed.Load() {
			return SafeRateResult{}, ErrRateUnavailable
		}
		out.Degraded = true
	}
	if l.closed.Load() {
		return SafeRateResult{}, ErrRateUnavailable
	}
	if errors.Is(err, ratelimit.ErrRejected) {
		out.RetryAfter = max(decision.RetryAfter, time.Second)
		return out, ErrRateLimited
	}
	if err != nil || !decision.Allowed {
		return SafeRateResult{}, ErrRateUnavailable
	}
	out.Allowed = true
	return out, nil
}

func rateKey(namespace, kind, value string) (ratelimit.Key, error) {
	return ratelimit.NewKey(ratelimit.KeySpec{Namespace: namespace, Version: "1", Subject: ratelimit.Subject{Kind: kind, Value: value}, Hash: true})
}

// Close terminally denies future admission and closes only owned emergency
// storage. It is idempotent and does not close the borrowed shared backend.
// It does not revoke admissions already returned or interrupt caller callbacks;
// the composition must drain handlers before releasing shared dependencies.
func (l *SafeRateLimiter) Close() error {
	if l == nil || l.store == nil {
		return ErrInvalidInput
	}
	l.closed.Store(true)
	return l.store.Close()
}

// Format prevents traversal of borrowed backend/callback configuration.
func (SafeRateLimiter) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.SafeRateLimiter(redacted)")
}

// MarshalJSON denies accidental export of runtime composition.
func (SafeRateLimiter) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText denies accidental export of runtime composition.
func (SafeRateLimiter) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }
