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
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// AuthRateConfig selects fixed original-flow, signup, signin and delivery
// policies, not caller-defined capacities. Shared must be a borrowed strong
// backend; Now must be a trusted prompt concurrency-safe clock. IdentifierKey
// is a stable nonzero deployment HMAC key, independent of credential keys.
// Namespace isolates deployment state. MaximumDuration is 1ms..2s; earlier
// caller deadlines win. Retain this owner across routes and requests. Changing
// its namespace/key resets corresponding budgets and requires deliberate rollout.
type AuthRateConfig struct {
	Shared          ratelimit.StrictBackend
	Namespace       string
	Now             func() time.Time
	IdentifierKey   [32]byte
	MaximumDuration time.Duration
}

// AuthRateRequest supplies the canonical operation and actual owning workflow's
// normalized identifier. Never use an unrelated client-claimed identifier for
// challenge completion: resolve original challenge custody first. UserID, when
// present, must come from authenticated current owner custody, not JSON. This
// input performs no normalization or authentication. Identifiers are 1..1024
// UTF-8 bytes without whitespace/control characters; subjects are 1..128 ASCII
// bytes when present. Neither raw value is a backend key or diagnostic field.
type AuthRateRequest struct {
	OperationID string
	Identifier  string
	UserID      identity.UserID
}

// AuthRateResult is a request-local observation, never authentication or a
// reusable clearance. Allowed requires nil error. RetryAfter on a known denial
// is the longest exhausted bucket delay, rounded up and clamped to 1s..1h.
type AuthRateResult struct {
	Allowed    bool
	RetryAfter time.Duration
}

// AuthRateLimiter composes primitive-owned atomic token buckets with no local
// fallback, retry, goroutine or owned store. Independent calls/Close are safe.
// Multiple bucket debits are ordered per-item, not an all-or-nothing transaction:
// earlier successful debits remain after a later denial/failure. All applicable
// buckets must allow before the workflow may proceed. Zero is invalid.
type AuthRateLimiter struct {
	shared     *ratelimit.StrictService
	config     AuthRateConfig
	operations map[string]RatePolicyID
	closed     *atomic.Bool
}

// NewAuthRateLimiter freezes selected policy without admission or storage IO.
// All signin operations share IP20/10m and tenant/identifier10/10m. Delivery
// operations share IP10/h, tenant/identifier5/h and, when authenticated,
// tenant/subject10/h. Signup shares IP5/h and tenant/identifier3/day without a
// subject dimension. Different profiles have independent budgets. Identifier
// and subject key derivation length-frames the tenant and value under HMAC.
func NewAuthRateLimiter(c AuthRateConfig) (*AuthRateLimiter, error) {
	if c.Now == nil || c.IdentifierKey == ([32]byte{}) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 2*time.Second {
		return nil, ErrInvalidInput
	}
	if _, err := rateKey(c.Namespace, "signin-ip", "validation"); err != nil {
		return nil, ErrInvalidInput
	}
	shared, err := ratelimit.NewStrictService(c.Shared)
	if err != nil {
		return nil, ErrInvalidInput
	}
	operations := make(map[string]RatePolicyID)
	for id, row := range readCatalog() {
		if row.Rate == "rate.signup" || row.Rate == "rate.signin" || row.Rate == "rate.delivery" {
			operations[id] = row.Rate
		}
	}
	return &AuthRateLimiter{shared: shared, config: c, operations: operations, closed: &atomic.Bool{}}, nil
}

// Configured reports structural, nonterminal owner validity without IO. Close
// may race immediately afterward; true is not health or an admission lease.
func (l *AuthRateLimiter) Configured() bool {
	return l != nil && l.shared != nil && l.closed != nil && !l.closed.Load()
}

// AdmitOriginalFlow applies rate.auth's IP-only 20/10m token bucket before a
// tenant-bound browser flow exists. No identifier or challenge exists at this
// stage; this method is not suitable for operations that already have either.
// Full normalized IP budgets span tenants and owners sharing the namespace,
// independently of signin/delivery. Call before entropy or durable flow work.
// The caller still owns HTTPS, origin and all other operation admission.
// Outage, ambiguity, panic and cancellation fail closed without fallback;
// an earlier caller deadline wins. Admission is not a reusable clearance.
func (l *AuthRateLimiter) AdmitOriginalFlow(ctx context.Context, facts NetworkFacts) (out AuthRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthRateResult{}, ErrRateUnavailable
		}
	}()
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != RealmTenant {
		return out, ErrInvalidInput
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
	key, keyErr := rateKey(l.config.Namespace, "auth-ip", facts.ClientIP().String())
	policy, policyErr := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: "identity-http-auth-ip", Revision: "identity-http-auth-1", Algorithm: ratelimit.TokenBucket, Capacity: 20, Period: 10 * time.Minute, Consistency: ratelimit.ConsistencyStrong})
	if keyErr != nil || policyErr != nil {
		return out, ErrInvalidInput
	}
	return l.admitRequests(ctx, []ratelimit.Request{{Policy: policy, Key: key, Cost: 1, Now: now}})
}

// Admit checks all selected buckets under one bounded context and trusted clock
// observation. Unknown operations, missing dimensions and malformed inputs deny
// before any backend work. Known exhaustion evaluates remaining buckets to retain
// the longest retry delay. Outage, ambiguity, cancellation or invalid backend
// results return ErrRateUnavailable with no positive observation or fallback.
// The owner neither authenticates nor runs/retries protected domain work.
func (l *AuthRateLimiter) Admit(ctx context.Context, facts NetworkFacts, r AuthRateRequest) (out AuthRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthRateResult{}, ErrRateUnavailable
		}
	}()
	if !l.Configured() || ctx == nil || !facts.Valid() || !rateIdentifier(r.Identifier) || len(r.UserID) > 128 || r.UserID != "" && (!ascii(string(r.UserID), 128, false) || facts.Realm() != RealmTenant) {
		return out, ErrInvalidInput
	}
	profile := l.operations[r.OperationID]
	if profile == "" || profile == "rate.signup" && (r.UserID != "" || facts.Realm() != RealmTenant) {
		return out, ErrInvalidInput
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
	name, period, ipCapacity, identifierCapacity := "signin", 10*time.Minute, uint64(20), uint64(10)
	identifierPeriod := period
	if profile == "rate.delivery" {
		name, period, ipCapacity, identifierCapacity = "delivery", time.Hour, 10, 5
		identifierPeriod = period
	} else if profile == "rate.signup" {
		name, period, ipCapacity, identifierCapacity = "signup", time.Hour, 5, 3
		identifierPeriod = 24 * time.Hour
	}
	type bucket struct {
		kind, value string
		capacity    uint64
		period      time.Duration
	}
	buckets := []bucket{{name + "-ip", facts.ClientIP().String(), ipCapacity, period}, {name + "-identifier", l.digest(name, "identifier", string(facts.TenantID()), r.Identifier), identifierCapacity, identifierPeriod}}
	if profile == "rate.delivery" && r.UserID != "" {
		buckets = append(buckets, bucket{name + "-subject", l.digest(name, "subject", string(facts.TenantID()), string(r.UserID)), 10, period})
	}
	requests := make([]ratelimit.Request, len(buckets))
	for i, b := range buckets {
		key, keyErr := rateKey(l.config.Namespace, b.kind, b.value)
		policy, policyErr := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: "identity-http-" + b.kind, Revision: "identity-http-auth-1", Algorithm: ratelimit.TokenBucket, Capacity: b.capacity, Period: b.period, Consistency: ratelimit.ConsistencyStrong})
		if keyErr != nil || policyErr != nil {
			return out, ErrInvalidInput
		}
		requests[i] = ratelimit.Request{Policy: policy, Key: key, Cost: 1, Now: now}
	}
	return l.admitRequests(ctx, requests)
}

// AdmitSigninIP applies the existing shared rate.signin trusted-IP20/10m
// bucket before original-custody/source lookup. Only canonical signin operations
// and mapped tenant facts are accepted. On nil-error Allowed, the transport may
// discover its native canonical source, then call AdmitSigninIdentifier once.
// A failed source lookup retains this debit. Do not also call Admit for the same
// request: that would debit IP twice. Admission is request-local, not authority
// or a reusable clearance. Cancellation, panic and backend outage deny without
// fallback. This method neither reads custody nor creates an identifier bucket.
func (l *AuthRateLimiter) AdmitSigninIP(ctx context.Context, facts NetworkFacts, operationID string) (AuthRateResult, error) {
	return l.admitAuthDimension(ctx, facts, operationID, "", false, "rate.signin")
}

// AdmitSigninIdentifier applies only the existing tenant/canonical-identifier
// rate.signin10/10m bucket after native source discovery. The caller MUST first
// obtain AdmitSigninIP for this same request; this method grants no independent
// complete admission. Identifier must come from the original authenticated
// workflow custody, never a replacement request field. UserID must be empty.
// Earlier IP debits are not rolled back by rejection or outage. No ticket,
// local fallback, new budget or domain lookup is created; existing Admit and
// split callers share exactly the same primitive-owned bucket identities.
func (l *AuthRateLimiter) AdmitSigninIdentifier(ctx context.Context, facts NetworkFacts, r AuthRateRequest) (AuthRateResult, error) {
	if r.UserID != "" {
		return AuthRateResult{}, ErrInvalidInput
	}
	return l.admitAuthDimension(ctx, facts, r.OperationID, r.Identifier, true, "rate.signin")
}

// AdmitSignupIP applies shared rate.signup IP5/hour before native address
// normalization. Only canonical signup operations and mapped tenant facts are
// accepted. A failed subsequent source lookup retains this debit. After nil-
// error Allowed, call AdmitSignupIdentifier for the same immutable request;
// never also call Admit, which would debit IP twice. Admission is request-local,
// not authority. No account lookup, fallback, retry or goroutine runs here.
func (l *AuthRateLimiter) AdmitSignupIP(ctx context.Context, facts NetworkFacts, operationID string) (AuthRateResult, error) {
	return l.admitAuthDimension(ctx, facts, operationID, "", false, "rate.signup")
}

// AdmitSignupIdentifier applies shared tenant/canonical-identifier3/day after
// native owning-workflow normalization and prior AdmitSignupIP for this request.
// UserID must be empty; signup cannot select an authenticated subject budget.
// It grants no complete admission, confirms no account existence and shares
// exactly the same primitive-owned bucket as Admit. Rejections and outages do
// not refund earlier IP debits. Retry metadata retains the one-hour ceiling
// without shortening the actual daily budget's continuous refill period.
func (l *AuthRateLimiter) AdmitSignupIdentifier(ctx context.Context, facts NetworkFacts, r AuthRateRequest) (AuthRateResult, error) {
	if r.UserID != "" {
		return AuthRateResult{}, ErrInvalidInput
	}
	return l.admitAuthDimension(ctx, facts, r.OperationID, r.Identifier, true, "rate.signup")
}

// AdmitDeliveryIP applies shared delivery IP10/hour before native destination
// normalization. Only canonical delivery operations and mapped tenant facts
// are accepted. A failed source lookup retains this debit. After admission,
// call AdmitDeliveryIdentifier once for the same immutable anonymous request;
// do not also call Admit. This grants no identity or delivery authority.
func (l *AuthRateLimiter) AdmitDeliveryIP(ctx context.Context, facts NetworkFacts, operationID string) (AuthRateResult, error) {
	return l.admitAuthDimension(ctx, facts, operationID, "", false, "rate.delivery")
}

// AdmitDeliveryIdentifier applies shared tenant/destination5/hour after native
// normalization and AdmitDeliveryIP. It does not debit IP again or refund an
// earlier debit. UserID must be empty: this split profile is anonymous; use
// Admit for authenticated delivery requiring the additional subject budget.
// Both profiles share the same destination bucket. Outage or ambiguity denies
// without fallback, retries, or a reusable admission ticket.
func (l *AuthRateLimiter) AdmitDeliveryIdentifier(ctx context.Context, facts NetworkFacts, r AuthRateRequest) (AuthRateResult, error) {
	if r.UserID != "" {
		return AuthRateResult{}, ErrInvalidInput
	}
	return l.admitAuthDimension(ctx, facts, r.OperationID, r.Identifier, true, "rate.delivery")
}

func (l *AuthRateLimiter) admitAuthDimension(ctx context.Context, facts NetworkFacts, operationID, identifier string, source bool, profile RatePolicyID) (out AuthRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthRateResult{}, ErrRateUnavailable
		}
	}()
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != RealmTenant || l.operations[operationID] != profile || source && !rateIdentifier(identifier) {
		return out, ErrInvalidInput
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
	name, period, identifierPeriod, ipCapacity, identifierCapacity := "signin", 10*time.Minute, 10*time.Minute, uint64(20), uint64(10)
	if profile == "rate.signup" {
		name, period, identifierPeriod, ipCapacity, identifierCapacity = "signup", time.Hour, 24*time.Hour, 5, 3
	} else if profile == "rate.delivery" {
		name, period, identifierPeriod, ipCapacity, identifierCapacity = "delivery", time.Hour, time.Hour, 10, 5
	}
	kind, value, capacity := name+"-ip", facts.ClientIP().String(), ipCapacity
	if source {
		kind, value, capacity = name+"-identifier", l.digest(name, "identifier", string(facts.TenantID()), identifier), identifierCapacity
		period = identifierPeriod
	}
	key, keyErr := rateKey(l.config.Namespace, kind, value)
	policy, policyErr := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: "identity-http-" + kind, Revision: "identity-http-auth-1", Algorithm: ratelimit.TokenBucket, Capacity: capacity, Period: period, Consistency: ratelimit.ConsistencyStrong})
	if keyErr != nil || policyErr != nil {
		return out, ErrInvalidInput
	}
	return l.admitRequests(ctx, []ratelimit.Request{{Policy: policy, Key: key, Cost: 1, Now: now}})
}

func (l *AuthRateLimiter) admitRequests(ctx context.Context, requests []ratelimit.Request) (out AuthRateResult, err error) {
	var retry time.Duration
	for _, request := range requests {
		if ctx.Err() != nil || l.closed.Load() {
			return out, ErrRateUnavailable
		}
		decision, err := l.shared.Admit(ctx, request)
		if ctx.Err() != nil || l.closed.Load() {
			return AuthRateResult{}, ErrRateUnavailable
		}
		if errors.Is(err, ratelimit.ErrRejected) {
			retry = max(retry, decision.RetryAfter, time.Second)
			continue
		}
		if err != nil || !decision.Allowed {
			return AuthRateResult{}, ErrRateUnavailable
		}
	}
	if retry > 0 {
		// Clamp before rounding: a hostile but structurally valid backend delay
		// can be MaxInt64, where adding the rounding offset would overflow.
		retry = min(retry, time.Hour)
		out.RetryAfter = (retry + time.Second - 1) / time.Second * time.Second
		return out, ErrRateLimited
	}
	out.Allowed = true
	return out, nil
}

func rateIdentifier(s string) bool {
	if s == "" || len(s) > 1024 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (l *AuthRateLimiter) digest(parts ...string) string {
	mac := hmac.New(sha256.New, l.config.IdentifierKey[:])
	mac.Write([]byte("identity.http.auth-rate.v1\x00"))
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		mac.Write(size[:])
		mac.Write([]byte(part))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// Close terminally denies new admission without closing the borrowed backend.
// In-flight debits are not undone. Drain handlers before releasing dependencies.
func (l *AuthRateLimiter) Close() error {
	if l == nil || l.shared == nil || l.closed == nil {
		return ErrInvalidInput
	}
	l.closed.Store(true)
	return nil
}

// Format prevents accidental identifier/subject disclosure.
func (AuthRateRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.AuthRateRequest(redacted)")
}

// MarshalJSON rejects implicit export of sensitive admission input.
func (AuthRateRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText rejects implicit text/map-key export of sensitive admission input.
func (AuthRateRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// LogValue redacts admission input in structured logging.
func (AuthRateRequest) LogValue() slog.Value {
	return slog.StringValue("identityhttp.AuthRateRequest(redacted)")
}

// Format prevents traversal of keys and borrowed backend configuration.
func (AuthRateLimiter) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.AuthRateLimiter(redacted)")
}

// MarshalJSON rejects implicit export of runtime composition.
func (AuthRateLimiter) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText rejects implicit text export of runtime composition.
func (AuthRateLimiter) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// LogValue redacts runtime composition in structured logging.
func (AuthRateLimiter) LogValue() slog.Value {
	return slog.StringValue("identityhttp.AuthRateLimiter(redacted)")
}

// Format prevents disclosure of the deployment identifier key.
func (AuthRateConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.AuthRateConfig(redacted)")
}

// MarshalJSON rejects implicit export of deployment key configuration.
func (AuthRateConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText rejects implicit text export of deployment key configuration.
func (AuthRateConfig) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// LogValue redacts deployment configuration in structured logging.
func (AuthRateConfig) LogValue() slog.Value {
	return slog.StringValue("identityhttp.AuthRateConfig(redacted)")
}
