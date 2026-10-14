package identityhttp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
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

// PasswordVerificationRateConfig selects the fixed rate.verify profile for
// identity.password.verify only. Shared must be an initialized concurrency-safe
// native atomic owner; PostgreSQL needs its atomic schema. Shared and prompt,
// concurrency-safe Now remain borrowed. Namespace/Key are immutable deployment
// rate identity, not credential keys; rotating them resets budgets.
// MaximumDuration is 1ms..2s; earlier caller deadlines win. No constructor IO.
type PasswordVerificationRateConfig struct {
	Shared          ratelimit.StrictAtomicBatchBackend
	Namespace       string
	Key             [32]byte
	Now             func() time.Time
	MaximumDuration time.Duration
}

// PasswordVerificationRateRequest borrows the current authenticated subject,
// never a client-claimed user. Password verification has no pre-issued challenge
// and is non-keyed: there is no challenge override or idempotency key. Admission
// does not authenticate the subject, validate a password or grant proof authority.
type PasswordVerificationRateRequest struct {
	UserID identity.UserID
}

// PasswordVerificationRateLimiter debits trusted IP20/10m and tenant/subject
// 10/10m atomically through the existing rate primitive. Each call owns a fresh
// server-generated native debit command, including repeated verification
// attempts. No retry, journal, counter algorithm, fallback or goroutine is added.
// This profile cannot admit challenge-based verification operations. Share one
// owner across password verification requests; concurrent calls/Close are safe.
type PasswordVerificationRateLimiter struct {
	shared *ratelimit.StrictService
	config PasswordVerificationRateConfig
	closed *atomic.Bool
}

// NewPasswordVerificationRateLimiter validates immutable deployment composition
// without storage IO or selecting any route/metadata. It owns no borrowed resource.
func NewPasswordVerificationRateLimiter(c PasswordVerificationRateConfig) (*PasswordVerificationRateLimiter, error) {
	if c.Key == ([32]byte{}) || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 2*time.Second {
		return nil, ErrInvalidInput
	}
	if _, err := rateKey(c.Namespace, "verify-ip", "validation"); err != nil {
		return nil, ErrInvalidInput
	}
	shared, err := ratelimit.NewStrictService(c.Shared)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return &PasswordVerificationRateLimiter{shared: shared, config: c, closed: &atomic.Bool{}}, nil
}

// Configured reports observed nonterminal structural validity, not health or
// admission. Close may race after it returns; no authority is cached here.
func (l *PasswordVerificationRateLimiter) Configured() bool {
	return l != nil && l.shared != nil && l.closed != nil && !l.closed.Load()
}

// Admit makes one bounded native atomic dispatch. Known denial returns
// ErrRateLimited with the longest exhausted delay rounded up to seconds and
// clamped1..3600. Invalid/nil/already closed input returns ErrInvalidInput before
// dispatch. Operational, ambiguous, contradictory, panicking, canceled or
// closure-after-dispatch paths return ErrRateUnavailable without raw diagnostics.
// A lost admission outcome must not be retried automatically: the debit may
// have committed. A later user verification attempt is a fresh counted attempt.
// Cancellation after debit is not refund evidence; domain work must separately
// honor cancellation, original session validity and cumulative native risk.
func (l *PasswordVerificationRateLimiter) Admit(ctx context.Context, facts NetworkFacts, r PasswordVerificationRateRequest) (out AuthRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthRateResult{}, ErrRateUnavailable
		}
	}()
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != RealmTenant || !ascii(string(r.UserID), 128, false) {
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
	values := []string{facts.ClientIP().String(), l.digest("subject", string(facts.TenantID()), string(r.UserID))}
	kinds := []string{"verify-ip", "verify-subject"}
	requests := make([]ratelimit.Request, 2)
	for i := range requests {
		capacity := uint64(20)
		if i == 1 {
			capacity = 10
		}
		key, keyErr := rateKey(l.config.Namespace, kinds[i], values[i])
		policy, policyErr := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: "identity-http-" + kinds[i], Revision: "identity-http-verify-1", Algorithm: ratelimit.TokenBucket, Capacity: capacity, Period: 10 * time.Minute, MaxCost: 1, Consistency: ratelimit.ConsistencyStrong})
		if keyErr != nil || policyErr != nil {
			return out, ErrInvalidInput
		}
		requests[i] = ratelimit.Request{Policy: policy, Key: key, Cost: 1, Now: now}
	}
	return l.admitVerificationRequests(ctx, requests)
}

func (l *PasswordVerificationRateLimiter) admitVerificationRequests(ctx context.Context, requests []ratelimit.Request) (out AuthRateResult, err error) {
	// Fresh randomness is server-side native correlation, not a credential or a
	// request retry key. The original workflow independently owns its command.
	var nonce [32]byte
	rand.Read(nonce[:])
	command := l.digest("command", l.config.Namespace, hex.EncodeToString(nonce[:]))
	decision, backendErr := l.shared.AdmitAtomicBatch(ctx, ratelimit.AtomicBatchRequest{CommandID: command, Requests: requests})
	if ctx.Err() != nil || l.closed.Load() {
		return out, ErrRateUnavailable
	}
	if errors.Is(backendErr, ratelimit.ErrRejected) {
		var retry time.Duration
		for _, b := range decision.Decisions {
			if b.Reason == ratelimit.ReasonLimited {
				retry = max(retry, b.RetryAfter)
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

func (l *PasswordVerificationRateLimiter) digest(parts ...string) string {
	mac := hmac.New(sha256.New, l.config.Key[:])
	mac.Write([]byte("identity.http.verify-rate.v1\x00"))
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		mac.Write(size[:])
		mac.Write([]byte(part))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// Close terminally denies new calls without closing borrowed storage or undoing
// committed debits. Drain handlers before releasing dependencies. Idempotent.
func (l *PasswordVerificationRateLimiter) Close() error {
	if l == nil || l.closed == nil {
		return ErrInvalidInput
	}
	l.closed.Store(true)
	return nil
}

// Format redacts deployment composition for every verb.
func (PasswordVerificationRateConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.PasswordVerificationRateConfig(redacted)")
}

// MarshalJSON denies implicit deployment export.
func (PasswordVerificationRateConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText denies implicit deployment text/map-key export.
func (PasswordVerificationRateConfig) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// LogValue redacts borrowed deployment composition.
func (PasswordVerificationRateConfig) LogValue() slog.Value {
	return slog.StringValue("identityhttp.PasswordVerificationRateConfig(redacted)")
}

// Format redacts trusted subject custody for every verb.
func (PasswordVerificationRateRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.PasswordVerificationRateRequest(redacted)")
}

// MarshalJSON denies implicit request export.
func (PasswordVerificationRateRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText denies implicit request text/map-key export.
func (PasswordVerificationRateRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// LogValue redacts original subject custody.
func (PasswordVerificationRateRequest) LogValue() slog.Value {
	return slog.StringValue("identityhttp.PasswordVerificationRateRequest(redacted)")
}

// Format prevents traversal of retained keys and borrowed owners.
func (PasswordVerificationRateLimiter) Format(s fmt.State, _ rune) {
	io.WriteString(s, "identityhttp.PasswordVerificationRateLimiter(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (PasswordVerificationRateLimiter) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText denies implicit runtime text/map-key export.
func (PasswordVerificationRateLimiter) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// LogValue redacts runtime composition.
func (PasswordVerificationRateLimiter) LogValue() slog.Value {
	return slog.StringValue("identityhttp.PasswordVerificationRateLimiter(redacted)")
}
