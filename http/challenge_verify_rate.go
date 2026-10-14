package identityhttp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	identity "github.com/faustbrian/go-identity"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// ChallengeVerificationRateConfig shares the immutable native rate.verify
// deployment profile with password verification. Use the same namespace/key
// and borrowed atomic backend to share IP and subject budgets across flows.
// This alias preserves one owner for policy validation and redacted config.
type ChallengeVerificationRateConfig = PasswordVerificationRateConfig

// ChallengeVerificationRateRequest contains authenticated original source
// bindings, never JSON-selected identity or bearer bytes. UserID and ChallengeID
// must come from the owning workflow's authenticated, purpose-bound original
// issuance. ChallengeLifetime is its immutable policy lifetime, not remaining
// expiry, a renewed interval or an override; integral microseconds in 1s..24h.
// This subject-bound profile does not support identifier-only challenges.
// It proves neither authority nor challenge validity. Explicit/private field
// copies remain sensitive; inputs must remain immutable during the call.
type ChallengeVerificationRateRequest struct {
	OperationID       string
	UserID            identity.UserID
	ChallengeID       string
	ChallengeLifetime time.Duration
}

// ChallengeVerificationRateLimiter owns no store or goroutine. It composes the
// existing strict native atomic owner; no retry, local fallback or second journal
// is introduced. Independent calls/Close are safe. Zero is invalid. Each call
// receives fresh server-side debit correlation, never a client retry key.
type ChallengeVerificationRateLimiter struct {
	owner      *PasswordVerificationRateLimiter
	operations map[string]bool
}

// NewChallengeVerificationRateLimiter freezes canonical issued-challenge
// rate.verify selection without IO or route registration. Password verification
// stays on its existing no-challenge contract. Core HTTP gains no feature import.
func NewChallengeVerificationRateLimiter(c ChallengeVerificationRateConfig) (*ChallengeVerificationRateLimiter, error) {
	owner, err := NewPasswordVerificationRateLimiter(c)
	if err != nil {
		return nil, err
	}
	operations := make(map[string]bool)
	for id, row := range readCatalog() {
		if row.Rate == "rate.verify" && id != "identity.password.verify" && row.Exposure != "direct" {
			operations[id] = true
		}
	}
	return &ChallengeVerificationRateLimiter{owner: owner, operations: operations}, nil
}

// Configured reports nonterminal structural validity, not health or admission.
func (l *ChallengeVerificationRateLimiter) Configured() bool { return l != nil && l.owner.Configured() }

// AdmitIP counts trusted IP20/10m before cryptographic/source lookup work. It
// does not authorize any operation and must be followed by AdmitChallenge with
// authenticated original bindings before mutation. The two phases are not one
// transaction: the IP debit remains after proof rejection or later failure.
func (l *ChallengeVerificationRateLimiter) AdmitIP(ctx context.Context, facts NetworkFacts) (AuthRateResult, error) {
	return l.admit(ctx, facts, ChallengeVerificationRateRequest{}, true, false)
}

// AdmitChallenge atomically counts tenant/subject10/10m and original challenge
// 10/lifetime after the same attempt's successful AdmitIP and source
// authentication. It never recounts IP or authenticates client input. A positive
// result is not reusable clearance; original expiry/current policy and the
// workflow's stricter protected attempt counters still apply.
func (l *ChallengeVerificationRateLimiter) AdmitChallenge(ctx context.Context, facts NetworkFacts, r ChallengeVerificationRateRequest) (AuthRateResult, error) {
	return l.admit(ctx, facts, r, false, true)
}

// Admit atomically counts all three dimensions for an already-authenticated
// direct caller. Do not call this after AdmitIP for the same attempt. Invalid
// input denies before dispatch; ambiguity/outage/panic/cancellation/close deny
// without retry. Known exhaustion retains the longest1s..1h ceiling delay.
func (l *ChallengeVerificationRateLimiter) Admit(ctx context.Context, facts NetworkFacts, r ChallengeVerificationRateRequest) (AuthRateResult, error) {
	return l.admit(ctx, facts, r, true, true)
}

func (l *ChallengeVerificationRateLimiter) admit(ctx context.Context, facts NetworkFacts, r ChallengeVerificationRateRequest, ip, challenge bool) (out AuthRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthRateResult{}, ErrRateUnavailable
		}
	}()
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != RealmTenant {
		return out, ErrInvalidInput
	}
	if challenge && (!l.operations[r.OperationID] || !ascii(string(r.UserID), 128, false) || !rateIdentifier(r.ChallengeID) || len(r.ChallengeID) > 256 || r.ChallengeLifetime < time.Second || r.ChallengeLifetime > 24*time.Hour || r.ChallengeLifetime%time.Microsecond != 0) {
		return out, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, l.owner.config.MaximumDuration)
	defer cancel()
	if ctx.Err() != nil {
		return out, ErrRateUnavailable
	}
	now := l.owner.config.Now()
	if now.IsZero() {
		return out, ErrRateUnavailable
	}
	requests := make([]ratelimit.Request, 0, 3)
	appendBucket := func(kind, value string, capacity uint64, period time.Duration) error {
		key, e := rateKey(l.owner.config.Namespace, kind, value)
		if e != nil {
			return ErrInvalidInput
		}
		policy, e := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: "identity-http-" + kind, Revision: "identity-http-verify-1", Algorithm: ratelimit.TokenBucket, Capacity: capacity, Period: period, MaxCost: 1, Consistency: ratelimit.ConsistencyStrong})
		if e != nil {
			return ErrInvalidInput
		}
		requests = append(requests, ratelimit.Request{Policy: policy, Key: key, Cost: 1, Now: now})
		return nil
	}
	if ip {
		if err := appendBucket("verify-ip", facts.ClientIP().String(), 20, 10*time.Minute); err != nil {
			return out, err
		}
	}
	if challenge {
		if err := appendBucket("verify-subject", l.owner.digest("subject", string(facts.TenantID()), string(r.UserID)), 10, 10*time.Minute); err != nil {
			return out, err
		}
		if err := appendBucket("verify-challenge", l.owner.digest("challenge", string(facts.TenantID()), r.OperationID, r.ChallengeID), 10, r.ChallengeLifetime); err != nil {
			return out, err
		}
	}
	return l.owner.admitVerificationRequests(ctx, requests)
}

// Close terminally denies calls without closing borrowed storage or undoing
// prior debits. Drain selected handlers before disposing composition owners.
func (l *ChallengeVerificationRateLimiter) Close() error {
	if l == nil || l.owner == nil {
		return ErrInvalidInput
	}
	return l.owner.Close()
}

// Format redacts source bindings.
func (ChallengeVerificationRateRequest) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "identityhttp.ChallengeVerificationRateRequest(redacted)")
}

// LogValue returns only a constant marker.
func (ChallengeVerificationRateRequest) LogValue() slog.Value {
	return slog.StringValue("identityhttp.ChallengeVerificationRateRequest(redacted)")
}

// MarshalJSON denies implicit source export.
func (ChallengeVerificationRateRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText denies implicit text export.
func (ChallengeVerificationRateRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// Format redacts runtime composition.
func (ChallengeVerificationRateLimiter) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "identityhttp.ChallengeVerificationRateLimiter(redacted)")
}

// LogValue returns only a constant marker.
func (ChallengeVerificationRateLimiter) LogValue() slog.Value {
	return slog.StringValue("identityhttp.ChallengeVerificationRateLimiter(redacted)")
}

// MarshalJSON denies implicit composition export.
func (ChallengeVerificationRateLimiter) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText denies implicit composition export.
func (ChallengeVerificationRateLimiter) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }
