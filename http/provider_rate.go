package identityhttp

import (
	"context"
	"time"

	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// AdmitProviderIP applies the shared trusted-IP/provider30-per10-minute budget
// from API_OPERATIONS.md's rate.provider and rate.provider-callback profiles.
// Provider is the exact configured provider ID, never an inbound issuer/URL.
// Call once before native callback lookup or session authentication, then apply
// AdmitProviderTransaction when original transaction custody exists. No local
// fallback, refund, retry, state admission or exchange authority is created.
func (l *AuthRateLimiter) AdmitProviderIP(ctx context.Context, facts NetworkFacts, operation, provider string) (AuthRateResult, error) {
	return l.admitProvider(ctx, facts, operation, provider, "", 0)
}

// AdmitProviderTransaction applies only the native owner's authenticated
// original transaction: 5/lifetime for callbacks,10/lifetime for other provider
// operations. Lifetime is its immutable original policy, not remaining expiry
// or a renewed interval. Moving IP does not replace this tenant/provider/flow
// bucket. Run after successful AdmitProviderIP and native source authentication,
// before exchange. Structural arguments do not establish those authorities.
// Zero/foreign operations or nonpositive/larger-than10-minute lifetimes deny.
func (l *AuthRateLimiter) AdmitProviderTransaction(ctx context.Context, facts NetworkFacts, operation, provider, transaction string, lifetime time.Duration) (AuthRateResult, error) {
	if !ascii(transaction, 128, false) || transaction == "" || lifetime < time.Second || lifetime > 10*time.Minute {
		return AuthRateResult{}, ErrInvalidInput
	}
	return l.admitProvider(ctx, facts, operation, provider, transaction, lifetime)
}

func (l *AuthRateLimiter) admitProvider(ctx context.Context, facts NetworkFacts, operation, provider, transaction string, lifetime time.Duration) (out AuthRateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthRateResult{}, ErrRateUnavailable
		}
	}()
	if !l.Configured() || ctx == nil || !facts.Valid() || facts.Realm() != RealmTenant || !ascii(provider, 128, false) || provider == "" {
		return out, ErrInvalidInput
	}
	profile := l.operations[operation]
	if profile != "rate.provider" && profile != "rate.provider-callback" {
		return out, ErrInvalidInput
	}
	ctx, stop := context.WithTimeout(ctx, l.config.MaximumDuration)
	defer stop()
	if ctx.Err() != nil {
		return out, ErrRateUnavailable
	}
	now := l.config.Now()
	if now.IsZero() {
		return out, ErrRateUnavailable
	}
	name, capacity, period := "provider-ip", uint64(30), 10*time.Minute
	value := l.digest(name, string(facts.TenantID()), facts.ClientIP().String(), provider)
	if transaction != "" {
		name, capacity, period = "provider-transaction", 10, lifetime
		if profile == "rate.provider-callback" {
			name, capacity = "provider-callback-transaction", 5
		}
		value = l.digest(name, string(facts.TenantID()), provider, transaction)
	}
	key, keyErr := rateKey(l.config.Namespace, name, value)
	policy, policyErr := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: "identity-http-" + name, Revision: "identity-http-provider-1", Algorithm: ratelimit.TokenBucket, Capacity: capacity, Period: period, Consistency: ratelimit.ConsistencyStrong})
	if keyErr != nil || policyErr != nil {
		return out, ErrInvalidInput
	}
	return l.admitRequests(ctx, []ratelimit.Request{{Policy: policy, Key: key, Cost: 1, Now: now}})
}
