package oauthserverhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// RateConfig borrows one concurrency-safe strong rate store and a prompt,
// trusted concurrent clock. Namespace is immutable deployment rate identity;
// changing it resets budgets. MaximumDuration is 1ms..2s. No process-local
// fallback, background work or store ownership is introduced.
type RateConfig struct {
	Shared          ratelimit.StrictBackend
	Namespace       string
	Now             func() time.Time
	MaximumDuration time.Duration
}

type protocolRate struct {
	service                                                  *ratelimit.StrictService
	config                                                   RateConfig
	issuer                                                   string
	tokenIP, tokenClient, protocolIP, protocolClient, tenant ratelimit.Policy
}

func newProtocolRate(c RateConfig, issuer string) (*protocolRate, error) {
	if c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 2*time.Second || issuer == "" {
		return nil, identityhttp.ErrInvalidInput
	}
	l := &protocolRate{config: c, issuer: issuer}
	var err error
	if _, err = l.key("ip", "validation"); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	if l.service, err = ratelimit.NewStrictService(c.Shared); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	policy := func(id string, capacity uint64) ratelimit.Policy {
		p, _ := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: id, Revision: "identity-oauth-http-1", Algorithm: ratelimit.TokenBucket, Capacity: capacity, Period: time.Minute, Consistency: ratelimit.ConsistencyStrong})
		return p
	}
	// These are the identity endpoint catalog's rate.oauth-token/rate.protocol
	// buckets, not provider-dependent tuning. Refresh-family limits belong to
	// the unselected refresh profile and must not be approximated with token text.
	l.tokenIP, l.tokenClient = policy("oauth-token-ip", 120), policy("oauth-token-client", 60)
	l.protocolIP, l.protocolClient, l.tenant = policy("oauth-protocol-ip", 240), policy("oauth-protocol-client", 120), policy("oauth-protocol-tenant", 600)
	return l, nil
}

func (l *protocolRate) key(kind, value string) (ratelimit.Key, error) {
	// Length framing isolates equal client IDs in distinct issuers without
	// placing raw credential, network or tenant data in primitive diagnostics.
	digest := sha256.Sum256([]byte(strconv.Itoa(len(l.issuer)) + ":" + l.issuer + value))
	return ratelimit.NewKey(ratelimit.KeySpec{Namespace: l.config.Namespace, Version: "1", Subject: ratelimit.Subject{Kind: kind, Value: hex.EncodeToString(digest[:])}, Hash: true})
}

func (l *protocolRate) admitIP(ctx context.Context, facts identityhttp.NetworkFacts, action string) (time.Duration, error) {
	if !facts.Valid() {
		return 0, identityhttp.ErrInvalidInput
	}
	var p ratelimit.Policy
	switch action {
	case "token":
		p = l.tokenIP
	case "introspect", "revoke":
		p = l.protocolIP
	default:
		return 0, identityhttp.ErrInvalidInput
	}
	return l.admit(ctx, p, "ip", facts.ClientIP().String())
}

// admitClient is reached only after native client authentication. An earlier
// IP debit remains on later denial; admission is not a refund transaction or
// reusable authentication proof. Both protocol routes share the same buckets.
func (l *protocolRate) admitClient(ctx context.Context, facts identityhttp.NetworkFacts, action, client string) (time.Duration, error) {
	if !facts.Valid() || client == "" || len(client) > 128 {
		return 0, identityhttp.ErrInvalidInput
	}
	var p ratelimit.Policy
	switch action {
	case "token":
		p = l.tokenClient
	case "introspect", "revoke":
		p = l.protocolClient
	default:
		return 0, identityhttp.ErrInvalidInput
	}
	retry, err := l.admit(ctx, p, "client", client)
	if err != nil || action == "token" || facts.Realm() != identityhttp.RealmTenant {
		return retry, err
	}
	return l.admit(ctx, l.tenant, "tenant", string(facts.TenantID()))
}

func (l *protocolRate) admit(ctx context.Context, p ratelimit.Policy, kind, value string) (retry time.Duration, err error) {
	defer func() {
		if recover() != nil {
			retry, err = 0, identityhttp.ErrRateUnavailable
		}
	}()
	if ctx == nil {
		return 0, identityhttp.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, l.config.MaximumDuration)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := l.config.Now()
	if now.IsZero() {
		return 0, identityhttp.ErrRateUnavailable
	}
	key, err := l.key(kind, value)
	if err != nil {
		return 0, identityhttp.ErrRateUnavailable
	}
	out, err := l.service.Admit(ctx, ratelimit.Request{Policy: p, Key: key, Cost: 1, Now: now})
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if errors.Is(err, ratelimit.ErrRejected) {
		return min(max(out.RetryAfter, time.Second), time.Hour), identityhttp.ErrRateLimited
	}
	if err != nil || !out.Allowed {
		return 0, identityhttp.ErrRateUnavailable
	}
	return 0, nil
}
