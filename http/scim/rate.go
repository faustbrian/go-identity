package scimhttp

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
	"net/netip"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	scim "github.com/faustbrian/go-scim"
)

// ProtocolRateConfig selects canonical rate.protocol through a borrowed native
// strict atomic backend. All selected SCIM routes must share the backend,
// namespace and nonzero HMAC key; changing them resets effective budgets.
// Shared and the prompt trusted Now callback must be concurrency-safe and must
// not retain requests or start detached work. MaximumDuration is 1ms..2s.
// The feature owns neither backend shutdown nor a process-local fallback.
type ProtocolRateConfig struct {
	Shared          ratelimit.StrictAtomicBatchBackend
	Namespace       string
	Key             [32]byte
	Now             func() time.Time
	MaximumDuration time.Duration
}

type protocolRate struct {
	shared   *ratelimit.StrictService
	config   ProtocolRateConfig
	policies [3]ratelimit.Policy
}

func newProtocolRate(c ProtocolRateConfig) (out *protocolRate, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, identityhttp.ErrInvalidInput
		}
	}()
	if c.Now == nil || c.Key == ([32]byte{}) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 2*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := protocolRateKey(c.Namespace, "protocol-client", "validation"); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	shared, err := ratelimit.NewStrictService(c.Shared)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	l := &protocolRate{shared: shared, config: c}
	// API_OPERATIONS.md's rate.protocol row fixes these cumulative budgets.
	// The selected native SCIM profile always has a resource tenant.
	for i, dimension := range []struct {
		kind     string
		capacity uint64
	}{{"client", 120}, {"ip", 240}, {"tenant", 600}} {
		policy, err := ratelimit.NewPolicy(ratelimit.PolicySpec{
			ID: "identity-http-scim-protocol-" + dimension.kind, Revision: "identity-http-scim-protocol-1",
			Algorithm: ratelimit.TokenBucket, Capacity: dimension.capacity, Period: time.Minute,
			MaxCost: 1, Consistency: ratelimit.ConsistencyStrong, FailureMode: ratelimit.FailClosed,
		})
		if err != nil {
			return nil, identityhttp.ErrInvalidInput
		}
		l.policies[i] = policy
	}
	return l, nil
}

// admit consumes one outer transport attempt, never an HTTP idempotency key or
// a retained workflow command. The caller supplies executor-authenticated IDs
// and the full resolver-owned IP, and separately verifies the host tenant.
func (l *protocolRate) admit(ctx context.Context, client scim.ProtocolClient, ip netip.Addr) (denial *scim.Error) {
	defer func() {
		if recover() != nil {
			denial = scim.NewError(503, "")
		}
	}()
	if l == nil || l.shared == nil || ctx == nil || !protocolRateID(string(client.ID)) || !protocolRateID(string(client.TenantID)) || ip.Zone() != "" {
		return scim.NewError(503, "")
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
		return scim.NewError(503, "")
	}
	ctx, cancel := context.WithTimeout(ctx, l.config.MaximumDuration)
	defer cancel()
	if ctx.Err() != nil {
		return scim.NewError(503, "")
	}
	now := l.config.Now()
	if now.IsZero() {
		return scim.NewError(503, "")
	}
	correlation, err := identity.NewCommandID()
	if err != nil {
		return scim.NewError(503, "")
	}
	values := [3]string{
		l.digest("client", string(client.TenantID), string(client.ID)),
		l.digest("ip", ip.String()),
		l.digest("tenant", string(client.TenantID)),
	}
	requests := make([]ratelimit.Request, len(values))
	for i, kind := range []string{"protocol-client", "protocol-ip", "protocol-tenant"} {
		key, err := protocolRateKey(l.config.Namespace, kind, values[i])
		if err != nil {
			return scim.NewError(503, "")
		}
		requests[i] = ratelimit.Request{Policy: l.policies[i], Key: key, Cost: 1, Now: now}
	}
	decision, backendErr := l.shared.AdmitAtomicBatch(ctx, ratelimit.AtomicBatchRequest{
		CommandID: l.digest("attempt", string(correlation)), Requests: requests,
	})
	if ctx.Err() != nil {
		return scim.NewError(503, "")
	}
	if errors.Is(backendErr, ratelimit.ErrRejected) {
		var longest time.Duration
		for _, bucket := range decision.Decisions {
			if bucket.Reason == ratelimit.ReasonLimited {
				longest = max(longest, bucket.RetryAfter)
			}
		}
		// The endpoint catalog clamps before ceiling; this also avoids duration
		// overflow and never fabricates a retry hint for an ambiguous outcome.
		return scim.NewRateLimitedError(min(max(longest, time.Second), time.Hour))
	}
	if backendErr != nil || !decision.Allowed {
		return scim.NewError(503, "")
	}
	return nil
}

func (l *protocolRate) digest(parts ...string) string {
	h := hmac.New(sha256.New, l.config.Key[:])
	for _, part := range append([]string{l.config.Namespace, "identity-http-scim-protocol-v1"}, parts...) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func protocolRateKey(namespace, kind, value string) (ratelimit.Key, error) {
	return ratelimit.NewKey(ratelimit.KeySpec{Namespace: namespace, Version: "identity-http-1", Subject: ratelimit.Subject{Kind: kind, Value: value}, Hash: true})
}

func protocolRateID(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r <= ' ' || r == 127 {
			return false
		}
	}
	return true
}

// Format redacts borrowed dependencies and keyed policy.
func (ProtocolRateConfig) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "scimhttp.ProtocolRateConfig(redacted)")
}

// MarshalJSON prevents implicit export of key and runtime custody.
func (ProtocolRateConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText prevents implicit runtime export.
func (ProtocolRateConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// LogValue redacts runtime policy.
func (ProtocolRateConfig) LogValue() slog.Value {
	return slog.StringValue("scimhttp.ProtocolRateConfig(redacted)")
}

func (protocolRate) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "scimhttp.protocolRate(redacted)")
}
func (protocolRate) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }
func (protocolRate) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }
func (protocolRate) LogValue() slog.Value         { return slog.StringValue("scimhttp.protocolRate(redacted)") }
