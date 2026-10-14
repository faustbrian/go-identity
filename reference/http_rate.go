package reference

import (
	"fmt"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// HTTPRateConfiguration selects one native PostgreSQL strong-admission owner.
// All durations must be explicit and within 1ms..2s. Timeout cannot exceed
// MaximumDuration; lock and rollback budgets cannot exceed Timeout. Namespace
// and IdentifierKey satisfy the HTTP owner's fixed policy contract. Construction
// copies inputs without IO. The caller pool must explicitly select search_path
// public because the native backend's schema and queries are unqualified.
// Concurrent input mutation during construction is forbidden.
type HTTPRateConfiguration struct {
	Namespace       string
	IdentifierKey   [32]byte
	MaximumDuration time.Duration
	Timeout         time.Duration
	LockTimeout     time.Duration
	RollbackTimeout time.Duration
}

type httpRateState struct {
	backend *ratepg.Store
	limiter *identityhttp.AuthRateLimiter
}

func composeHTTPRate(c *HTTPRateConfiguration, pool *database.Pool) (*httpRateState, error) {
	if c == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_rate"}
	for _, duration := range []time.Duration{c.MaximumDuration, c.Timeout, c.LockTimeout, c.RollbackTimeout} {
		if duration < time.Millisecond || duration > 2*time.Second {
			return nil, invalid
		}
	}
	if c.Timeout > c.MaximumDuration || c.LockTimeout > c.Timeout || c.RollbackTimeout > c.Timeout || pool == nil || pool.Raw() == nil {
		return nil, invalid
	}
	if pool.Raw().Config().ConnConfig.RuntimeParams["search_path"] != "public" {
		return nil, invalid
	}
	backend, err := ratepg.NewStrict(pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: c.Timeout, LockTimeout: c.LockTimeout, Clock: ratepg.ServerClock}, RollbackTimeout: c.RollbackTimeout})
	if err != nil {
		return nil, invalid
	}
	limiter, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: c.Namespace, IdentifierKey: c.IdentifierKey, Now: time.Now, MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &httpRateState{backend: backend, limiter: limiter}, nil
}

// Format redacts deployment key material for all formatting verbs.
func (HTTPRateConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPRateConfiguration(redacted)")
}

// MarshalJSON rejects serialization of deployment key material.
func (HTTPRateConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText rejects serialization of deployment key material.
func (HTTPRateConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
