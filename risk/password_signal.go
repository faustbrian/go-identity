package risk

import (
	"context"
	"slices"
	"time"
)

// HIBPPolicy selects password-creating operations and the immutable provider-range
// validity interval. Zero disables this composition, preserving existing policies.
// CacheTTL is explicit, 1 hour..7 days; Operations is a nonempty unique subset of
// canonical password-creating operations, copied at construction. Reference
// composition must select every supported password-creating operation. It does
// not select fail-open behavior or replace any existing mandatory signal.
type HIBPPolicy struct {
	CacheTTL   time.Duration
	Operations []Action
}

// HIBPConfiguration returns an owned, sorted snapshot for adapter startup
// consistency checks. Zero or disabled policies return ErrInvalidPolicy. The
// snapshot grants no assessment, provider or mutation authority.
func (p Policy) HIBPConfiguration() (HIBPPolicy, error) {
	if p.state == nil || len(p.state.hibpOperations) == 0 {
		return HIBPPolicy{}, ErrInvalidPolicy
	}
	c := HIBPPolicy{CacheTTL: p.state.hibpTTL}
	for operation := range p.state.hibpOperations {
		c.Operations = append(c.Operations, operation)
	}
	slices.Sort(c.Operations)
	return c, nil
}

// ProviderFailure is bounded, non-secret provider classification, not a decision.
// Zero means no failure. It never carries provider messages, URLs or credentials.
type ProviderFailure uint8

const (
	ProviderUnavailable ProviderFailure = iota + 1
	ProviderMalformed
	ProviderInvalidConfiguration
	ProviderCancelled
	ProviderInvalidBinding
	ProviderOverloaded
	ProviderClosed
)

// PasswordObservation is trusted checker output. ObservedAt is the original
// provider read; ValidUntil is its unchanged observation plus selected range TTL.
// CheckedAt is the local candidate-match time, not a replacement observation.
// A failure has no count or timestamps. Structural validation proves no source
// provenance; only owned provider/workflow composition may supply this value.
type PasswordObservation struct {
	BreachCount                       uint64
	ObservedAt, ValidUntil, CheckedAt time.Time
	Failure                           ProviderFailure
}

func passwordCreating(action Action) bool {
	switch action {
	case "identity.password.signup", "identity.username.signup", "identity.password.set", "identity.password.change",
		"identity.password.reset-complete", "identity.otp.password-reset", "identity.phone.password-reset-complete", "identity.admin.user-password-set":
		return true
	}
	return false
}

// PasswordSignal normalizes facts without selecting allow, deny, throttle or
// step-up. Assess owns that decision. Successful facts retain provider age;
// derived expiry is capped by both local assessment TTL and original provider
// validity. Failures remain unavailable with a safe classification. Cancellation
// returns no signal. Unselected operations or invalid observations reject.
func (p Policy) PasswordSignal(ctx context.Context, c Context, observation PasswordObservation) (Signal, error) {
	if ctx == nil {
		return Signal{}, ErrInvalidContext
	}
	if e := ctx.Err(); e != nil {
		return Signal{}, e
	}
	a, e := p.Admit(c.Operation)
	if e != nil {
		return Signal{}, e
	}
	if !p.state.hibpOperations[c.Operation] || !scopeID(c.Tenant) || !scopeID(c.Attempt) || !validTime(c.Now) {
		return Signal{}, ErrInvalidSignal
	}
	s := Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "hibp", Trust: ServerVerified,
		BreachCount: observation.BreachCount, Failure: observation.Failure, ObservedAt: observation.ObservedAt,
		ProviderValidUntil: observation.ValidUntil, CheckedAt: observation.CheckedAt}
	if observation.Failure != 0 {
		s.State = SignalUnavailable
	} else {
		s.State = SignalClean
		if s.BreachCount > 0 {
			s.State = SignalPositive
		}
		s.ExpiresAt = observation.CheckedAt.Add(a.Profile.EvidenceTTL)
		if observation.ValidUntil.Before(s.ExpiresAt) {
			s.ExpiresAt = observation.ValidUntil
		}
	}
	if !validSignal(s, c, a.Profile, p.state.limits, p.state.hibpTTL) {
		return Signal{}, ErrInvalidSignal
	}
	return s, nil
}

func validPasswordSignal(s Signal, c Context, p Profile, ttl time.Duration) bool {
	if ttl == 0 || s.RetryAfter != 0 {
		return false
	}
	if s.State == SignalSkipped {
		return s.Failure == 0 && s.BreachCount == 0 && s.ObservedAt.IsZero() && s.ExpiresAt.IsZero() && s.ProviderValidUntil.IsZero() && s.CheckedAt.IsZero()
	}
	if s.State == SignalUnavailable {
		return s.Failure >= ProviderUnavailable && s.Failure <= ProviderClosed && s.BreachCount == 0 && s.ObservedAt.IsZero() && s.ExpiresAt.IsZero() && s.ProviderValidUntil.IsZero() && s.CheckedAt.IsZero()
	}
	if s.Failure != 0 || (s.State != SignalClean && s.State != SignalPositive) || s.BreachCount > 1000000000 ||
		(s.State == SignalPositive) != (s.BreachCount > 0) {
		return false
	}
	return validTime(s.ObservedAt) && validTime(s.ProviderValidUntil) && validTime(s.CheckedAt) && validTime(s.ExpiresAt) &&
		!s.ObservedAt.After(s.CheckedAt) && !s.CheckedAt.After(c.Now) && s.ProviderValidUntil.Equal(s.ObservedAt.Add(ttl)) &&
		s.ProviderValidUntil.After(c.Now) && s.ExpiresAt.After(c.Now) && !s.ExpiresAt.After(s.ProviderValidUntil) &&
		s.ExpiresAt.After(s.CheckedAt) && !s.ExpiresAt.After(s.CheckedAt.Add(p.EvidenceTTL))
}

func irreversibleDeny(s Signal) bool {
	return s.Trust == ServerVerified && (s.State == SignalDeny || s.State == SignalPositive)
}
