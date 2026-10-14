package otp

import (
	"errors"
	"fmt"
	"io"
	"time"
)

// ErrInvalidChallenge rejects an invalid primary snapshot or time input without
// preserving private challenge fields. Construction is not an authority lookup.
var ErrInvalidChallenge = errors.New("otp: invalid challenge")

// CheckPolicySpec explicitly enables a separately limited non-consuming check.
// MaximumChecks is 1..10 when Enabled and zero otherwise. LockoutAfter is a
// positive microsecond-exact duration at most 24 hours, applied by the primary
// adapter to the shared subject/destination lockout when wrong attempts exhaust.
// Disabling checks never disables the code profile's shared total-attempt cap.
type CheckPolicySpec struct {
	Enabled       bool
	MaximumChecks uint32
	LockoutAfter  time.Duration
}

// AttemptPolicy is immutable issued policy, safe for concurrent reads. Its
// shared total-attempt bound is derived from the exact CodeProfile, not a second
// independent override. Zero is invalid. It owns no store or rate limiter.
type AttemptPolicy struct {
	profile CodeProfile
	checks  CheckPolicySpec
}

// NewAttemptPolicy freezes the exact generation/expiry/send/attempt profile and
// explicit check policy without defaults or IO. Invalid input returns
// ErrInvalidProfile. Construct a new challenge rather than changing live policy.
func NewAttemptPolicy(profile CodeProfile, checks CheckPolicySpec) (AttemptPolicy, error) {
	if _, e := profile.Bindings(); e != nil || checks.LockoutAfter <= 0 || checks.LockoutAfter > 24*time.Hour || checks.LockoutAfter%time.Microsecond != 0 ||
		checks.Enabled && (checks.MaximumChecks == 0 || checks.MaximumChecks > 10) || !checks.Enabled && checks.MaximumChecks != 0 {
		return AttemptPolicy{}, ErrInvalidProfile
	}
	return AttemptPolicy{profile: profile, checks: checks}, nil
}

// Bindings returns exact caller-owned policy projections. Zero returns
// ErrInvalidProfile. No defaults, lifetimes or allowance are renewed.
func (p AttemptPolicy) Bindings() (CodeProfileSpec, CheckPolicySpec, error) {
	profile, e := p.profile.Bindings()
	if e != nil {
		return CodeProfileSpec{}, CheckPolicySpec{}, e
	}
	return profile, p.checks, nil
}

// ChallengeState is the closed primary participant lifecycle. Every non-issued
// state denies a new code submission; reserved state cannot be released by this
// policy or by expiry. Only the durable adapter owns actual transitions.
type ChallengeState uint8

const (
	// ChallengeIssued is eligible for a counted attempt, subject to current checks.
	ChallengeIssued ChallengeState = iota + 1
	// ChallengeReserved belongs to one command/generation until primary recovery.
	ChallengeReserved
	// ChallengeFinalized is terminal consumption in the owning domain commit.
	ChallengeFinalized
	// ChallengeReleased is terminal proven non-commit; a new challenge is required.
	ChallengeReleased
	// ChallengeExpired is terminal expiry of an unreserved issued challenge.
	ChallengeExpired
	// ChallengeRevoked is terminal primary revocation.
	ChallengeRevoked
	// ChallengeExhausted is terminal exhaustion of the shared total-attempt budget.
	ChallengeExhausted
)

// ChallengeSpec is an adapter-only primary snapshot, not a wire format or
// authentication evidence. Continuation includes all scope and authorization
// declarations; current authority must be checked independently under primary
// locks. Digest contains no plaintext. UsedAttempts counts every admitted
// comparison across BOTH modes, including correct checks and correct consumption.
// FailedAttempts counts wrong submissions; Checks counts every admitted precheck, correct
// or incorrect. IssuedAt/ExpiresAt must be year 1..9999 microsecond-exact instants;
// expiry is exclusive and cannot exceed the frozen profile TTL. Version is
// positive. Reservation ownership/replay records remain solely adapter-owned.
type ChallengeSpec struct {
	Continuation                         Continuation
	Policy                               AttemptPolicy
	Digest                               StoredCodeDigest
	IssuedAt, ExpiresAt                  time.Time
	State                                ChallengeState
	Version                              uint64
	UsedAttempts, FailedAttempts, Checks uint32
}

func (ChallengeSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.ChallengeSpec(redacted)")
}
func (ChallengeSpec) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ChallengeSpec) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Challenge owns immutable validated primary snapshot data. Construction does
// not issue, read, lock, reserve or authenticate a challenge. Zero is invalid;
// copies are safe for concurrent evaluation and retain private destination data.
type Challenge struct{ state *ChallengeSpec }

// NewChallenge validates before retaining immutable input. Issued snapshots
// must have allowance remaining; exhausted snapshots have exactly the total
// budget. Reserved/finalized/released snapshots include a correct consuming
// attempt (UsedAttempts exceeds both FailedAttempts and Checks). Other terminal snapshots
// preserve their original counters. Times are normalized to UTC without rounding
// or changing their instants. Invalid input returns ErrInvalidChallenge.
func NewChallenge(s ChallengeSpec) (Challenge, error) {
	profile, checks, e := s.Policy.Bindings()
	scope, scopeErr := s.Continuation.Bindings()
	if e != nil || scopeErr != nil || profile.Purpose != scope.Scope.Purpose || s.Digest.KeyVersion == 0 || s.Digest.Value == ([32]byte{}) ||
		!challengeTime(s.IssuedAt) || !challengeTime(s.ExpiresAt) || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > profile.TTL ||
		s.State < ChallengeIssued || s.State > ChallengeExhausted || s.Version == 0 || s.UsedAttempts > profile.Attempts || s.FailedAttempts > s.UsedAttempts || s.Checks > s.UsedAttempts || s.Checks > checks.MaximumChecks ||
		s.State == ChallengeIssued && s.UsedAttempts == profile.Attempts ||
		(s.State == ChallengeReserved || s.State == ChallengeFinalized || s.State == ChallengeReleased) && (s.UsedAttempts == s.FailedAttempts || s.UsedAttempts == s.Checks) ||
		s.State == ChallengeExhausted && s.UsedAttempts != profile.Attempts {
		return Challenge{}, ErrInvalidChallenge
	}
	s.IssuedAt, s.ExpiresAt = s.IssuedAt.UTC(), s.ExpiresAt.UTC()
	return Challenge{state: &s}, nil
}

func challengeTime(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999 && t.Nanosecond()%1000 == 0
}

// Bindings returns an owned adapter-only snapshot. Zero returns
// ErrInvalidChallenge. Changing the returned scalars cannot change this value.
func (c Challenge) Bindings() (ChallengeSpec, error) {
	if c.state == nil {
		return ChallengeSpec{}, ErrInvalidChallenge
	}
	return *c.state, nil
}
func (Challenge) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "otp.Challenge(redacted)") }
func (Challenge) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (Challenge) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// AttemptOutcome is a closed private adapter decision. Neither Checked nor
// Reserved proves persistence, current authority, authentication or consumption.
// Public service responses must collapse private state to enumeration-safe data.
type AttemptOutcome uint8

const (
	// AttemptChecked proposes a bounded non-consuming comparison success only.
	AttemptChecked AttemptOutcome = iota + 1
	// AttemptReserved proposes the sole consuming reservation, not a proof/handle.
	AttemptReserved
	// AttemptDenied proposes no authority; wrong code may charge the shared budget.
	AttemptDenied
	// AttemptExpired proposes expiry of the exact unreserved issued challenge.
	AttemptExpired
	// AttemptExhausted proposes a wrong code exhausting the total budget and lockout.
	AttemptExhausted
	// AttemptConflict rejects stale/unincrementable optimistic version input.
	AttemptConflict
)

// AttemptDecision is a provisional adapter-only policy result, not an attempt
// receipt. Apply these exact counters/state/version atomically with the command
// result after primary authorization checks; never return success from this
// value alone. LockoutAfter is nonzero ONLY on new wrong-code exhaustion. A
// correct final Check returns AttemptChecked with ChallengeExhausted and zero
// lockout; it grants no future consuming allowance. Correct final Consume may
// propose Reserved. It owns no bearer,
// proof, reservation handle, durable outcome or mutable challenge state.
type AttemptDecision struct {
	Outcome                              AttemptOutcome
	State                                ChallengeState
	Version                              uint64
	UsedAttempts, FailedAttempts, Checks uint32
	LockoutAfter                         time.Duration
}

func (AttemptDecision) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.AttemptDecision(redacted)")
}
func (AttemptDecision) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AttemptDecision) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// EvaluateAttempt evaluates ONE new logical submission against a locked primary
// snapshot and primary time. Call only inside the authoritative counted attempt
// or single coordinator reservation transaction, AFTER checking current session/
// pre-auth authority, original remember policy and subject/destination lockout.
// The adapter must check the durable attempt replay record FIRST: replay/recovery
// must not call this method, compare again or decrement again. This pure function
// has no IO, store, retry or commit authority and never creates a proof/reservation.
// It uses one bounded keyed comparison even for valid cross-scope/version/terminal
// denials. Unknown/retired keys return an error without a charge; the public
// workflow must normalize unavailable/denied private outcomes appropriately.
// Checks have a separate cap and share the TOTAL comparison budget with Consume.
// No reserved state is expired/released here. Earlier time denies without renewal;
// exact expiry equality expires only issued state. A changed proposal increments
// optimistic version once without overflow. Rollback means discard the proposal;
// ambiguity means recover the same durable command, never reevaluate.
func (v Verifier) EvaluateAttempt(c Challenge, a AttemptCommand, primaryNow time.Time) (AttemptDecision, error) {
	if c.state == nil || !challengeTime(primaryNow) {
		return AttemptDecision{}, ErrInvalidChallenge
	}
	if a.state == nil {
		return AttemptDecision{}, ErrInvalidAttempt
	}
	s := c.state
	scope, _ := a.state.bindings.Continuation.DigestScope()
	matched, e := v.Compare(scope, s.Digest, a.state.code)
	if e != nil {
		return AttemptDecision{}, e
	}
	result := AttemptDecision{Outcome: AttemptDenied, State: s.State, Version: s.Version, UsedAttempts: s.UsedAttempts, FailedAttempts: s.FailedAttempts, Checks: s.Checks}
	if scope.binding != s.Continuation.state.scope.binding {
		return result, nil
	}
	if a.state.bindings.ExpectedVersion != s.Version || s.Version == ^uint64(0) {
		result.Outcome = AttemptConflict
		return result, nil
	}
	if s.State != ChallengeIssued || primaryNow.Before(s.IssuedAt) {
		return result, nil
	}
	if !primaryNow.Before(s.ExpiresAt) {
		result.Outcome, result.State, result.Version = AttemptExpired, ChallengeExpired, s.Version+1
		return result, nil
	}
	checks := s.Policy.checks
	if a.state.bindings.Mode == AttemptModeCheck {
		if !checks.Enabled || s.Checks == checks.MaximumChecks {
			return result, nil
		}
		result.Checks++
	}
	result.Version++
	result.UsedAttempts++
	if result.UsedAttempts == s.Policy.profile.spec.Attempts {
		result.State = ChallengeExhausted
	}
	if !matched {
		result.FailedAttempts++
		if result.State == ChallengeExhausted {
			result.Outcome, result.State, result.LockoutAfter = AttemptExhausted, ChallengeExhausted, checks.LockoutAfter
		}
	} else if a.state.bindings.Mode == AttemptModeCheck {
		result.Outcome = AttemptChecked
	} else {
		result.Outcome, result.State = AttemptReserved, ChallengeReserved
	}
	return result, nil
}
