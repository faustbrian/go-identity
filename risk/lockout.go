package risk

import (
	"fmt"
	"io"
	"slices"
	"time"
)

// LockoutMode is a closed administrative restriction transition, not a risk
// verdict. Neither mode confers authentication, authorization or an override.
type LockoutMode string

const (
	// StartLockout proposes a new bounded restriction at an exact current version.
	StartLockout LockoutMode = "start"
	// EndLockout proposes ending the exact current restriction without deletion.
	EndLockout LockoutMode = "end"
)

// LockoutPolicyConfig selects the existing protected-counter policy and an
// explicit positive, microsecond-exact duration ceiling. There is no default
// trigger or duration and no unauthenticated identifier-hint profile.
type LockoutPolicyConfig struct {
	Counters        CommandCounterPolicy
	MaximumDuration time.Duration
}

// LockoutPolicy prepares immutable, operation-specific subject restrictions.
// It never mutates state or grants permission. The native durable owner must
// enforce current actor authorization, CAS, primary time, audit and recovery
// through the identity coordinator. Zero is invalid; copies are concurrent-safe.
type LockoutPolicy struct{ state *lockoutPolicyState }
type lockoutPolicyState struct {
	counters CommandCounterPolicy
	maximum  time.Duration
}

// LockoutRequest contains trusted server-resolved input, not HTTP hints. Scope
// names the operation being restricted; Attempt names the mutation command.
// Subject must satisfy that operation's CredentialMutation dimensions. Actor
// is the independently authenticated administrative initiator, not Subject.User.
// ExpectedVersion is zero only for a first start, otherwise the exact current
// restriction version. End requires a positive version and zero Duration.
// Context.Now and IndependentFactor are forbidden: neither bypasses lockout.
type LockoutRequest struct {
	Scope           Context
	Subject         Subject
	Actor           string
	Mode            LockoutMode
	ExpectedVersion uint64
	Duration        time.Duration
}

// LockoutBinding is an owned native-adapter projection, never HTTP output or an
// authority proof. Target is only the operation-specific keyed subject root;
// tenant/network/session dimensions cannot become broad lockouts. Counter
// retains original scope and retained-key history for native custody checks.
type LockoutBinding struct {
	Counter         CounterBinding
	Target          CounterTarget
	Actor           string
	Mode            LockoutMode
	ExpectedVersion uint64
	Duration        time.Duration
}

// LockoutCommand owns a frozen proposed restriction. Construction and copies
// perform no IO and authorize no transition. Bindings returns an owned copy;
// only the exact preparing policy can validate current admission. Zero is invalid.
type LockoutCommand struct{ state *lockoutCommandState }
type lockoutCommandState struct {
	owner   *lockoutPolicyState
	request LockoutRequest
	counter CounterCommand
}

// NewLockoutPolicy validates configuration without callbacks or storage access.
// Invalid counter custody or a missing/non-microsecond duration ceiling fails
// with ErrInvalidPolicy. It does not infer lockout from velocity exhaustion.
func NewLockoutPolicy(c LockoutPolicyConfig) (LockoutPolicy, error) {
	if c.Counters.state == nil || c.MaximumDuration <= 0 || c.MaximumDuration%time.Microsecond != 0 {
		return LockoutPolicy{}, ErrInvalidPolicy
	}
	return LockoutPolicy{state: &lockoutPolicyState{counters: c.Counters, maximum: c.MaximumDuration}}, nil
}

// Prepare freezes an exact operation/subject/CAS intent at supplied primary UTC
// microsecond time. Authentication and recovery profiles remain excluded, so a
// credential-change restriction cannot become an account-wide recovery ban.
// Preparation is not permission and cannot access a provider or state store.
func (p LockoutPolicy) Prepare(r LockoutRequest, primaryTime time.Time) (LockoutCommand, error) {
	if p.state == nil || !scopeID(r.Actor) || !r.Scope.Now.IsZero() || r.Scope.IndependentFactor || r.ExpectedVersion == ^uint64(0) {
		return LockoutCommand{}, ErrInvalidCounterCommand
	}
	switch r.Mode {
	case StartLockout:
		if r.Duration <= 0 || r.Duration > p.state.maximum || r.Duration%time.Microsecond != 0 || !databaseEvidenceTime(primaryTime.Add(r.Duration)) {
			return LockoutCommand{}, ErrInvalidCounterCommand
		}
	case EndLockout:
		if r.ExpectedVersion == 0 || r.Duration != 0 {
			return LockoutCommand{}, ErrInvalidCounterCommand
		}
	default:
		return LockoutCommand{}, ErrInvalidCounterCommand
	}
	a, err := p.state.counters.state.policy.Admit(r.Scope.Operation)
	if err != nil || a.Profile.Class != CredentialMutation || lockoutRecoveryOperation(r.Scope.Operation) {
		return LockoutCommand{}, ErrInvalidCounterCommand
	}
	counter, err := p.state.counters.Prepare(r.Scope, r.Subject, primaryTime)
	if err != nil {
		return LockoutCommand{}, ErrInvalidCounterCommand
	}
	return LockoutCommand{state: &lockoutCommandState{owner: p.state, request: r, counter: counter}}, nil
}

// Counter classification is not recovery eligibility: the canonical matrix
// classifies factor proofs and administrative recovery as credential mutations.
// Preserve those recovery/support routes without changing their counter profile
// or letting a request supply an override. These are exact canonical operations,
// not prefix heuristics or an alternative action catalog.
func lockoutRecoveryOperation(action Action) bool {
	switch action {
	case "identity.mfa.recovery-use", "identity.mfa.recovery-regenerate",
		"identity.mfa.totp-verify", "identity.mfa.security-key-assert-verify",
		"identity.mfa.otp-send", "identity.mfa.otp-verify",
		"identity.admin.mfa-recovery-issue", "identity.admin.mfa-reset":
		return true
	default:
		return false
	}
}

// Validate authenticates the exact policy and original request at current
// primary time without renewing its exclusive counter-policy admission TTL.
// Current durable version and administrator authorization remain native checks.
func (p LockoutPolicy) Validate(c LockoutCommand, r LockoutRequest, primaryTime time.Time) error {
	if p.state == nil || c.state == nil || c.state.owner != p.state || c.state.request != r {
		return ErrInvalidCounterCommand
	}
	if r.Mode == StartLockout && !databaseEvidenceTime(primaryTime.Add(r.Duration)) {
		return ErrInvalidCounterCommand
	}
	return p.state.counters.Validate(c.state.counter, r.Scope, r.Subject, primaryTime)
}

// Bindings returns an owned redacted-storage projection. Zero returns no target.
// Changing the projection cannot change the retained original mutation intent.
func (c LockoutCommand) Bindings() LockoutBinding {
	if c.state == nil {
		return LockoutBinding{}
	}
	r := c.state.request
	b := LockoutBinding{Counter: c.state.counter.Bindings(), Actor: r.Actor, Mode: r.Mode, ExpectedVersion: r.ExpectedVersion, Duration: r.Duration}
	for _, target := range b.Counter.Targets {
		if target.Dimension == SubjectDimension {
			b.Target = CounterTarget{Dimension: target.Dimension, Keys: slices.Clone(target.Keys)}
		}
	}
	return b
}

// Format redacts startup custody and policy details.
func (LockoutPolicyConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.LockoutPolicyConfig(redacted)")
}

// MarshalJSON forbids accidental serialization of runtime custody.
func (LockoutPolicyConfig) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids accidental serialization of runtime custody.
func (LockoutPolicyConfig) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts runtime policy custody.
func (LockoutPolicy) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.LockoutPolicy(redacted)")
}

// MarshalJSON forbids runtime policy serialization.
func (LockoutPolicy) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids runtime policy serialization.
func (LockoutPolicy) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts trusted account, administrator and network inputs.
func (LockoutRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.LockoutRequest(redacted)")
}

// MarshalJSON forbids serialization of trusted request inputs.
func (LockoutRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids serialization of trusted request inputs.
func (LockoutRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts scoped digest and administrator linkage.
func (LockoutBinding) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.LockoutBinding(redacted)")
}

// MarshalJSON forbids exporting adapter-only projections.
func (LockoutBinding) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids exporting adapter-only projections.
func (LockoutBinding) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts retained proposed mutation custody.
func (LockoutCommand) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.LockoutCommand(redacted)")
}

// MarshalJSON forbids exporting opaque mutation custody.
func (LockoutCommand) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText forbids exporting opaque mutation custody.
func (LockoutCommand) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
