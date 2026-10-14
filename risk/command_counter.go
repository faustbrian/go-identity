package risk

import (
	"crypto/hmac"
	"fmt"
	"io"
	"slices"
	"time"
)

// CommandCounterPolicyConfig selects existing protected-operation profiles and
// 1..4 newest-first retained digest keys. All active versions must be retained;
// the native store verifies their authoritative rotation history. No clock,
// store, lockout duration or caller-selected profile can be configured here.
type CommandCounterPolicyConfig struct {
	Policy Policy
	Keys   []CounterDigestKey
}

// Format redacts retained keys and policy configuration in diagnostics.
func (CommandCounterPolicyConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CommandCounterPolicyConfig(redacted)")
}

// MarshalJSON rejects serialization of retained secret configuration.
func (CommandCounterPolicyConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects serialization of retained secret configuration.
func (CommandCounterPolicyConfig) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// CommandCounterPolicy owns pure preparation for CredentialMutation and
// Privileged counters at ReserveWithCommand, never ephemeral velocity. Zero is
// invalid; copies share immutable state and are safe for concurrent reads.
// The registered native PostgreSQL participant must validate this exact policy
// and command scope, mutate once during the coordinator reservation transaction,
// and resolve its outcome through that coordinator. Preparation grants no
// allowance, lockout override, reservation or durable commitment. It performs
// no IO, clock sampling, provider callbacks or dispatch.
type CommandCounterPolicy struct{ state *commandCounterPolicy }
type commandCounterPolicy struct {
	policy Policy
	keys   []CounterDigestKey
}

// Format omits private authority and retained key material.
func (CommandCounterPolicy) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CommandCounterPolicy(redacted)")
}

// MarshalJSON rejects export of runtime authority configuration.
func (CommandCounterPolicy) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects export of runtime authority configuration.
func (CommandCounterPolicy) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// NewCommandCounterPolicy validates and copies configuration without IO.
// Secret bytes were already copied by NewCounterDigestKey. Duplicate, unordered
// or invalid versions and incomplete policy fail with ErrInvalidPolicy.
func NewCommandCounterPolicy(c CommandCounterPolicyConfig) (CommandCounterPolicy, error) {
	if c.Policy.state == nil || len(c.Keys) == 0 || len(c.Keys) > 4 {
		return CommandCounterPolicy{}, ErrInvalidPolicy
	}
	for i, key := range c.Keys {
		if key.version == 0 || len(key.secret) < 32 || len(key.secret) > 128 || i > 0 && c.Keys[i-1].version <= key.version {
			return CommandCounterPolicy{}, ErrInvalidPolicy
		}
	}
	return CommandCounterPolicy{state: &commandCounterPolicy{policy: c.Policy, keys: slices.Clone(c.Keys)}}, nil
}

// Prepare derives bounded, keyed storage projections at supplied primary UTC
// microsecond time. Context.Now and factor flags confer no authority. Only the
// exact closed protected profile and its exact dimensions are accepted. Every
// other phase/class fails before derivation. Raw dimensions never enter the
// projection. Durable keys and fingerprints are domain-separated from velocity.
func (p CommandCounterPolicy) Prepare(scope Context, subject Subject, primaryTime time.Time) (CounterCommand, error) {
	if p.state == nil {
		return CounterCommand{}, ErrInvalidPolicy
	}
	if !databaseEvidenceTime(primaryTime) || !scopeID(scope.Tenant) || !scopeID(scope.Attempt) {
		return CounterCommand{}, ErrInvalidCounterCommand
	}
	a, err := p.state.policy.Admit(scope.Operation)
	if err != nil {
		return CounterCommand{}, err
	}
	if a.Preflight != "" || a.Profile.Phase != ReserveWithCommand || a.Profile.Class != CredentialMutation && a.Profile.Class != Privileged {
		return CounterCommand{}, ErrUnsupportedCounterPhase
	}
	command, err := prepareCounter(scope, subject, ReserveWithCommand, a, primaryTime, p.state.keys, true)
	if err != nil {
		return CounterCommand{}, err
	}
	command.state.commandOwner = p.state
	return command, nil
}

// Validate authenticates exact policy ownership and reconstructs every original
// scoped target without IO at primary time. It never refreshes PreparedAt; the
// profile evidence interval is exclusive. A foreign policy, ephemeral command,
// changed scope or expired command fails redacted. The native participant must
// separately prove current Work/command ownership and authoritative row state.
// This check is not a durable-counter snapshot or permission to mutate.
func (p CommandCounterPolicy) Validate(command CounterCommand, scope Context, subject Subject, primaryTime time.Time) error {
	if p.state == nil || command.state == nil || command.state.owner != nil || command.state.commandOwner != p.state || !databaseEvidenceTime(primaryTime) {
		return ErrInvalidCounterCommand
	}
	b := command.state.binding
	if primaryTime.Before(b.PreparedAt) || !primaryTime.Before(b.PreparedAt.Add(command.state.profile.EvidenceTTL)) {
		return ErrInvalidCounterCommand
	}
	expected, err := p.Prepare(scope, subject, b.PreparedAt)
	if err != nil || !hmac.Equal([]byte(expected.state.binding.Fingerprint), []byte(b.Fingerprint)) {
		return ErrInvalidCounterCommand
	}
	return nil
}
