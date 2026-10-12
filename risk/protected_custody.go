package risk

import (
	"context"
	"crypto/hmac"
	"fmt"
	"io"
	"slices"
	"time"
)

// ProtectedProviderAdmissionCustodyConfig pins provider configuration and
// retained existing integrity keys. Sources require explicit versions. Unlike
// Authentication custody it does not require nontransactional counters/audit;
// those belong to the protected command. It is immutable startup input.
type ProtectedProviderAdmissionCustodyConfig AuthenticationAdmissionCustodyConfig

// ProtectedProviderAdmissionCustody retains provider-only facts for the existing
// encrypted preparation journal. It reuses the native admission integrity codec
// with a distinct profile; it owns no store, issuer, counter or audit sink.
type ProtectedProviderAdmissionCustody struct{ state *authenticationCustody }

// PreparedProtectedProviderAdmission is an owned native projection for the
// existing authenticated encrypted output, never transport input. Its fields
// grant nothing without Restore. Original scope, observations and exclusive
// expiry cannot be renewed by a copy or restart. Velocity is never included.
type PreparedProtectedProviderAdmission struct {
	Scope                          Context
	Signals                        []Signal
	KeyVersion                     uint32
	PolicyVersion                  uint64
	ConfigurationDigest, Signature [32]byte
}

// ProtectedProviderAdmission is opaque provider-only custody. It supplies no
// factor proof, counter allowance or authentication permission. The protected
// owner still reserves velocity and audits atomically with its effects.
type ProtectedProviderAdmission struct {
	owner    *authenticationCustody
	prepared PreparedProtectedProviderAdmission
}

func (ProtectedProviderAdmissionCustody) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.ProtectedProviderAdmissionCustody(redacted)")
}
func (ProtectedProviderAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.ProtectedProviderAdmission(redacted)")
}
func (PreparedProtectedProviderAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.PreparedProtectedProviderAdmission(redacted)")
}
func (ProtectedProviderAdmissionCustody) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (ProtectedProviderAdmission) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (PreparedProtectedProviderAdmission) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (ProtectedProviderAdmissionCustody) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (ProtectedProviderAdmission) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (PreparedProtectedProviderAdmission) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// NewProtectedProviderAdmissionCustody validates/copies configuration without
// callbacks or IO. Check/Restore are concurrent-safe with immutable callbacks.
func NewProtectedProviderAdmissionCustody(c ProtectedProviderAdmissionCustodyConfig) (ProtectedProviderAdmissionCustody, error) {
	s, err := newAdmissionCustody(AuthenticationAdmissionCustodyConfig(c), true)
	return ProtectedProviderAdmissionCustody{state: s}, err
}

// ValidateCounterPolicy requires native counters to consume the exact immutable
// policy that produced these provider facts, not an equivalent version number
// with different limits or failure behavior. It performs no callbacks or IO.
func (s ProtectedProviderAdmissionCustody) ValidateCounterPolicy(p Policy) error {
	if s.state == nil || !s.state.protectedProviders || p.state == nil || s.state.evaluation.state.policy.state != p.state {
		return ErrInvalidPolicy
	}
	return nil
}

// Prepared returns an independently owned native projection, or zero for zero.
func (a ProtectedProviderAdmission) Prepared() PreparedProtectedProviderAdmission {
	p := a.prepared
	p.Signals = slices.Clone(p.Signals)
	return p
}

func protectedSignature(key EvidenceKey, p PreparedProtectedProviderAdmission) [32]byte {
	return authenticationSignature(key, PreparedAuthenticationAdmission{Scope: p.Scope, Signals: p.Signals, KeyVersion: p.KeyVersion, PolicyVersion: p.PolicyVersion, ConfigurationDigest: p.ConfigurationDigest})
}

// Prepare captures only this evaluator's owned fresh provider-only Allow. It
// performs no provider/store/audit IO, counter mutation or evidence issuance.
func (s ProtectedProviderAdmissionCustody) Prepare(ctx context.Context, r EvaluateResult, scope Context) (ProtectedProviderAdmission, error) {
	if ctx == nil {
		return ProtectedProviderAdmission{}, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return ProtectedProviderAdmission{}, err
	}
	if s.state == nil || !s.state.protectedProviders {
		return ProtectedProviderAdmission{}, ErrInvalidProtectedProviderAdmission
	}
	if err := s.state.evaluation.RequireProtectedProviderAdmission(ctx, r, scope); err != nil {
		return ProtectedProviderAdmission{}, err
	}
	p := PreparedProtectedProviderAdmission{Scope: r.provenance.context, Signals: slices.Clone(r.provenance.signals), KeyVersion: s.state.current.version, PolicyVersion: r.PolicyVersion, ConfigurationDigest: s.state.configuration(s.state.current)}
	p.Signature = protectedSignature(s.state.current, p)
	return s.Restore(ctx, p, scope)
}

// Restore authenticates bounded original facts against the same pinned provider
// configuration and retained key. It invokes no providers, counters or audit.
// Changed scope/policy/configuration, tampering and original expiry deny. It
// restores no EvaluateResult provenance and cannot authorize another charge.
func (s ProtectedProviderAdmissionCustody) Restore(ctx context.Context, p PreparedProtectedProviderAdmission, scope Context) (ProtectedProviderAdmission, error) {
	bad := func() (ProtectedProviderAdmission, error) {
		return ProtectedProviderAdmission{}, ErrInvalidProtectedProviderAdmission
	}
	if ctx == nil {
		return ProtectedProviderAdmission{}, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return ProtectedProviderAdmission{}, err
	}
	if s.state == nil || !s.state.protectedProviders || len(p.Signals) > 32 || !validTime(p.Scope.Now) || p.Scope.Tenant != scope.Tenant || p.Scope.Operation != scope.Operation || p.Scope.Attempt != scope.Attempt || p.PolicyVersion != s.state.evaluation.state.policy.state.version {
		return bad()
	}
	var key EvidenceKey
	for _, k := range s.state.keys {
		if k.version == p.KeyVersion {
			key = k
			break
		}
	}
	if key.version == 0 || s.state.configuration(key) != p.ConfigurationDigest {
		return bad()
	}
	assessment, err := s.state.evaluation.state.policy.AssessProtectedProviders(ctx, p.Scope, p.Signals)
	if ctx.Err() != nil {
		return ProtectedProviderAdmission{}, ctx.Err()
	}
	if err != nil || assessment.Decision.Action != Allow {
		return bad()
	}
	want := protectedSignature(key, p)
	if !hmac.Equal(want[:], p.Signature[:]) {
		return bad()
	}
	p.Signals = slices.Clone(p.Signals)
	a := ProtectedProviderAdmission{owner: s.state, prepared: p}
	if err := a.Check(ctx); err != nil {
		return ProtectedProviderAdmission{}, err
	}
	return a, nil
}

// Check uses the configured clock without IO; original facts cannot renew.
func (a ProtectedProviderAdmission) Check(ctx context.Context) (err error) {
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.owner == nil || !a.owner.protectedProviders {
		return ErrInvalidProtectedProviderAdmission
	}
	defer func() {
		if recover() != nil {
			err = ErrInvalidProtectedProviderAdmission
		}
	}()
	return a.CheckAt(ctx, a.owner.evaluation.state.clock())
}

// CheckAt uses trusted primary time without invoking any configured callback,
// so it may run while native locks are held. Never pass request-controlled time.
// Invalid/backward times and exclusive expiry deny. Cancellation is preserved.
func (a ProtectedProviderAdmission) CheckAt(ctx context.Context, now time.Time) error {
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.owner == nil || !a.owner.protectedProviders || !validTime(now) || now.Before(a.prepared.Scope.Now) {
		return ErrInvalidProtectedProviderAdmission
	}
	c := a.prepared.Scope
	c.Now = now
	assessment, err := a.owner.evaluation.state.policy.AssessProtectedProviders(ctx, c, a.prepared.Signals)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || assessment.Decision.Action != Allow {
		return ErrInvalidProtectedProviderAdmission
	}
	return nil
}
