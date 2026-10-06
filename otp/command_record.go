package otp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

// CommandAttemptRecord is explicit code-free native adapter custody for the
// original server-issued logical submission. It includes PII and must never
// reach clients, logs or telemetry. Signature authenticates the random ID,
// complete scope/authorization/remember declaration, command/operation, mode,
// expected version and original submitted-code fingerprint. It is not a bearer,
// successful code check, current authorization or transaction receipt. Adapters
// own bounded persistence encoding and must verify before use. Zero is invalid;
// callers own projections, and immutable embedded values support concurrent reads.
type CommandAttemptRecord struct {
	Attempt   AttemptBindings
	Binding   identity.CommandBinding
	Operation identity.FeatureOperation
	Signature [32]byte
}

// Format redacts private scope and correlation data.
func (CommandAttemptRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.CommandAttemptRecord(redacted)")
}

// MarshalJSON rejects automatic private custody export.
func (CommandAttemptRecord) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit private custody export.
func (CommandAttemptRecord) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// SealForCommand authenticates an already prepared command-bound attempt using
// the exact original issuer key/version. Zero and legacy unbound attempts deny.
// This neither generates an ID nor accesses a store, challenge, clock or entropy.
// The record contains no code. An adapter may persist it with the original
// command but may not expose it as a client-selected replacement submission.
func (i AttemptIssuer) SealForCommand(a AttemptCommand) (CommandAttemptRecord, error) {
	if a.state == nil || a.state.command == nil {
		return CommandAttemptRecord{}, ErrInvalidAttempt
	}
	r := CommandAttemptRecord{Attempt: a.state.bindings, Binding: a.state.command.binding, Operation: a.state.command.operation}
	s, err := i.recordScope(r)
	if err != nil {
		return CommandAttemptRecord{}, err
	}
	fingerprint, err := i.fingerprint(r.Attempt.Continuation, r.Attempt.Mode, r.Attempt.ExpectedVersion, a.state.code, s)
	if err != nil {
		return CommandAttemptRecord{}, err
	}
	defer clear(fingerprint[:])
	if !equalAttemptFingerprint(r.Attempt.Fingerprint, fingerprint) {
		return CommandAttemptRecord{}, ErrInvalidAttempt
	}
	r.Signature = i.recordSignature(r, s)
	return r, nil
}

// VerifyCommandRecord authenticates immutable historical declaration only,
// without submitted-code access or comparison. It grants no current validity,
// reservation, attempt allowance or replay exemption. Retain the original issuer
// key/version until dependent history is retired; a replacement key or unknown
// version denies without fallback. Bounded pure crypto; no IO or goroutines.
func (i AttemptIssuer) VerifyCommandRecord(r CommandAttemptRecord) error {
	s, err := i.recordScope(r)
	if err != nil {
		return err
	}
	want := i.recordSignature(r, s)
	defer clear(want[:])
	if r.Signature == ([32]byte{}) || !hmac.Equal(want[:], r.Signature[:]) {
		return ErrInvalidAttempt
	}
	return nil
}

// RestoreForCommand restores the exact sealed logical submission with an opaque
// copy of the original submitted code. It verifies custody BEFORE authenticating
// that code against the original attempt fingerprint, never the stored challenge
// digest. No ID, fingerprint, expiry or policy is regenerated, and no authority
// is renewed. This is adapter restoration, not an online OTP verification API:
// call only for private original-command custody, then enforce primary replay,
// current authority and counted challenge verification in the shared transaction.
// Wrong code, zero or tampered records and unavailable issuer versions deny with
// ErrInvalidAttempt. Discard restored code custody after the bounded operation.
func (i AttemptIssuer) RestoreForCommand(r CommandAttemptRecord, code auth.OneTimeCode) (AttemptCommand, error) {
	if err := i.VerifyCommandRecord(r); err != nil {
		return AttemptCommand{}, err
	}
	s, _ := i.recordScope(r)
	fingerprint, err := i.fingerprint(r.Attempt.Continuation, r.Attempt.Mode, r.Attempt.ExpectedVersion, code, s)
	if err != nil {
		return AttemptCommand{}, err
	}
	defer clear(fingerprint[:])
	if !equalAttemptFingerprint(r.Attempt.Fingerprint, fingerprint) {
		return AttemptCommand{}, ErrInvalidAttempt
	}
	return AttemptCommand{state: &attemptState{bindings: r.Attempt, command: s, code: code}}, nil
}

func equalAttemptFingerprint(f AttemptFingerprint, want [32]byte) bool {
	got, err := base64.RawURLEncoding.Strict().DecodeString(string(f))
	defer clear(got)
	return err == nil && len(got) == 32 && hmac.Equal(got, want[:])
}

func (i AttemptIssuer) recordScope(r CommandAttemptRecord) (*attemptCommandScope, error) {
	a := r.Attempt
	if i.version == 0 || i.key == ([32]byte{}) || a.FingerprintKeyVersion != i.version || a.Continuation.state == nil ||
		a.ExpectedVersion == 0 || (a.Mode != AttemptModeCheck && a.Mode != AttemptModeConsume) || len(a.AttemptID) != 22 || len(a.Fingerprint) != 43 || a.CommandID != r.Binding.CommandID {
		return nil, ErrInvalidAttempt
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(a.AttemptID))
	if err != nil || len(id) != 16 || string(id) == string(make([]byte, 16)) {
		return nil, ErrInvalidAttempt
	}
	fingerprint, err := base64.RawURLEncoding.Strict().DecodeString(string(a.Fingerprint))
	if err != nil || len(fingerprint) != 32 {
		return nil, ErrInvalidAttempt
	}
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: r.Binding, Operation: r.Operation})
	if err != nil {
		return nil, ErrInvalidAttempt
	}
	s, _ := c.Feature()
	scope := a.Continuation.state.bindings.Scope
	if s.Binding != r.Binding || s.Operation != r.Operation || string(s.Binding.TenantID) != scope.TenantID || string(s.Binding.UserID) != scope.SubjectID || s.Operation.RecordRequirement == identity.FeatureRecordRequired && s.Binding.RecordID != scope.TargetID {
		return nil, ErrInvalidAttempt
	}
	return &attemptCommandScope{binding: s.Binding, operation: s.Operation, digest: attemptCommandDigest(s.Binding, s.Operation)}, nil
}

// This independent MAC includes the random server ID omitted by the legacy
// code-fingerprint profile. Domain separation preserves that released profile
// while preventing an adapter/client from swapping correlation identities.
func (i AttemptIssuer) recordSignature(r CommandAttemptRecord, s *attemptCommandScope) [32]byte {
	a := r.Attempt
	scope := a.Continuation.state.scope.binding
	frame := []byte("identity-otp-command-attempt-record-v1\x00")
	frame = binary.BigEndian.AppendUint32(frame, i.version)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(scope)))
	frame = append(frame, scope...)
	frame = append(frame, string(a.AttemptID)...)
	frame = append(frame, string(a.Fingerprint)...)
	frame = append(frame, byte(a.Mode))
	frame = binary.BigEndian.AppendUint64(frame, a.ExpectedVersion)
	frame = append(frame, s.digest[:]...)
	defer clear(frame)
	h := hmac.New(sha256.New, i.key[:])
	_, _ = h.Write(frame)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
