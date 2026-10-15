package otp

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// CheckService is the optional, independently composable non-consuming OTP
// workflow. Service deliberately remains Send-only for existing implementers.
// Each Check is a new logical submission: the service allocates its command and
// attempt identity. After ambiguity call RecoverCheck, never resubmit Check.
// Both methods require current authorization and original bearer possession.
// Correct Check grants no proof, reservation, session or workflow authority.
type CheckService interface {
	Check(context.Context, CheckRequest) (CheckResult, error)
	RecoverCheck(context.Context, CheckRecoveryRequest) (CheckResult, error)
}

// CheckRequest selects an original public Send command, not a caller-created
// challenge. Flow supplies the same original possession variant as Send.
// Caller is trusted composition context, never authentication evidence itself.
// There is intentionally no idempotency key, attempt ID or expected version.
// Adapters validate Code through its opaque owner before metering. Do not mutate
// Caller maps during a call. Transport must not log code or bearer custody.
type CheckRequest struct {
	TenantID      identity.TenantID
	UserID        identity.UserID
	Caller        authorization.DecisionContext
	Flow          SendFlow
	SendCommandID identity.CommandID
	Code          auth.OneTimeCode
}

// Validate checks bounded structure only; it neither authenticates the bearer
// nor compares Code. Invalid opaque codes fail during server attempt preparation.
func (r CheckRequest) Validate() error {
	if _, err := identity.ParseCommandID(string(r.SendCommandID)); err != nil {
		return ErrInvalidAttempt
	}
	return validateCheckScope(r.TenantID, r.UserID, r.Caller, r.Flow)
}

func validateCheckScope(tenant identity.TenantID, user identity.UserID, caller authorization.DecisionContext, flow SendFlow) error {
	if len(caller.Request.Attributes) > 64 || len(caller.Request.Subject.Groups) > 64 || len(caller.Request.Subject.Attributes) > 64 || len(caller.Request.Resource.Attributes) > 64 || len(caller.Request.Environment.Attributes) > 64 {
		return ErrInvalidAttempt
	}
	kind, _, _, err := flow.Bindings()
	if err != nil || caller.Validate() != nil || string(caller.Request.Tenant) != string(tenant) || !boundedText(string(tenant), 128, false) || !boundedText(string(caller.Request.Subject.ID), 128, false) || user != "" && !boundedText(string(user), 128, false) || kind == FlowAuthorizationAuthenticatedSession && user == "" {
		return ErrInvalidAttempt
	}
	switch caller.Request.Subject.Kind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
		return nil
	default:
		return ErrInvalidAttempt
	}
}

// CheckRecoveryBindings is a code-free trusted transport projection of one
// server-prepared attempt. None of these fields grants permission or proves a
// result. Adapters must match the exact retained journal plan AND authenticate
// original Send custody, current caller and flow. Do not use it to submit Check.
type CheckRecoveryBindings struct {
	SendCommandID    identity.CommandID
	Attempt          AttemptRecoveryIdentity
	ExpectedVersion  uint64
	DigestKeyVersion uint32
	ScopeDigest      [32]byte
}

// CheckRecovery retains immutable code-free original correlation. Zero is
// invalid. It owns no resource, code, bearer or key; copies support concurrent
// recovery. Native transport must explicitly project Bindings rather than rely
// on default serialization. Reconstructing it does not authenticate its values.
type CheckRecovery struct{ bindings CheckRecoveryBindings }

// NewCheckRecovery validates bounded canonical correlation structure without
// IO or authentication. Only the service issues original values; a transport
// may reconstruct them for recovery, never for new-attempt selection.
func NewCheckRecovery(b CheckRecoveryBindings) (CheckRecovery, error) {
	if _, err := identity.ParseCommandID(string(b.SendCommandID)); err != nil {
		return CheckRecovery{}, ErrInvalidAttempt
	}
	if _, err := identity.ParseCommandID(string(b.Attempt.CommandID)); err != nil {
		return CheckRecovery{}, ErrInvalidAttempt
	}
	if !boundedText(string(b.Attempt.TenantID), 128, false) || b.Attempt.FingerprintKeyVersion == 0 || b.ExpectedVersion == 0 || b.DigestKeyVersion == 0 || b.ScopeDigest == ([32]byte{}) {
		return CheckRecovery{}, ErrInvalidAttempt
	}
	for _, item := range []struct {
		text string
		size int
	}{{string(b.Attempt.AttemptID), 16}, {string(b.Attempt.Fingerprint), 32}} {
		if len(item.text) != base64.RawURLEncoding.EncodedLen(item.size) {
			return CheckRecovery{}, ErrInvalidAttempt
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(item.text)
		if err != nil || len(raw) != item.size {
			return CheckRecovery{}, ErrInvalidAttempt
		}
		var any byte
		for _, v := range raw {
			any |= v
		}
		clear(raw)
		if any == 0 {
			return CheckRecovery{}, ErrInvalidAttempt
		}
	}
	return CheckRecovery{bindings: b}, nil
}

// Bindings returns a scalar copy, not authority to disclose a retained outcome.
func (r CheckRecovery) Bindings() (CheckRecoveryBindings, error) {
	if _, err := NewCheckRecovery(r.bindings); err != nil {
		return CheckRecoveryBindings{}, err
	}
	return r.bindings, nil
}

// CheckRecoveryRequest supplies fresh caller and original bearer possession;
// no submitted code is needed or accepted. Recovery never charges or takes over.
type CheckRecoveryRequest struct {
	TenantID identity.TenantID
	UserID   identity.UserID
	Caller   authorization.DecisionContext
	Flow     SendFlow
	Recovery CheckRecovery
}

// Validate checks bounded structure and tenant agreement, not authorization.
func (r CheckRecoveryRequest) Validate() error {
	b, err := r.Recovery.Bindings()
	if err != nil || b.Attempt.TenantID != r.TenantID {
		return ErrInvalidAttempt
	}
	return validateCheckScope(r.TenantID, r.UserID, r.Caller, r.Flow)
}

// CheckResult distinguishes durable receipt state from non-authoritative Valid.
// Valid is true only for Committed; Unknown/InProgress never imply code validity
// or permission to retry submission. Recovery is present after a server attempt
// is prepared, including ambiguous execution; preserve it unchanged. RetryAfter
// applies only to InProgress. No attempts-remaining value is disclosed.
type CheckResult struct {
	CommandID  identity.CommandID
	Outcome    identity.CommitOutcome
	Valid      bool
	Recovery   CheckRecovery
	RetryAfter time.Duration
}

func (CheckRequest) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("otp.CheckRequest(redacted)")) }
func (CheckRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CheckRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CheckRequest) LogValue() slog.Value         { return slog.StringValue("otp.CheckRequest(redacted)") }
func (CheckRecoveryBindings) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.CheckRecoveryBindings(redacted)"))
}
func (CheckRecoveryBindings) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CheckRecoveryBindings) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CheckRecoveryBindings) LogValue() slog.Value {
	return slog.StringValue("otp.CheckRecoveryBindings(redacted)")
}
func (CheckRecovery) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.CheckRecovery(redacted)"))
}
func (CheckRecovery) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CheckRecovery) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CheckRecovery) LogValue() slog.Value         { return slog.StringValue("otp.CheckRecovery(redacted)") }
func (CheckRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.CheckRecoveryRequest(redacted)"))
}
func (CheckRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CheckRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CheckRecoveryRequest) LogValue() slog.Value {
	return slog.StringValue("otp.CheckRecoveryRequest(redacted)")
}
