package otp

import (
	"context"
	"fmt"
	"log/slog"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SigninService is the optional consuming OTP login workflow. Existing Service
// remains Send-only, and CheckService never grants signin authority. Each Signin
// call creates one server-owned logical submission; after ambiguity use only
// RecoverSignin with the original returned recovery correlation. Implementations
// must atomically consume the original OTP and pre-auth transaction with session,
// audit, outbox and command effects. All IO must honor ctx and a bounded service
// deadline. Concurrent calls must not issue multiple sessions from one challenge.
type SigninService interface {
	Signin(context.Context, SigninRequest) (SigninResult, error)
	RecoverSignin(context.Context, SigninRecoveryRequest) (SigninResult, error)
}

// SigninRequest selects an original public Send and the same pre-auth cookie
// possession. UserID preserves the original command subject; it may be empty for
// anonymous pre-auth and must not be replaced by the subsequently resolved user.
// Caller is trusted composition context, not authentication evidence. No field
// selects attempt identity, version, recipient, remember policy or lifetime:
// those come from original server custody. Do not mutate Caller during a call.
// The service validates opaque Code before metering; never log this request.
type SigninRequest struct {
	TenantID      identity.TenantID
	UserID        identity.UserID
	Caller        authorization.DecisionContext
	Flow          SendFlow
	SendCommandID identity.CommandID
	Code          auth.OneTimeCode
}

// Validate checks bounded structural selection only. It neither authenticates
// possession nor validates Code, current policy, recipient or challenge state.
// Authenticated-session continuations are not a login profile and fail closed.
func (r SigninRequest) Validate() error {
	if _, err := identity.ParseCommandID(string(r.SendCommandID)); err != nil {
		return ErrInvalidAttempt
	}
	return validateSigninScope(r.TenantID, r.UserID, r.Caller, r.Flow)
}

func validateSigninScope(tenant identity.TenantID, user identity.UserID, caller authorization.DecisionContext, flow SendFlow) error {
	if err := validateCheckScope(tenant, user, caller, flow); err != nil {
		return err
	}
	kind, _, _, _ := flow.Bindings()
	if kind != FlowAuthorizationPreAuthTransaction {
		return ErrInvalidAttempt
	}
	return nil
}

// SigninRecoveryBindings is the code-free scalar projection of one original
// consuming attempt. Fields have the same bounded correlation shape as Check,
// but this distinct type selects neither Check nor new execution. The adapter
// must match every field to the retained consuming plan, original Send custody
// and current disclosure policy. Possession of these values grants no authority.
type SigninRecoveryBindings CheckRecoveryBindings

// SigninRecovery freezes original code-free correlation. Zero is invalid;
// copies support concurrent reads and own no code, credential, key or resource.
// Use Bindings for an explicit trusted transport projection, not serialization.
type SigninRecovery struct{ bindings SigninRecoveryBindings }

// NewSigninRecovery validates shape without IO, authentication or lookup. Only
// the service allocates original attempts; reconstruction is solely for recovery.
// Send and consuming commands must differ. No session identity is client-selected.
func NewSigninRecovery(b SigninRecoveryBindings) (SigninRecovery, error) {
	if b.SendCommandID == b.Attempt.CommandID {
		return SigninRecovery{}, ErrInvalidAttempt
	}
	if _, err := NewCheckRecovery(CheckRecoveryBindings(b)); err != nil {
		return SigninRecovery{}, err
	}
	return SigninRecovery{bindings: b}, nil
}

// Bindings returns a scalar copy. It proves neither authenticity nor permission
// to disclose history, resume execution, replace an attempt or issue a session.
func (r SigninRecovery) Bindings() (SigninRecoveryBindings, error) {
	if _, err := NewSigninRecovery(r.bindings); err != nil {
		return SigninRecoveryBindings{}, err
	}
	return r.bindings, nil
}

// SigninRecoveryRequest supplies fresh caller context and original pre-auth
// possession, but no code. The adapter authorizes historical disclosure against
// retained original scope and current policy; it must not require the original
// pre-auth transaction to remain executable after successful consumption/expiry.
// Recovery never compares codes, charges attempts or redelivers credentials.
type SigninRecoveryRequest struct {
	TenantID identity.TenantID
	UserID   identity.UserID
	Caller   authorization.DecisionContext
	Flow     SendFlow
	Recovery SigninRecovery
}

// Validate checks bounded structure and exact tenant agreement, not authority.
func (r SigninRecoveryRequest) Validate() error {
	b, err := r.Recovery.Bindings()
	if err != nil || b.Attempt.TenantID != r.TenantID {
		return ErrInvalidAttempt
	}
	return validateSigninScope(r.TenantID, r.UserID, r.Caller, r.Flow)
}

// SigninResult reuses the session owner's commit outcome and reveal-once token
// custody instead of creating another issuance model. SessionID is the original
// committed session identity when historical disclosure is authorized, even if
// its live payload has been deleted. It is empty for noncommitted, unresolved or
// undisclosed outcomes. Issuance.Session may be zero on historical recovery;
// never fabricate a partial session to populate it. Neither identifies current
// authority. Only a fresh successful committed
// issuance may carry Token and CSRFToken; Cookie.Value is always empty and
// trusted transport explicitly reveals the original bearer once. Replay,
// recovery, error, cancellation and unknown outcomes carry no credentials.
// Preserve Recovery after server attempt preparation, including denied or
// ambiguous outcomes; never resubmit Signin as a retry. No attempts-remaining
// count is disclosed. MFA continuation composition is a separate required
// profile; a single-factor adapter must fail closed when further factors apply.
type SigninResult struct {
	SessionID string
	Issuance  session.IssueResult
	CSRFToken session.CSRFToken
	Recovery  SigninRecovery
}

func (SigninRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.SigninRequest(redacted)"))
}
func (SigninRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRequest) LogValue() slog.Value         { return slog.StringValue("otp.SigninRequest(redacted)") }
func (SigninRecoveryBindings) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.SigninRecoveryBindings(redacted)"))
}
func (SigninRecoveryBindings) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecoveryBindings) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecoveryBindings) LogValue() slog.Value {
	return slog.StringValue("otp.SigninRecoveryBindings(redacted)")
}
func (SigninRecovery) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.SigninRecovery(redacted)"))
}
func (SigninRecovery) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecovery) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecovery) LogValue() slog.Value         { return slog.StringValue("otp.SigninRecovery(redacted)") }
func (SigninRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.SigninRecoveryRequest(redacted)"))
}
func (SigninRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninRecoveryRequest) LogValue() slog.Value {
	return slog.StringValue("otp.SigninRecoveryRequest(redacted)")
}
func (SigninResult) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("otp.SigninResult(redacted)")) }
func (SigninResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninResult) LogValue() slog.Value         { return slog.StringValue("otp.SigninResult(redacted)") }
