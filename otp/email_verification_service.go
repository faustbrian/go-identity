package otp

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// EmailVerificationService is the separately selected authenticated self-user
// pending-email OTP workflow. It does not extend the existing Send-only Service
// or reinterpret links, signin, primary replacement or MFA continuation. Durable
// adapters supply the complete workflow; consumers supply no domain stores.
// Calls require bounded contexts and preserve original recovery on ambiguity.
type EmailVerificationService interface {
	SendEmailVerification(context.Context, EmailVerificationSendRequest) (SendResult, error)
	EmailVerify(context.Context, EmailVerifyRequest) (EmailVerifyResult, error)
	RecoverEmailVerify(context.Context, EmailVerifyRecoveryRequest) (EmailVerifyResult, error)
}

// EmailVerificationSessionSource authenticates possession of the original
// password-session token for transport subject/CSRF mapping. The returned
// immutable record is private provenance, not current validity or authorization;
// it may describe revoked/expired history. Native Send/EmailVerify independently
// require executable authority, while recovery independently authorizes history.
// No refresh, credential issuance or freshness renewal is permitted.
type EmailVerificationSessionSource interface {
	EmailVerificationSession(context.Context, identity.TenantID, SendFlow) (session.Session, error)
}

// EmailVerificationRateSource provides native original correlation for transport
// budgets only. Pending recipient/factor/current authority must still be checked
// transactionally by the workflow. Send lookup preserves an existing keyed
// winner instead of retargeting after mutation; neither call writes or issues.
type EmailVerificationRateSource interface {
	EmailVerificationSessionSource
	EmailVerificationSendDestination(context.Context, EmailVerificationSendRequest) (DestinationInput, error)
	EmailVerificationChallenge(context.Context, EmailVerifyRequest) (EmailVerificationChallenge, error)
}

// EmailVerificationChallenge is private original scope for verification budgets,
// not a proof, validity lease or public response. Lifetime is the original issued
// challenge interval; callers must not replace it with a renewed remaining TTL.
type EmailVerificationChallenge struct {
	UserID   identity.UserID
	Target   EmailVerificationTarget
	Lifetime time.Duration
}

// Format redacts original subject and workflow correlation.
func (EmailVerificationChallenge) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailVerificationChallenge(redacted)"))
}

// MarshalJSON denies implicit source export.
func (EmailVerificationChallenge) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText denies implicit source export.
func (EmailVerificationChallenge) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// EmailVerificationSendRequest selects an existing pending nonprimary address
// and its exact version. Native identity/MFA owners resolve its mailbox, current
// verification and factor generations; callers cannot supply those authorities.
// Flow carries actual original session possession. Caller/network/device require
// trusted composition provenance. Keep caller collections immutable during use.
type EmailVerificationSendRequest struct {
	TenantID        identity.TenantID
	UserID          identity.UserID
	AddressID       identity.IdentifierID
	AddressVersion  uint64
	Caller          authorization.DecisionContext
	Flow            SendFlow
	Network, Device string
	IdempotencyKey  identity.IdempotencyKey
}

// Validate admits structure only, without reading, authenticating or issuing.
func (r EmailVerificationSendRequest) Validate() error {
	if validateEmailVerificationScope(r.TenantID, r.UserID, r.Caller, r.Flow, "identity.otp.send") != nil || r.AddressVersion == 0 || r.AddressVersion == ^uint64(0) || r.IdempotencyKey == (identity.IdempotencyKey{}) || !boundedText(r.Device, 128, false) || len(r.Network) > 128 {
		return ErrInvalidAttempt
	}
	if _, err := identity.ParseIdentifierID(string(r.AddressID)); err != nil {
		return ErrInvalidAttempt
	}
	ip, err := netip.ParseAddr(r.Network)
	if err != nil || ip.Zone() != "" || ip.String() != r.Network {
		return ErrInvalidAttempt
	}
	return nil
}

// EmailVerifyRequest submits a new logical attempt against one original Send.
// The native owner alone allocates attempt/command identities and authenticates
// the original purpose, selector, target, versions and session possession.
// RecoverEmailVerify observes a returned ambiguous attempt without another code
// comparison. Reinvoking EmailVerify is a new submission, not recovery.
type EmailVerifyRequest struct {
	TenantID      identity.TenantID
	UserID        identity.UserID
	Caller        authorization.DecisionContext
	Flow          SendFlow
	SendCommandID identity.CommandID
	Code          auth.OneTimeCode
}

// Validate checks bounded structural scope; the native attempt issuer validates
// opaque Code before metering. It grants no possession, freshness or code proof.
func (r EmailVerifyRequest) Validate() error {
	if _, err := identity.ParseCommandID(string(r.SendCommandID)); err != nil {
		return ErrInvalidAttempt
	}
	return validateEmailVerificationScope(r.TenantID, r.UserID, r.Caller, r.Flow, "identity.otp.email-verify")
}

func validateEmailVerificationScope(tenant identity.TenantID, user identity.UserID, caller authorization.DecisionContext, flow SendFlow, action authorization.Action) error {
	if validateCheckScope(tenant, user, caller, flow) != nil || user == "" || caller.Request.Subject.Kind != authorization.SubjectUser || string(caller.Request.Subject.ID) != string(user) || caller.Request.Action != action {
		return ErrInvalidAttempt
	}
	kind, _, _, _ := flow.Bindings()
	if kind != FlowAuthorizationAuthenticatedSession {
		return ErrInvalidAttempt
	}
	return nil
}

// EmailVerifyRecovery is immutable original code-free attempt correlation.
// It contains neither a bearer nor permission to disclose or re-execute history.
// Zero denies. Copies permit concurrent reads without owning any resources.
type EmailVerifyRecovery struct{ state *emailVerifyRecoveryState }

type emailVerifyRecoveryState struct{ read func() CheckRecoveryBindings }

// NewEmailVerifyRecovery validates bounded original correlation without IO,
// authentication or lookup. Native recovery must bind it to this exact profile,
// original Send and current query policy; another workflow cannot be aliased.
func NewEmailVerifyRecovery(b CheckRecoveryBindings) (EmailVerifyRecovery, error) {
	if b.SendCommandID == b.Attempt.CommandID {
		return EmailVerifyRecovery{}, ErrInvalidAttempt
	}
	if _, err := NewCheckRecovery(b); err != nil {
		return EmailVerifyRecovery{}, err
	}
	return EmailVerifyRecovery{state: &emailVerifyRecoveryState{read: func() CheckRecoveryBindings { return b }}}, nil
}

// Bindings explicitly returns sensitive code-free original correlation.
func (r EmailVerifyRecovery) Bindings() (CheckRecoveryBindings, error) {
	if r.state == nil {
		return CheckRecoveryBindings{}, ErrInvalidAttempt
	}
	return r.state.read(), nil
}

// EmailVerifyRecoveryRequest selects original history under current query policy
// and original possession, never another comparison or replacement submission.
type EmailVerifyRecoveryRequest struct {
	TenantID identity.TenantID
	UserID   identity.UserID
	Caller   authorization.DecisionContext
	Flow     SendFlow
	Recovery EmailVerifyRecovery
}

// Validate checks scope and original tenant, not current disclosure authority.
func (r EmailVerifyRecoveryRequest) Validate() error {
	b, err := r.Recovery.Bindings()
	if err != nil || b.Attempt.TenantID != r.TenantID {
		return ErrInvalidAttempt
	}
	return validateEmailVerificationScope(r.TenantID, r.UserID, r.Caller, r.Flow, "identity.otp.email-verify.recover")
}

// EmailVerifyResult preserves observed durability independently of disclosure
// errors. Address appears only for a new successful commit, never replay,
// recovery or failure. This profile has no session/cookie/bearer fields.
// Unknown retains original Recovery; it is never an inferred rollback.
type EmailVerifyResult struct {
	CommandID  identity.CommandID
	Outcome    identity.CommitOutcome
	Address    identity.IdentifierProjection
	Recovery   EmailVerifyRecovery
	Replayed   bool
	RetryAfter time.Duration
}

// Format redacts sender intent and actual session possession.
func (EmailVerificationSendRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailVerificationSendRequest(redacted)"))
}

// MarshalJSON rejects implicit sender export; HTTP owns a separate schema.
func (EmailVerificationSendRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit sender export.
func (EmailVerificationSendRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts the actual code, session and original correlation.
func (EmailVerifyRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailVerifyRequest(redacted)"))
}

// MarshalJSON rejects implicit submission export.
func (EmailVerifyRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit submission export.
func (EmailVerifyRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts original correlation even in Go-syntax diagnostics.
func (EmailVerifyRecovery) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailVerifyRecovery(redacted)"))
}

// LogValue emits only a constant marker.
func (EmailVerifyRecovery) LogValue() slog.Value {
	return slog.StringValue("otp.EmailVerifyRecovery(redacted)")
}

// MarshalJSON rejects implicit recovery export.
func (EmailVerifyRecovery) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit recovery export.
func (EmailVerifyRecovery) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts caller, possession and original recovery correlation.
func (EmailVerifyRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailVerifyRecoveryRequest(redacted)"))
}

// MarshalJSON rejects implicit recovery-request export.
func (EmailVerifyRecoveryRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit recovery-request export.
func (EmailVerifyRecoveryRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts private result projections and correlation.
func (EmailVerifyResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailVerifyResult(redacted)"))
}

// MarshalJSON rejects implicit result export.
func (EmailVerifyResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit result export.
func (EmailVerifyResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
