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

// EmailChangeService independently issues new-address OTPs for genuine committed
// change requests, then coordinates consuming confirmation with primary swap,
// old-address notice, audit/lifecycle and session invalidation. It neither
// invents fresh-password admission nor accepts ordinary pending attachments.
// Contexts are bounded; calls preserve original custody on ambiguity. Unsupported
// factor/current-address/auto-signin profiles fail closed, never fall back.
type EmailChangeService interface {
	EmailChangeRequest(context.Context, EmailChangeRequest) (SendResult, error)
	EmailChangeConfirm(context.Context, EmailChangeConfirmRequest) (EmailChangeResult, error)
	RecoverEmailChange(context.Context, EmailChangeRecoveryRequest) (EmailChangeResult, error)
}

// EmailChangeRateSource exposes authenticated original correlation for transport
// subject, CSRF and rate admission, not mutation permission. Neither source call
// issues a code, charges an attempt or changes a directory record. Original
// times and source generations are immutable; current native admission remains
// mandatory. Implementations are cancellation-bounded and concurrent-safe.
type EmailChangeRateSource interface {
	EmailChangeSession(context.Context, identity.TenantID, SendFlow) (session.Session, error)
	EmailChangeSendDestination(context.Context, EmailChangeRequest) (DestinationInput, error)
	EmailChangeChallenge(context.Context, EmailChangeConfirmRequest) (EmailChangeChallenge, error)
}

// EmailChangeChallenge is private original change/send correlation for transport
// budgets. Lifetime is the issued interval, not a refreshed remaining TTL.
// It grants no code proof, replacement authority or public disclosure.
type EmailChangeChallenge struct {
	UserID   identity.UserID
	Target   EmailChangeTarget
	Lifetime time.Duration
}

// Format redacts subject and original change correlation.
func (EmailChangeChallenge) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailChangeChallenge(redacted)"))
}

// MarshalJSON rejects implicit original-custody export.
func (EmailChangeChallenge) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit original-custody export.
func (EmailChangeChallenge) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// EmailChangeRequest names the actual committed change request and candidate.
// The native owner reads the original mailbox, previous primary, generations,
// policy and validity; callers cannot supply or renew them. Flow is actual
// authenticated session possession. Caller/network/device are trusted transport
// context, not permission. Matching retry keys conserve the original issuance.
type EmailChangeRequest struct {
	TenantID        identity.TenantID
	UserID          identity.UserID
	OriginCommandID identity.CommandID
	AddressID       identity.IdentifierID
	Caller          authorization.DecisionContext
	Flow            SendFlow
	Network, Device string
	IdempotencyKey  identity.IdempotencyKey
}

// Validate checks bounded shape, not origin, possession, freshness or authority.
func (r EmailChangeRequest) Validate() error {
	if validateEmailVerificationScope(r.TenantID, r.UserID, r.Caller, r.Flow, "identity.otp.email-change-request") != nil || r.IdempotencyKey == (identity.IdempotencyKey{}) || !boundedText(r.Device, 128, false) || len(r.Network) > 128 {
		return ErrInvalidAttempt
	}
	if _, err := identity.ParseCommandID(string(r.OriginCommandID)); err != nil {
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

// EmailChangeConfirmRequest submits a new logical consuming attempt against the
// original Send. Only the native issuer selects attempt/command identities.
// After an ambiguous result use its original code-free recovery, not another
// submission. The code and flow are borrowed and must not be logged or mutated.
type EmailChangeConfirmRequest struct {
	TenantID      identity.TenantID
	UserID        identity.UserID
	Caller        authorization.DecisionContext
	Flow          SendFlow
	SendCommandID identity.CommandID
	Code          auth.OneTimeCode
}

// Validate checks scope; the native attempt owner validates opaque code custody.
func (r EmailChangeConfirmRequest) Validate() error {
	if _, err := identity.ParseCommandID(string(r.SendCommandID)); err != nil {
		return ErrInvalidAttempt
	}
	return validateEmailVerificationScope(r.TenantID, r.UserID, r.Caller, r.Flow, "identity.otp.email-change-confirm")
}

// EmailChangeRecovery is immutable code-free original correlation, distinct from
// verification-only recovery. It grants no mutation or disclosure permission.
// Zero denies; copies own no resources and support concurrent reads.
type EmailChangeRecovery struct{ original CheckRecovery }

// NewEmailChangeRecovery reuses the owned attempt-correlation validator without
// IO, renewal or authentication. Send and consuming command must be distinct.
func NewEmailChangeRecovery(b CheckRecoveryBindings) (EmailChangeRecovery, error) {
	if b.SendCommandID == b.Attempt.CommandID {
		return EmailChangeRecovery{}, ErrInvalidAttempt
	}
	original, err := NewCheckRecovery(b)
	if err != nil {
		return EmailChangeRecovery{}, err
	}
	return EmailChangeRecovery{original: original}, nil
}

// Bindings returns private scalar correlation, never current authority.
func (r EmailChangeRecovery) Bindings() (CheckRecoveryBindings, error) { return r.original.Bindings() }

// EmailChangeRecoveryRequest observes original metadata under current disclosure
// policy and original possession, including after this change invalidated its
// session. It cannot compare a code, debit, retry execution or renew custody.
type EmailChangeRecoveryRequest struct {
	TenantID identity.TenantID
	UserID   identity.UserID
	Caller   authorization.DecisionContext
	Flow     SendFlow
	Recovery EmailChangeRecovery
}

// Validate checks original correlation/tenant and bounded self-session shape.
func (r EmailChangeRecoveryRequest) Validate() error {
	b, err := r.Recovery.Bindings()
	if err != nil || b.Attempt.TenantID != r.TenantID {
		return ErrInvalidAttempt
	}
	return validateEmailVerificationScope(r.TenantID, r.UserID, r.Caller, r.Flow, "identity.otp.email-change-confirm.recover")
}

// EmailChangeResult preserves observed durability even if later disclosure
// fails. Address is present only for fresh successful primary replacement;
// replay/recovery return metadata only. No session, cookie or bearer is issued.
// Unknown retains original Recovery and must not be guessed to be rollback.
type EmailChangeResult struct {
	CommandID  identity.CommandID
	Outcome    identity.CommitOutcome
	Address    identity.IdentifierProjection
	Recovery   EmailChangeRecovery
	Replayed   bool
	RetryAfter time.Duration
}

// Format redacts the actual flow and original change correlation.
func (EmailChangeRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailChangeRequest(redacted)"))
}

// MarshalJSON rejects implicit custody export; HTTP owns a separate schema.
func (EmailChangeRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit custody/map-key export.
func (EmailChangeRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts submitted code, flow and command correlation.
func (EmailChangeConfirmRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailChangeConfirmRequest(redacted)"))
}

// MarshalJSON rejects implicit code-bearing export.
func (EmailChangeConfirmRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit code-bearing export.
func (EmailChangeConfirmRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts original private recovery identity.
func (EmailChangeRecovery) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailChangeRecovery(redacted)"))
}

// LogValue redacts original correlation from structured diagnostics.
func (EmailChangeRecovery) LogValue() slog.Value {
	return slog.StringValue("otp.EmailChangeRecovery(redacted)")
}

// MarshalJSON rejects implicit original-recovery export.
func (EmailChangeRecovery) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit original-recovery export.
func (EmailChangeRecovery) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts historical caller, flow and correlation.
func (EmailChangeRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailChangeRecoveryRequest(redacted)"))
}

// MarshalJSON rejects implicit historical-request export.
func (EmailChangeRecoveryRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit historical-request export.
func (EmailChangeRecoveryRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts private projections and command correlation.
func (EmailChangeResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailChangeResult(redacted)"))
}

// MarshalJSON rejects implicit projection/result export.
func (EmailChangeResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit projection/result export.
func (EmailChangeResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
