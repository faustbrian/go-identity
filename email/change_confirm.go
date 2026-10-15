package email

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// ChangeConfirmRequest is explicit new-address confirmation with the same
// bounded proof/callback/trusted transport fields as VerificationConfirmRequest.
// It selects change-confirm, never a verification-only or auto-signin profile.
type ChangeConfirmRequest VerificationConfirmRequest

// Validate checks only structure and exact caller action, not current authority.
func (r ChangeConfirmRequest) Validate() error {
	return VerificationConfirmRequest(r).validate("identity.email.change-confirm")
}

// ChangeRecovery retains exact original change-command correlation, not proof
// or permission. Copies own no resources; each observation needs current policy.
type ChangeRecovery struct{ state *verificationRecoveryState }

// NewChangeRecovery copies bounded change-confirm scope without IO or authority.
func NewChangeRecovery(q identity.RecoveryQuery) (ChangeRecovery, error) {
	r, err := newEmailRecovery(q, "identity.email.change-confirm")
	return ChangeRecovery{state: r.state}, err
}

// Bindings explicitly returns sensitive correlation. Zero denies.
func (r ChangeRecovery) Bindings() (identity.RecoveryQuery, error) {
	if r.state == nil {
		return identity.RecoveryQuery{}, ErrInvalidVerification
	}
	return r.state.read(), nil
}

// ChangeConfirmResult preserves an observed durable outcome even if disclosure
// subsequently fails. Fresh committed success returns the verified primary;
// replay/failure return no address. No session or cookie is issued by this policy.
type ChangeConfirmResult struct {
	Outcome    identity.CommitOutcome
	Address    identity.IdentifierProjection
	Recovery   ChangeRecovery
	Replayed   bool
	RetryAfter time.Duration
}

// Validate checks metadata/disclosure shape, not authorization or durability.
func (r ChangeConfirmResult) Validate() error {
	q, err := r.Recovery.Bindings()
	if err != nil || !verificationOutcome(r.Outcome, r.RetryAfter) {
		return ErrInvalidVerification
	}
	if r.Address != (identity.IdentifierProjection{}) {
		b, e := r.Address.Bindings()
		if e != nil || r.Outcome != identity.CommitOutcomeCommitted || r.Replayed || b.TenantID != q.TenantID || b.UserID != q.UserID || string(b.IdentifierID) != q.RecordID || b.Kind != identity.IdentifierEmail || b.Status != identity.StatusActive || !b.Primary || !b.Verified || b.VerificationState != identity.VerificationVerified {
			return ErrInvalidVerification
		}
	}
	return nil
}

// ChangeRecoveryRequest selects original correlation and trusted current caller.
type ChangeRecoveryRequest struct {
	Recovery ChangeRecovery
	Caller   authorization.DecisionContext
}

// Validate checks exact caller/tenant/original actor, not current permission.
func (r ChangeRecoveryRequest) Validate() error {
	q, err := r.Recovery.Bindings()
	if err != nil || validateEmailCaller(q.TenantID, r.Caller, "identity.email.change-confirm") != nil || string(r.Caller.Request.Subject.ID) != string(q.ActorID) || r.Caller.Request.Subject.Kind != q.ActorKind || r.Caller.Request.Resource.ID != "" && string(r.Caller.Request.Resource.ID) != string(q.UserID) {
		return ErrInvalidVerification
	}
	return nil
}

// ChangeRecoveryResult is historical metadata only; it cannot repeat a mutation,
// send another notice or issue authentication.
type ChangeRecoveryResult struct {
	Outcome    identity.CommitOutcome
	Recovery   ChangeRecovery
	RetryAfter time.Duration
}

// Validate requires an observed closed outcome and exact original correlation.
func (r ChangeRecoveryResult) Validate() error {
	if _, err := r.Recovery.Bindings(); err != nil || !verificationOutcome(r.Outcome, r.RetryAfter) {
		return ErrInvalidVerification
	}
	return nil
}

// ChangeConfirmationService implements the selected delivered-link change
// lifecycle. Current authority, one-use mutation, old notice and required
// session effects belong to its single protected transaction; recovery only
// observes original history under current authorization. Calls are bounded.
type ChangeConfirmationService interface {
	ChangeConfirm(context.Context, ChangeConfirmRequest) (ChangeConfirmResult, error)
	ChangeRecover(context.Context, ChangeRecoveryRequest) (ChangeRecoveryResult, error)
}

// Format redacts proof, mailbox and caller correlation.
func (ChangeConfirmRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.ChangeConfirmRequest(redacted)")
}

// MarshalJSON denies implicit sensitive request export.
func (ChangeConfirmRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit sensitive request export.
func (ChangeConfirmRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured diagnostics.
func (ChangeConfirmRequest) LogValue() slog.Value {
	return slog.StringValue("email.ChangeConfirmRequest(redacted)")
}

// Format redacts outcome and mailbox correlation.
func (ChangeConfirmResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.ChangeConfirmResult(redacted)")
}

// MarshalJSON denies implicit sensitive receipt export.
func (ChangeConfirmResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit sensitive receipt export.
func (ChangeConfirmResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured diagnostics.
func (ChangeConfirmResult) LogValue() slog.Value {
	return slog.StringValue("email.ChangeConfirmResult(redacted)")
}

// Format redacts original correlation.
func (ChangeRecovery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.ChangeRecovery(redacted)")
}

// MarshalJSON denies implicit original-correlation export.
func (ChangeRecovery) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit original-correlation export.
func (ChangeRecovery) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured diagnostics.
func (ChangeRecovery) LogValue() slog.Value {
	return slog.StringValue("email.ChangeRecovery(redacted)")
}

// Format redacts original correlation and caller.
func (ChangeRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.ChangeRecoveryRequest(redacted)")
}

// MarshalJSON denies implicit sensitive request export.
func (ChangeRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit sensitive request export.
func (ChangeRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured diagnostics.
func (ChangeRecoveryRequest) LogValue() slog.Value {
	return slog.StringValue("email.ChangeRecoveryRequest(redacted)")
}

// Format redacts recovery correlation.
func (ChangeRecoveryResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.ChangeRecoveryResult(redacted)")
}

// MarshalJSON denies implicit original-correlation export.
func (ChangeRecoveryResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit original-correlation export.
func (ChangeRecoveryResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured diagnostics.
func (ChangeRecoveryResult) LogValue() slog.Value {
	return slog.StringValue("email.ChangeRecoveryResult(redacted)")
}
