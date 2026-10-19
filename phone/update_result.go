package phone

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// ChangeService is separately selected verified-phone replacement. Sending
// preserves the old number; Update requires its own fresh action proof plus
// original new-number OTP possession. Current factors, independent recovery,
// risk, session/CSRF, collision/recycling and protected transaction effects are
// native-owner obligations. Ambiguous Update requires the unchanged original
// keyed request or code-free recovery, never another code or renewed proof.
// Historical results require current disclosure authority. Implementations must
// honor bounded contexts and support concurrent independent callers.
type ChangeService interface {
	SendChange(context.Context, ChangeRequest) (identity.CommandResult, error)
	Update(context.Context, UpdateRequest) (UpdateResult, error)
	RecoverUpdate(context.Context, UpdateRecoveryRequest) (UpdateResult, error)
}

// UpdateResult retains the original consuming command and code-free OTP
// correlation. Treat Result's pointer projections as immutable, as required by
// identity.CommandResult. A committed pending cascade is not completed cleanup
// or a new session. Replayed history cannot confer fresh authentication.
// Fields are an explicit correlation projection, not a logging/transport DTO.
type UpdateResult struct {
	Result   identity.CommandResult
	Recovery VerificationRecovery
	Replayed bool
}

// Validate checks structural receipt/attempt correlation, not authentication,
// current permission or SMS possession. Zero denies. Committed replacement must
// include the actual pending change-cascade admission from its protected Work.
func (r UpdateResult) Validate() error {
	b := r.Result.Binding
	if r.Result.Validate() != nil || validateVerificationResult(b, "identity.phone.update", r.Result.Outcome, r.Result.RetryAfter) != nil {
		return ErrInvalidChange
	}
	original, err := r.Recovery.Bindings()
	if err != nil || original.Attempt.TenantID != b.TenantID || original.Attempt.CommandID != b.CommandID {
		return ErrInvalidChange
	}
	if r.Result.Outcome == identity.CommitOutcomeCommitted && (r.Result.Feature == nil || r.Result.Cascade == nil || r.Result.Cascade.Kind != identity.IdentifierChangeCascade) {
		return ErrInvalidChange
	}
	return nil
}

// UpdateRecoveryRequest is opaque original session possession and code-free
// command correlation. Copies are immutable/concurrent-safe and own no IO or
// background resource. Native recovery authenticates original sending custody
// and current disclosure policy without renewing session/proof validity.
type UpdateRecoveryRequest struct {
	read func() UpdateRecoveryRequestSpec
}

// UpdateRecoveryRequestSpec explicitly projects sensitive original custody.
// Flow is the original authenticated session even after replacement invalidates
// its identifier epoch; it is not current permission. Recovery never carries a
// code or fresh action proof. CSRFToken is the current cookie synchronizer;
// bearer admission requires it absent. Do not log or implicitly serialize fields.
type UpdateRecoveryRequestSpec struct {
	TenantID  identity.TenantID
	UserID    identity.UserID
	Caller    authorization.DecisionContext
	Flow      otp.SendFlow
	Recovery  VerificationRecovery
	CSRFToken session.CSRFToken
}

// NewUpdateRecoveryRequest validates exact self/action/tenant structure before
// copying and cloning caller collections. It performs no IO or authorization.
func NewUpdateRecoveryRequest(spec UpdateRecoveryRequestSpec) (UpdateRecoveryRequest, error) {
	if err := spec.Validate(); err != nil {
		return UpdateRecoveryRequest{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return UpdateRecoveryRequest{read: func() UpdateRecoveryRequestSpec { return spec }}, nil
}

// Bindings reveals explicit original input with independent caller collections.
// This projection cannot renew validity or authorize history disclosure.
func (r UpdateRecoveryRequest) Bindings() (UpdateRecoveryRequestSpec, error) {
	if r.read == nil {
		return UpdateRecoveryRequestSpec{}, ErrInvalidChange
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return UpdateRecoveryRequestSpec{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return spec, nil
}

// Validate rejects malformed or substituted historical correlation, without IO.
func (r UpdateRecoveryRequestSpec) Validate() error {
	b, err := r.Recovery.Bindings()
	if err != nil || b.Attempt.TenantID != r.TenantID || validateVerificationFlow(r.TenantID, r.UserID, r.Caller, r.Flow, "identity.phone.update.recover") != nil || r.Caller.Request.Resource.Type != "identity.user" || r.Caller.Request.Resource.ID != authorization.ResourceID(r.UserID) {
		return ErrInvalidChange
	}
	return nil
}

// Format redacts correlated historical metadata.
func (UpdateResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.UpdateResult(redacted)"))
}

// MarshalJSON denies implicit correlated-history export.
func (UpdateResult) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit correlated-history export.
func (UpdateResult) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue returns only a fixed marker.
func (UpdateResult) LogValue() slog.Value { return slog.StringValue("phone.UpdateResult(redacted)") }

// Format redacts original session and historical correlation.
func (UpdateRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.UpdateRecoveryRequest(redacted)"))
}

// MarshalJSON denies implicit original-custody export.
func (UpdateRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit original-custody export.
func (UpdateRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue returns only a fixed marker.
func (UpdateRecoveryRequest) LogValue() slog.Value {
	return slog.StringValue("phone.UpdateRecoveryRequest(redacted)")
}

// Format redacts ordinary explicit projections; enclosed fields remain sensitive.
func (UpdateRecoveryRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.UpdateRecoveryRequestSpec(redacted)"))
}

// MarshalJSON denies implicit original-custody export.
func (UpdateRecoveryRequestSpec) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit original-custody export.
func (UpdateRecoveryRequestSpec) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }
