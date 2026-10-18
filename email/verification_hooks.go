package email

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// VerificationHooksConfig selects cooperative callback budgets and registered
// non-secret reason codes. The configuration is copied. Change the enclosing
// native ConfigurationID when callback semantics change; retain original
// configurations for their existing command recovery.
type VerificationHooksConfig struct {
	MaximumDuration time.Duration
	Reasons         []identity.PolicyReason
}

// VerificationHooks is optional immutable link-confirmation callback policy.
// It borrows concurrency-safe hooks and owns no resources or transaction. It
// discloses only command/user/identifier correlation, never an address, proof,
// password or execution authority. Every field is read-only: verification
// enrichment is forbidden. Nil means disabled only in selecting adapters;
// invoking a nil or zero selection directly is invalid.
type VerificationHooks struct{ runner *identity.HookRunner }

// NewVerificationHooks fixes safe metadata for original-signup and managed
// pending-address link confirmation. It selects neither OTP nor email change.
// Before must run before reservation outside SQL, and After only after a fresh
// known committed result and transaction closure. Adapters must never invoke
// these callbacks for scanner validation, replay, recovery, rollback or unknown
// outcomes. These methods validate shape, not that transaction placement.
func NewVerificationHooks(hooks []identity.Hook, config VerificationHooksConfig) (*VerificationHooks, error) {
	runner, err := identity.NewHookRunner(hooks, identity.HookRunnerConfig{
		MaximumDuration: config.MaximumDuration,
		Reasons:         config.Reasons,
		Fields: []identity.HookFieldRegistration{
			{Name: "command_id", Kind: identity.AttributeString, Sensitivity: identity.SensitivitySensitive},
			{Name: "user_id", Kind: identity.AttributeString, Sensitivity: identity.SensitivitySensitive},
			{Name: "identifier_id", Kind: identity.AttributeString, Sensitivity: identity.SensitivitySensitive},
		},
	})
	if err != nil {
		return nil, err
	}
	return &VerificationHooks{runner: runner}, nil
}

func (h *VerificationHooks) operation(ctx context.Context, b identity.CommandBinding) (identity.OperationContext, error) {
	if h == nil || h.runner == nil || ctx == nil {
		return identity.OperationContext{}, ErrInvalidVerification
	}
	switch b.SchemaID {
	case "identity.email.verification-confirm.native-v1", "identity.email.verification-confirm.managed-v1":
	default:
		return identity.OperationContext{}, ErrInvalidVerification
	}
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if b.ValidateFor(op) != nil {
		return identity.OperationContext{}, ErrInvalidVerification
	}
	deadline, _ := ctx.Deadline()
	return identity.OperationContext{OperationID: b.OperationID, TenantID: b.TenantID, ActorID: b.ActorID, CorrelationID: b.CorrelationID, Deadline: deadline}, nil
}

// Before runs ordered pretransaction policy, preserving the caller's original
// execution deadline. Explicit rejection is ForbiddenError; malformed callback
// output, errors and panics fail closed with redacted errors. Callbacks must
// cooperate with cancellation; no goroutine is detached to preempt them.
func (h *VerificationHooks) Before(ctx context.Context, b identity.CommandBinding) error {
	op, err := h.operation(ctx, b)
	if err != nil {
		return err
	}
	fields := []identity.HookField{
		{Name: "command_id", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: string(b.CommandID)}, Sensitivity: identity.SensitivitySensitive},
		{Name: "user_id", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: string(b.UserID)}, Sensitivity: identity.SensitivitySensitive},
		{Name: "identifier_id", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: b.RecordID}, Sensitivity: identity.SensitivitySensitive},
	}
	result, err := h.runner.Before(ctx, identity.BeforeHookInput{Context: op, Fields: fields})
	if err != nil {
		return err
	}
	if result.Decision != identity.BeforeHookContinue {
		return identity.ForbiddenError{}
	}
	return nil
}

// After reports a fresh known commit outside SQL. Its error cannot undo that
// commit: native callers must preserve outcome/recovery, withhold subsequent
// confidential projections/signin and never retry observation through replay.
// Use the durable outbox rather than this callback for reliable external work.
func (h *VerificationHooks) After(ctx context.Context, b identity.CommandBinding) error {
	op, err := h.operation(ctx, b)
	if err != nil {
		return err
	}
	return h.runner.After(ctx, identity.AfterHookInput{Context: op, Observation: identity.HookObservation{Outcome: identity.AttemptedCommitOutcomeCommitted, Notes: []identity.PolicyReason{}}})
}
