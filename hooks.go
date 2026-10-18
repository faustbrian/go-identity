package identity

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"
)

// OperationContext is immutable operation correlation, never authentication or
// transaction authority. Deadline, when present, is the original exclusive
// execution bound; hook execution may narrow but never extend that instant.
type OperationContext struct {
	OperationID   string
	TenantID      TenantID
	ActorID       ActorID
	CorrelationID string
	Deadline      time.Time
}

// Hook supplies cooperative, bounded, concurrency-safe application callbacks.
// Before runs outside transactions and must not perform durable side effects:
// concurrent attempts may call it before the sole reservation selects a winner.
// After runs after transaction closure; its failure cannot undo committed work.
// Neither phase receives a store, transaction, proof or continuation authority.
// Use the durable outbox, not these callbacks, for retryable external effects.
type Hook interface {
	Before(context.Context, BeforeHookInput) (BeforeHookResult, error)
	After(context.Context, AfterHookInput) error
}

// HookField is one registered bounded scalar. Credentials are forbidden even
// when marked secret. Diagnostic formatting deliberately hides every value.
type HookField struct {
	Name        string
	Value       AttributeScalar
	Sensitivity Sensitivity
}

// BeforeHookInput contains owned metadata copies and the immutable operation.
type BeforeHookInput struct {
	Context OperationContext
	Fields  []HookField
}

// BeforeHookDecision is a closed explicit decision; zero is invalid.
type BeforeHookDecision string

const (
	BeforeHookContinue BeforeHookDecision = "continue"
	BeforeHookReject   BeforeHookDecision = "reject"
)

// HookEnrichment replaces or adds registered writable metadata only. It never
// changes OperationContext or grants permission to modify protected authority.
type HookEnrichment struct{ Fields []HookField }

// BeforeHookResult is the ordered validated decision. Reject discards earlier
// enrichments; Reasons contain only registered non-secret diagnostic codes.
type BeforeHookResult struct {
	Decision    BeforeHookDecision
	Enrichments []HookEnrichment
	Reasons     []PolicyReason
}

// AttemptedCommitOutcome distinguishes attempt observation from durable results.
// Unknown conserves uncertainty and must never be interpreted as rollback.
type AttemptedCommitOutcome string

const (
	AttemptedCommitOutcomeAttempted    AttemptedCommitOutcome = "attempted"
	AttemptedCommitOutcomeNotCommitted AttemptedCommitOutcome = "not-committed"
	AttemptedCommitOutcomeCommitted    AttemptedCommitOutcome = "committed"
	AttemptedCommitOutcomeUnknown      AttemptedCommitOutcome = "unknown"
)

// HookObservation is safe outcome metadata after transaction closure. Notes
// are registered codes, never user values, credentials or replay payloads.
// Notes must be non-nil; an explicit empty collection observes no extra notes.
type HookObservation struct {
	Outcome AttemptedCommitOutcome
	Notes   []PolicyReason
}

// AfterHookInput contains the original operation and an owned outcome copy.
type AfterHookInput struct {
	Context     OperationContext
	Observation HookObservation
}

// HookFieldRegistration fixes one scalar's kind/classification and whether
// before hooks may enrich it. Core reserved fields cannot be writable. Domain
// adapters must register only metadata safe for their selected workflow.
type HookFieldRegistration struct {
	Name        string
	Kind        AttributeKind
	Sensitivity Sensitivity
	Enrichment  bool
}

// HookRunnerConfig is copied immutable composition: at most64 fields and32
// unique reason codes, and a positive maximum duration no greater than1 minute.
// Secret fields and lists are unavailable. Hooks must honor context deadlines;
// execution is synchronous, with no goroutine attempting forced preemption.
type HookRunnerConfig struct {
	Fields          []HookFieldRegistration
	Reasons         []PolicyReason
	MaximumDuration time.Duration
}

// HookRunner runs1..64 callbacks in registration order, stopping at the first
// rejection/failure. One shared bounded budget covers the complete phase.
// Callback-context reentry into any HookRunner is rejected, including After.
// Dependencies are borrowed and must be concurrency-safe; the runner owns no
// lock, goroutine or resource lifetime. Zero/nil runners are invalid.
type HookRunner struct {
	hooks  []Hook
	config HookRunnerConfig
}
type hookInvocationKey struct{}

// NewHookRunner validates and copies ordered callbacks and field/reason policy.
// No callback, IO, transaction or provider runs during construction.
func NewHookRunner(hooks []Hook, config HookRunnerConfig) (*HookRunner, error) {
	invalid := InvalidInputError{Field: "hooks"}
	if len(hooks) < 1 || len(hooks) > 64 || len(config.Fields) > 64 || len(config.Reasons) > 32 || config.MaximumDuration <= 0 || config.MaximumDuration > time.Minute {
		return nil, invalid
	}
	for _, h := range hooks {
		if nilDependency(h) {
			return nil, invalid
		}
	}
	for i, f := range config.Fields {
		if !validFieldName(f.Name) || !validSensitivity(f.Sensitivity) || f.Sensitivity == SensitivitySecret || f.Enrichment && reservedFieldName(f.Name) {
			return nil, invalid
		}
		switch f.Kind {
		case AttributeString, AttributeBool, AttributeInt64, AttributeTime:
		default:
			return nil, invalid
		}
		for _, prior := range config.Fields[:i] {
			if prior.Name == f.Name {
				return nil, invalid
			}
		}
	}
	for i, r := range config.Reasons {
		if !validPolicyText(string(r), 64) || slices.Contains(config.Reasons[:i], r) {
			return nil, invalid
		}
	}
	config.Fields = slices.Clone(config.Fields)
	config.Reasons = slices.Clone(config.Reasons)
	return &HookRunner{hooks: slices.Clone(hooks), config: config}, nil
}

func validHookContext(c OperationContext) bool {
	return validDirectoryID(c.OperationID) && validDirectoryID(string(c.TenantID)) && validDirectoryID(c.CorrelationID) && (c.ActorID == "" || validDirectoryID(string(c.ActorID)))
}
func (r *HookRunner) reasons(reasons []PolicyReason) bool {
	if len(reasons) > 32 {
		return false
	}
	for i, v := range reasons {
		if !slices.Contains(r.config.Reasons, v) || slices.Contains(reasons[:i], v) {
			return false
		}
	}
	return true
}
func (r *HookRunner) field(f HookField, enrich bool) bool {
	if _, ok := scalarSize(f.Value); !ok {
		return false
	}
	for _, p := range r.config.Fields {
		if p.Name == f.Name {
			return p.Kind == f.Value.Kind && p.Sensitivity == f.Sensitivity && (!enrich || p.Enrichment)
		}
	}
	return false
}
func cloneHookFields(fields []HookField) []HookField {
	fields = slices.Clone(fields)
	for i := range fields {
		fields[i].Value = utcScalar(fields[i].Value)
	}
	return fields
}
func hookContextError(ctx context.Context, deadline time.Time) error {
	if err := readContextError(ctx); err != nil {
		return err
	}
	// Context timer delivery can lag the exclusive deadline. A returned callback
	// must not publish success or enter the next hook during that scheduling gap.
	if !time.Now().Before(deadline) {
		return DeadlineExceededError{}
	}
	return nil
}

// Before invokes ordered hooks with independent metadata copies. Enrichments
// must match registration and may write each field at most once across a phase;
// at most64 total fields/enrichments and32 registered reasons are retained.
// The returned data is not applied to domain records or authorization by this
// runner: that remains the selected adapter's explicit pretransaction policy.
func (r *HookRunner) Before(ctx context.Context, in BeforeHookInput) (BeforeHookResult, error) {
	if r == nil || ctx == nil || ctx.Value(hookInvocationKey{}) != nil || !validHookContext(in.Context) || len(in.Fields) < 1 || len(in.Fields) > 64 {
		return BeforeHookResult{}, InvalidInputError{Field: "hook_input"}
	}
	for i, f := range in.Fields {
		if !r.field(f, false) {
			return BeforeHookResult{}, InvalidInputError{Field: "hook_input"}
		}
		for _, prior := range in.Fields[:i] {
			if prior.Name == f.Name {
				return BeforeHookResult{}, InvalidInputError{Field: "hook_input"}
			}
		}
	}
	var effective time.Time
	out, err := callPolicy(ctx, r.config.MaximumDuration, in.Context.Deadline, func(ctx context.Context, deadline time.Time) (BeforeHookResult, error) {
		effective = deadline
		ctx = context.WithValue(ctx, hookInvocationKey{}, true)
		fields := cloneHookFields(in.Fields)
		result := BeforeHookResult{Decision: BeforeHookContinue}
		written := make(map[string]bool)
		for _, h := range r.hooks {
			if err := hookContextError(ctx, deadline); err != nil {
				return BeforeHookResult{}, err
			}
			x, err := h.Before(ctx, BeforeHookInput{Context: in.Context, Fields: cloneHookFields(fields)})
			if err != nil {
				return BeforeHookResult{}, err
			}
			if err := hookContextError(ctx, deadline); err != nil {
				return BeforeHookResult{}, err
			}
			if (x.Decision != BeforeHookContinue && x.Decision != BeforeHookReject) || !r.reasons(x.Reasons) || len(x.Enrichments) > 64 {
				return BeforeHookResult{}, UnavailableError{}
			}
			for _, reason := range x.Reasons {
				if !slices.Contains(result.Reasons, reason) {
					result.Reasons = append(result.Reasons, reason)
				}
			}
			if x.Decision == BeforeHookReject {
				if len(x.Enrichments) != 0 {
					return BeforeHookResult{}, UnavailableError{}
				}
				return BeforeHookResult{Decision: BeforeHookReject, Reasons: result.Reasons}, nil
			}
			if len(result.Enrichments)+len(x.Enrichments) > 64 {
				return BeforeHookResult{}, UnavailableError{}
			}
			for _, enrichment := range x.Enrichments {
				if len(enrichment.Fields) > 32 {
					return BeforeHookResult{}, UnavailableError{}
				}
				for _, field := range enrichment.Fields {
					if !r.field(field, true) || written[field.Name] {
						return BeforeHookResult{}, UnavailableError{}
					}
					written[field.Name] = true
					idx := slices.IndexFunc(fields, func(x HookField) bool { return x.Name == field.Name })
					field.Value = utcScalar(field.Value)
					if idx >= 0 {
						fields[idx] = field
					} else {
						if len(fields) >= 64 {
							return BeforeHookResult{}, UnavailableError{}
						}
						fields = append(fields, field)
					}
				}
				result.Enrichments = append(result.Enrichments, HookEnrichment{Fields: cloneHookFields(enrichment.Fields)})
			}
		}
		return result, nil
	}, func(out BeforeHookResult) (BeforeHookResult, bool) { return out, true })
	if !effective.IsZero() && !time.Now().Before(effective) {
		return BeforeHookResult{}, DeadlineExceededError{}
	}
	return out, err
}

// After observes an already closed transaction and stops on the first error.
// Errors/panics are redacted, not translated to rollback. The workflow must
// conserve its original known result even if this returns an error. There is
// no automatic retry, exactly-once external-effect claim or replay observation.
func (r *HookRunner) After(ctx context.Context, in AfterHookInput) error {
	if r == nil || ctx == nil || ctx.Value(hookInvocationKey{}) != nil || !validHookContext(in.Context) || in.Observation.Notes == nil || !r.reasons(in.Observation.Notes) {
		return InvalidInputError{Field: "hook_input"}
	}
	switch in.Observation.Outcome {
	case AttemptedCommitOutcomeCommitted, AttemptedCommitOutcomeNotCommitted, AttemptedCommitOutcomeUnknown:
	default:
		return InvalidInputError{Field: "hook_input"}
	}
	var effective time.Time
	_, err := callPolicy(ctx, r.config.MaximumDuration, in.Context.Deadline, func(ctx context.Context, deadline time.Time) (bool, error) {
		effective = deadline
		ctx = context.WithValue(ctx, hookInvocationKey{}, true)
		for _, h := range r.hooks {
			if err := hookContextError(ctx, deadline); err != nil {
				return false, err
			}
			x := in
			x.Observation.Notes = slices.Clone(in.Observation.Notes)
			if err := h.After(ctx, x); err != nil {
				return false, err
			}
			if err := hookContextError(ctx, deadline); err != nil {
				return false, err
			}
		}
		return true, nil
	}, func(out bool) (bool, bool) { return out, true })
	if !effective.IsZero() && !time.Now().Before(effective) {
		return DeadlineExceededError{}
	}
	return err
}

// Format suppresses callback metadata in diagnostics, including sensitive IDs.
func (HookField) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.HookField(redacted)")
}

// Format suppresses callback metadata in diagnostics.
func (BeforeHookInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.BeforeHookInput(redacted)")
}

// Format suppresses enriched metadata in diagnostics.
func (BeforeHookResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.BeforeHookResult(redacted)")
}

// Format suppresses callback metadata in diagnostics.
func (AfterHookInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.AfterHookInput(redacted)")
}
