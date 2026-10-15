package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// CancelCommandRequest is trusted authenticated workflow input, not HTTP JSON
// or authority. Binding must exactly identify the target and cancel operation;
// ActorScope binds current policy. Freeze ExpectedStatusVersion and generation
// from VersionedStatusGet before first submission, retaining every field and
// CommandID unchanged on retry. Never reread fences to rewrite a pending command.
// Reason is 1..256 UTF-8 bytes; no credentials or PII. Only a keyed fingerprint
// persists. Caller must not mutate authorization attributes during the call.
type CancelCommandRequest struct {
	Binding               identity.CommandBinding
	ActorScope            authorization.DecisionContext
	ExpectedStatusVersion uint64
	Request               delivery.CancelRequest
}

// CancelOperation returns the fixed protected cancellation operation/schema
// used to construct a CommandBinding. The descriptor is not authority; callers
// must supply authenticated scope, a fresh command ID and original retry fences.
func CancelOperation() identity.FeatureOperation { return cancelOperation() }

func (CancelCommandRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.CancelCommandRequest(redacted)"))
}
func (CancelCommandRequest) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.CancelCommandRequest(redacted)")
}

// MarshalJSON rejects implicit sensitive workflow serialization.
func (CancelCommandRequest) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}

type cancelExecutor struct {
	coordinator *identitypostgres.Coordinator
	registry    *identitypostgres.ContributorRegistry
	native      *cancelContributor
}

// Cancel atomically records local stop, original-command outcome, protected
// audit and lifecycle. Requires Cancellation configuration. Current exact policy
// applies before reservation and historical disclosure; IDs grant no authority.
// Concurrent calls use original kernel command identity and version/generation
// fences. Exact committed replay returns the original result, not current status.
// Provider cancellation is not invoked: prior sends remain outcome-unknown.
// ErrOutcomeUnknown includes a live pending command and requires an exact retry;
// another command. Earlier caller deadline wins over the whole-call timeout.
// This authenticated operation does not yet implement the complete core Queue.
func (s *EnqueueService) Cancel(ctx context.Context, r CancelCommandRequest) (delivery.CancelResult, error) {
	if err := s.startupCheck(ctx); err != nil {
		return delivery.CancelResult{}, err
	}
	if ctx == nil || s == nil || s.executor == nil || s.keyed == nil || s.keyed.pool == nil || s.cancellation == nil || r.Binding.ValidateFor(cancelOperation()) != nil || r.Binding.TenantID != identity.TenantID(r.Request.TenantID) || r.Binding.RecordID != string(r.Request.IntentID) || validateCancellation(r.Request, string(r.Binding.UserID)) != nil || r.ExpectedStatusVersion == 0 || r.ExpectedStatusVersion == ^uint64(0) {
		return delivery.CancelResult{}, delivery.ErrInvalidInput
	}
	w, stop := context.WithTimeout(ctx, s.executor.timeout)
	defer stop()
	if err := w.Err(); err != nil {
		return delivery.CancelResult{}, err
	}
	caller, err := cancellationScope(r.ActorScope, r.Request.IntentID)
	if err != nil {
		return delivery.CancelResult{}, err
	}
	if err := s.executor.allow(w, r.Binding, caller); err != nil {
		return delivery.CancelResult{}, err
	}
	reason := cancellationReason(s.keyed.key, r)
	command, err := newCancellationCommand(r.Binding, r.Request.ExpectedGeneration, r.ExpectedStatusVersion, reason)
	if err != nil {
		return delivery.CancelResult{}, admissionError(err)
	}
	result, err := s.cancellation.execute(w, s.executor.retentionVersion, r.Binding, command, r.ExpectedStatusVersion)
	switch result.Outcome {
	case identity.CommitOutcomeUnknown:
		return delivery.CancelResult{}, delivery.ErrOutcomeUnknown
	case identity.CommitOutcomeInProgress:
		return delivery.CancelResult{}, delivery.ErrOutcomeUnknown
	case identity.CommitOutcomeConflict:
		return delivery.CancelResult{}, delivery.ErrConflict
	case identity.CommitOutcomeCommitted:
		if err != nil {
			return delivery.CancelResult{}, delivery.ErrOutcomeUnknown
		}
		// Recheck current policy before disclosing even a historical result.
		if err := s.executor.allow(w, r.Binding, caller); err != nil {
			return delivery.CancelResult{}, err
		}
		return s.cancellationResult(w, r)
	default:
		if err == nil {
			return delivery.CancelResult{}, delivery.ErrUnavailable
		}
		return delivery.CancelResult{}, admissionError(err)
	}
}

func cancellationScope(caller authorization.DecisionContext, intent delivery.IntentID) (authorization.DecisionContext, error) {
	for _, attrs := range []authorization.Attributes{caller.Request.Subject.Attributes, caller.Request.Resource.Attributes, caller.Request.Environment.Attributes, caller.Request.Attributes} {
		if len(attrs) > 128 {
			return authorization.DecisionContext{}, delivery.ErrInvalidInput
		}
		for name := range attrs {
			if len(name) > 128 || strings.HasPrefix(string(name), "delivery.") {
				return authorization.DecisionContext{}, delivery.ErrInvalidInput
			}
		}
	}
	attrs := make(authorization.Attributes, len(caller.Request.Resource.Attributes)+1)
	for name, value := range caller.Request.Resource.Attributes {
		attrs[name] = value
	}
	attrs["delivery.intent"] = authorization.StringValue(string(intent))
	caller.Request.Resource.Attributes = attrs
	return caller, nil
}

func cancellationReason(key [32]byte, r CancelCommandRequest) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-delivery-cancel-reason-v1\x00"))
	scope := cancellationBindingDigest(r.Binding)
	_, _ = mac.Write(scope[:])
	var fences [12]byte
	binary.BigEndian.PutUint64(fences[:8], r.ExpectedStatusVersion)
	binary.BigEndian.PutUint32(fences[8:], r.Request.ExpectedGeneration)
	_, _ = mac.Write(fences[:])
	_, _ = mac.Write([]byte(r.Request.Reason))
	return [32]byte(mac.Sum(nil))
}

func (e *cancelExecutor) execute(ctx context.Context, retention uint64, b identity.CommandBinding, command identity.Command, version uint64) (identity.CommandResult, error) {
	digest, err := cancellationAuditDigest(b)
	if err != nil {
		return identity.CommandResult{}, delivery.ErrUnavailable
	}
	plan := identitypostgres.CommandPlan{Contributors: e.registry.Descriptors(), SubjectType: "delivery_intent", Feature: &identitypostgres.FeatureRegistration{Contributor: e.native.Descriptor(), Operation: cancelOperation()}, Audits: []identitypostgres.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: retention, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "delivery.cancelled.v1", BeforeVersion: version, AfterVersion: version + 1}}
	plan, err = e.coordinator.PrepareCommandPlan(b, command, plan)
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := e.coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil || reservation == (identitypostgres.Reservation{}) {
		return result, err
	}
	work, err := e.coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: cancelOperation()}}, err
	}
	defer e.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := e.coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		return e.coordinator.Abort(work, err)
	}
	return e.coordinator.Commit(work, provisional)
}

func (s *EnqueueService) cancellationResult(ctx context.Context, r CancelCommandRequest) (delivery.CancelResult, error) {
	id, _ := base64.RawURLEncoding.DecodeString(string(r.Binding.CommandID))
	var digest []byte
	var generation int64
	var before, after string
	var state int16
	var local bool
	err := s.keyed.pool.QueryRow(ctx, `SELECT binding_digest,generation,before_version::text,after_version::text,result_state,local_cancelled FROM identity.delivery_cancellations WHERE deployment=$1 AND tenant_id=$2 AND command_id=$3 AND effect_id=$4 AND subject_id=$5`, s.keyed.deployment, string(r.Binding.TenantID), id, r.Binding.RecordID, string(r.Binding.UserID)).Scan(&digest, &generation, &before, &after, &state, &local)
	if err != nil || len(digest) != 32 || [32]byte(digest) != cancellationBindingDigest(r.Binding) || generation != int64(r.Request.ExpectedGeneration) || before != strconv.FormatUint(r.ExpectedStatusVersion, 10) || after != strconv.FormatUint(r.ExpectedStatusVersion+1, 10) {
		return delivery.CancelResult{}, delivery.ErrOutcomeUnknown
	}
	out := delivery.CancelResult{State: delivery.DeliveryState(state), LocalCancelled: local}
	switch out.State {
	case delivery.StateDelivered, delivery.StateRejected, delivery.StateBounced, delivery.StateExpired, delivery.StateExhausted, delivery.StateSuperseded:
		if local {
			return delivery.CancelResult{}, delivery.ErrOutcomeUnknown
		}
	case delivery.StateCancelled, delivery.StateOutcomeUnknown:
	default:
		return delivery.CancelResult{}, delivery.ErrOutcomeUnknown
	}
	return out, nil
}
