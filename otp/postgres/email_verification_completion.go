package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// EmailVerify submits a new server-issued logical attempt, not a client-selected
// attempt identity. The existing OTP owner meters wrong codes and reserves correct
// ones. Kernel identifier CAS, OTP finalization, protected audit, lifecycle and
// command receipt commit together. No session, primary swap or sender is invoked.
// Unknown retains original code-free Recovery; use RecoverEmailVerify rather than
// submitting another attempt. Earlier cancellation wins; observed commit remains
// committed even if subsequent projection/disclosure fails.
func (s *EmailVerificationService) EmailVerify(ctx context.Context, r otp.EmailVerifyRequest) (out otp.EmailVerifyResult, err error) {
	if ctx == nil || s == nil || s.sender == nil || s.coordinator == nil {
		return out, ErrInvalidCommand
	}
	if err := r.Validate(); err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, s.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			out.Address, err = identity.IdentifierProjection{}, ErrUnavailable
		}
		if ctx.Err() != nil {
			out.Address, err = identity.IdentifierProjection{}, ctx.Err()
		}
	}()
	original, custody, flow, err := s.source.restoreSource(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, r.SendCommandID)
	if err != nil {
		return out, err
	}
	spec, _ := original.Feature()
	issued, err := custody.challenge.Bindings()
	if err != nil || custody.recipient == nil {
		return out, identity.ForbiddenError{}
	}
	scope, err := issued.Continuation.Bindings()
	if err != nil || scope.Scope.Purpose != otp.PurposeEmailVerification || scope.Scope.Channel != otp.ChannelEmail || scope.Scope.ChallengeID != string(r.SendCommandID) {
		return out, identity.ForbiddenError{}
	}
	target, err := otp.ParseEmailVerificationTarget(scope.Scope.TargetID)
	if err != nil {
		return out, err
	}
	selected, _ := target.Bindings()
	if custody.recipient.Identifier.ID != selected.IdentifierID || custody.recipient.Identifier.Version != selected.IdentifierVersion || custody.recipient.Verification.Version != selected.VerificationVersion || custody.recipient.Identifier.Verified || custody.recipient.Identifier.Primary {
		return out, identity.ForbiddenError{}
	}
	if err := s.source.requireCurrent(ctx, spec.Binding, custody.authority, flow); err != nil {
		return out, err
	}
	digestScope, _ := issued.Continuation.DigestScope()
	digest, err := s.owner.codec.verifier.ScopeDigest(digestScope, issued.Digest.KeyVersion)
	if err != nil {
		return out, ErrInvalidCommand
	}
	var encodedVersion string
	schema := pgx.Identifier{s.owner.schema}.Sanitize()
	if err := s.sender.pool.Raw().QueryRow(ctx, `SELECT version::text FROM `+schema+`.challenges WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4`, string(r.TenantID), string(r.SendCommandID), int64(issued.Digest.KeyVersion), digest.Value[:]).Scan(&encodedVersion); err != nil {
		return out, custodyFailure(ctx)
	}
	version, err := strconv.ParseUint(encodedVersion, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != encodedVersion {
		return out, ErrUnavailable
	}
	spec.Operation = emailVerificationOperation()
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.SchemaVersion = spec.Operation.OperationID, spec.Operation.SchemaID, spec.Operation.SchemaVersion
	spec.Binding.RecordID = string(selected.IdentifierID)
	spec.Binding.CommandID, err = identity.NewCommandID()
	if err != nil {
		return out, ErrUnavailable
	}
	spec.Binding.CorrelationID = string(spec.Binding.CommandID)
	out.CommandID = spec.Binding.CommandID
	i := kernel.ManagedEmailVerificationIntent{Change: identity.IdentifierChange{TenantID: r.TenantID, UserID: r.UserID, ID: selected.IdentifierID, Action: identity.IdentifierVerify, ExpectedUserVersion: custody.recipient.User.Version, ExpectedAuthorityVersion: custody.authority.IdentifierAuthorityVersion, ExpectedIdentifierVersion: selected.IdentifierVersion, ExpectedVerificationVersion: selected.VerificationVersion}, CanonicalAddress: scope.Scope.Destination.Value(), ComparisonProfile: s.profile.comparison, RequestCommandID: r.SendCommandID}
	spec.Fields, err = kernel.OTPEmailVerificationFields(i, r.SendCommandID)
	if err != nil {
		return out, err
	}
	query := checkQuery(spec.Binding, spec.Binding.CommandID, spec.Operation.OperationID, false)
	query.RecordID = spec.Binding.RecordID
	caller := s.source.planCaller(r.Caller, query)
	admission, err := s.coordinator.ObserveCommandAdmission(ctx, query, caller)
	if err != nil || !admission.Absent {
		if err == nil {
			err = identity.ForbiddenError{}
		}
		return out, err
	}
	attempt, err := s.source.issuer.PrepareForCommand(ctx, spec.Binding, spec.Operation, issued.Continuation, otp.AttemptModeConsume, version, r.Code)
	if err != nil {
		return out, err
	}
	_, _, bearer, _ := r.Flow.Bindings()
	command, otpPlan, err := s.owner.codec.MapSessionWithAuthority(ctx, attempt, issued.Digest.KeyVersion, spec, bearer, custody.authority)
	if err != nil {
		return out, err
	}
	recovery, _ := attempt.Recovery()
	out.Recovery, err = otp.NewEmailVerifyRecovery(otp.CheckRecoveryBindings{SendCommandID: r.SendCommandID, Attempt: recovery, ExpectedVersion: version, DigestKeyVersion: otpPlan.DigestKeyVersion, ScopeDigest: otpPlan.ScopeDigest})
	if err != nil {
		return out, err
	}
	plan, err := s.completionPlan(command, otpPlan, selected.VerificationVersion)
	if err != nil {
		return out, err
	}
	plan, err = s.coordinator.PrepareOTPReservationPlan(spec.Binding, command, plan)
	if err != nil {
		return out, err
	}
	denial, err := s.coordinator.RecordOTPAttemptDenial(ctx, spec.Binding, command, plan)
	var conflict identity.ConflictError
	if denial.Outcome != identity.CommitOutcomeConflict || !errors.As(err, &conflict) {
		out.Outcome, out.RetryAfter = denial.Outcome, denial.RetryAfter
		return out, err
	}
	reserved, receipt, err := s.coordinator.ReserveOTPCommand(ctx, spec.Binding, command, plan)
	if err != nil || reserved == (kernel.Reservation{}) {
		out.Outcome, out.RetryAfter, out.Replayed = receipt.Outcome, receipt.RetryAfter, true
		return out, err
	}
	w, err := s.coordinator.Begin(ctx, reserved)
	if err != nil {
		out.Outcome = identity.CommitOutcomeUnknown
		return out, err
	}
	defer s.coordinator.Abort(w, identity.UnavailableError{})
	receipt, err = s.coordinator.ApplyFeature(ctx, w, command)
	if err == nil {
		receipt, err = s.coordinator.Commit(w, receipt)
	} else {
		receipt, err = s.coordinator.Abort(w, err)
	}
	out.Outcome, out.RetryAfter = receipt.Outcome, receipt.RetryAfter
	if err == nil && out.Outcome == identity.CommitOutcomeCommitted {
		out.Address, err = s.committedAddress(ctx, i)
	}
	return out, err
}

func (s *EmailVerificationService) committedAddress(ctx context.Context, original kernel.ManagedEmailVerificationIntent) (identity.IdentifierProjection, error) {
	i := original.Change
	state, err := s.profile.repository.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: i.TenantID, UserID: i.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return identity.IdentifierProjection{}, err
	}
	if state.User.Status != identity.StatusActive || state.User.Version != i.ExpectedUserVersion+1 || state.AuthorityVersion != i.ExpectedAuthorityVersion+1 {
		return identity.IdentifierProjection{}, identity.ForbiddenError{}
	}
	var now time.Time
	if err := s.sender.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return identity.IdentifierProjection{}, custodyFailure(ctx)
	}
	projection, err := identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: i.TenantID, UserID: i.UserID, IdentifierID: i.ID, State: state, Values: identity.IdentifierValuesOmitted, ObservedAt: now.UTC()})
	b, e := projection.Bindings()
	if err != nil || e != nil || !b.Verified || b.Primary || b.IdentifierVersion != i.ExpectedIdentifierVersion+1 || b.VerificationVersion != i.ExpectedVerificationVersion+1 {
		return identity.IdentifierProjection{}, identity.ForbiddenError{}
	}
	return projection, nil
}

func (s *EmailVerificationService) completionPlan(command identity.Command, attempt kernel.OTPAttemptPlan, before uint64) (kernel.CommandPlan, error) {
	spec, ok := command.Feature()
	if !ok || before == 0 || before == ^uint64(0) {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	b := spec.Binding
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	builder, err := audit.NewBuilder(audit.BuilderConfig{Clock: func() time.Time { return when }, IDGenerator: func() (string, error) { return "otp-email-binding", nil }})
	if err != nil {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: when, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "identifier", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "aggregate.type": "identifier", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(before, 10), "aggregate.after_version": strconv.FormatUint(before+1, 10), "retention.class": "protected", "authentication.recovery_path": otp.EmailVerificationRecoveryPath}})
	if err != nil {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, "identifier", record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	owner := s.owner.Descriptor()
	return kernel.CommandPlan{Contributors: s.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Operation: spec.Operation, Contributor: owner}, SubjectType: "identifier", OTP: &attempt, Lifecycle: &kernel.LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: before, AfterVersion: before + 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected"}}}, nil
}
