package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// CaptchaExecutorConfig selects exact trusted server-resolved flow context and
// verified caller composition. Flow is not client input or authentication proof;
// the server must authenticate its session/actor/pre-auth context. Admission and
// recovery policies must check current authority and receive the immutable flow
// as identity.captcha.* request attributes on every uncached primary lookup.
// Executor owns only composition, not caller pool/effect lifetimes. Empty is
// invalid; selected Repository.CaptchaCustody is required. Construction does no IO.
type CaptchaExecutorConfig struct {
	Executor ExecutorConfig
	Flow     risk.FlowContextInput
}

// CaptchaExecutor owns CAPTCHA issuance and original encrypted-response recovery
// through the sole identity coordinator. It is safe for concurrent calls, retains
// immutable composition and starts no goroutines or private mutation transactions.
// Zero is invalid. No provider verification, replacement issuance or protected
// consumption occurs here. Original response disclosure requires current recovery
// authorization even immediately after commit. Unknown outcomes reveal nothing.
type CaptchaExecutor struct {
	executor  *Executor
	flow      risk.FlowContextInput
	operation identity.FeatureOperation
}

var _ risk.CaptchaEvidenceExecutor = (*CaptchaExecutor)(nil)

// NewCaptchaExecutor freezes one exact flow and verified caller using the owned
// kernel/risk/audit/lifecycle registry. Caller operation, tenant and target must
// match; administrator actor must be the separately verified caller. Missing,
// malformed or mismatched composition returns redacted ErrInvalidPolicy. Copies
// of caller attributes are owned, and caller mutation cannot change admission.
func NewCaptchaExecutor(c CaptchaExecutorConfig) (*CaptchaExecutor, error) {
	if _, err := risk.NewFlowContext(c.Flow); err != nil || c.Executor.Repository == nil || len(c.Executor.Repository.captcha) == 0 {
		return nil, risk.ErrInvalidPolicy
	}
	subject := identity.FeatureSubjectUser
	target, resource := c.Flow.Subject, "identity.user"
	if c.Flow.AnonymousFlow != "" {
		subject, target, resource = identity.FeatureSubjectAnonymousFlow, c.Flow.AnonymousFlow, "identity.anonymous-flow"
	}
	op := CaptchaIssueOperation(subject)
	r := c.Executor.Caller.Request
	if !boundedExecutorCallerShape(c.Executor.Caller) || r.Action != authorization.Action(op.OperationID) || string(r.Tenant) != c.Flow.Tenant || string(r.Resource.Type) != resource || string(r.Resource.ID) != target || c.Flow.Kind == risk.FlowAdministrator && string(r.Subject.ID) != c.Flow.Actor {
		return nil, risk.ErrInvalidPolicy
	}
	c.Executor.Caller = c.Executor.Caller.Clone()
	if c.Executor.Caller.Request.Attributes == nil {
		c.Executor.Caller.Request.Attributes = authorization.Attributes{}
	}
	for name, value := range map[string]string{"flow-kind": string(c.Flow.Kind), "operation": string(c.Flow.Operation), "pre-auth": c.Flow.PreAuthTransaction, "session": c.Flow.Session, "actor": c.Flow.Actor, "challenge": c.Flow.ChallengeID, "request": c.Flow.RequestFingerprint} {
		c.Executor.Caller.Request.Attributes[authorization.AttributeName("identity.captcha."+name)] = authorization.StringValue(value)
	}
	executor, err := newExecutor(c.Executor, boundedExecutorCallerShape(c.Executor.Caller))
	if err != nil {
		return nil, err
	}
	return &CaptchaExecutor{executor: executor, flow: c.Flow, operation: op}, nil
}

// Resolve performs bounded current admission and primary history observation.
// Only an actual missing claim permits provider verification. Historical rows
// need independent current recovery authorization and exact intent/AAD matching;
// elapsed time never renews or releases custody. Unknown/denied returns no bearer.
func (e *CaptchaExecutor) Resolve(ctx context.Context, i risk.CaptchaEvidenceIntent) (risk.CaptchaEvidenceExecution, error) {
	if ctx == nil || e == nil || e.executor == nil {
		return risk.CaptchaEvidenceExecution{}, risk.ErrInvalidEvidenceExecution
	}
	q, err := e.query(i)
	if err != nil {
		return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceDenied, risk.CaptchaEvidenceRecord{})
	}
	bounded, cancel := context.WithTimeout(ctx, e.executor.timeout)
	defer cancel()
	a, err := e.executor.coordinator.ObserveCommandAdmission(bounded, q, e.executor.caller)
	if a.Absent && err == nil && bounded.Err() == nil {
		return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceMissing, risk.CaptchaEvidenceRecord{})
	}
	if a.Validate() != nil {
		return e.failure(i, err)
	}
	return e.afterSubmission(bounded, i)
}

// Execute reserves original aliases, applies native evidence and commits its
// audit/lifecycle/receipt in the same coordinator Work. Proven rollback never
// exposes a candidate; ambiguity retains replay ownership for primary recovery.
// It neither retries provider work nor manufactures a successor bearer.
func (e *CaptchaExecutor) Execute(ctx context.Context, issue risk.CaptchaEvidenceIssue) (risk.CaptchaEvidenceExecution, error) {
	if ctx == nil || e == nil || e.executor == nil || issue.Prepared().Binding.KeyVersion == 0 {
		return risk.CaptchaEvidenceExecution{}, risk.ErrInvalidEvidenceExecution
	}
	i := issue.Intent()
	q, err := e.query(i)
	if err != nil {
		return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceDenied, risk.CaptchaEvidenceRecord{})
	}
	bounded, cancel := context.WithTimeout(ctx, e.executor.timeout)
	defer cancel()
	a, err := e.executor.coordinator.ObserveCommandAdmission(bounded, q, e.executor.caller)
	if err != nil {
		return e.failure(i, err)
	}
	if !a.Absent {
		return e.afterSubmission(bounded, i)
	}
	p := issue.Prepared()
	b := identity.CommandBinding{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, AnonymousFlowID: q.AnonymousFlowID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, PolicyID: e.executor.policyID, PolicyVersion: p.Binding.PolicyVersion, SchemaID: e.operation.SchemaID, SchemaVersion: 1, CorrelationID: string(q.CommandID)}
	command, err := MapCaptchaIssue(issue, b)
	if err != nil {
		return risk.CaptchaEvidenceExecution{}, risk.ErrInvalidEvidenceExecution
	}
	spec, _ := command.Feature()
	plan, err := e.plan(spec.Binding, command, p.PreparedAt)
	if err != nil {
		return risk.CaptchaEvidenceExecution{}, risk.ErrInvalidEvidenceExecution
	}
	reservation, result, err := e.executor.coordinator.ReserveCommand(bounded, spec.Binding, command, plan)
	if result.Outcome == identity.CommitOutcomeUnknown {
		return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceUnknown, risk.CaptchaEvidenceRecord{})
	}
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		return e.afterSubmission(bounded, i)
	}
	w, err := e.executor.coordinator.Begin(bounded, reservation)
	if err != nil {
		return e.afterSubmission(bounded, i)
	}
	defer e.executor.coordinator.Abort(w, identity.UnavailableError{})
	result, err = e.executor.coordinator.ApplyFeature(bounded, w, command)
	if err != nil {
		_, _ = e.executor.coordinator.Abort(w, err)
		return e.afterSubmission(bounded, i)
	}
	result, err = e.executor.coordinator.Commit(w, result)
	if err != nil || result.Outcome == identity.CommitOutcomeUnknown {
		return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceUnknown, risk.CaptchaEvidenceRecord{})
	}
	return e.afterSubmission(bounded, i)
}

func (e *CaptchaExecutor) failure(i risk.CaptchaEvidenceIntent, err error) (risk.CaptchaEvidenceExecution, error) {
	var denied identity.ForbiddenError
	if errors.As(err, &denied) {
		return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceDenied, risk.CaptchaEvidenceRecord{})
	}
	return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceUnknown, risk.CaptchaEvidenceRecord{})
}

func (e *CaptchaExecutor) query(i risk.CaptchaEvidenceIntent) (identity.RecoveryQuery, error) {
	bindings := i.Bindings()
	if len(bindings) < 1 || len(bindings) > 16 {
		return identity.RecoveryQuery{}, risk.ErrInvalidEvidenceExecution
	}
	b := bindings[0]
	if b.Replay.Flow != e.flow || b.PolicyVersion != e.executor.repository.policy {
		return identity.RecoveryQuery{}, risk.ErrInvalidEvidenceExecution
	}
	r := e.executor.caller.Request
	return identity.RecoveryQuery{CommandID: identity.CommandID(b.CommandID), TenantID: identity.TenantID(e.flow.Tenant), UserID: identity.UserID(e.flow.Subject), AnonymousFlowID: e.flow.AnonymousFlow, ActorID: identity.ActorID(r.Subject.ID), ActorKind: r.Subject.Kind, OperationID: e.operation.OperationID, RecordID: b.CommandID}, nil
}

func (e *CaptchaExecutor) afterSubmission(ctx context.Context, i risk.CaptchaEvidenceIntent) (risk.CaptchaEvidenceExecution, error) {
	q, err := e.query(i)
	if err != nil {
		return risk.CaptchaEvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	observed, err := e.executor.coordinator.RecoverCommand(ctx, q, e.executor.caller)
	if ctx.Err() != nil {
		return risk.CaptchaEvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	if observed.Outcome == identity.CommitOutcomeCommitted && err == nil {
		return e.original(ctx, i, observed)
	}
	if observed.Outcome == identity.CommitOutcomeNotCommitted {
		return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceFailed, risk.CaptchaEvidenceRecord{})
	}
	return e.failure(i, err)
}

func (e *CaptchaExecutor) plan(b identity.CommandBinding, c identity.Command, at time.Time) (identitypostgres.CommandPlan, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at, Action: "identity.captcha.verify", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "captcha_evidence", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "captcha_evidence", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	digest, err := identitypostgres.FeatureAuditBindingDigest(b, e.operation, "captcha_evidence", seed)
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	return e.executor.coordinator.PrepareCommandPlan(b, c, identitypostgres.CommandPlan{Contributors: e.executor.registry.Descriptors(), SubjectType: "captcha_evidence", CaptchaReplayReservation: true, Feature: &identitypostgres.FeatureRegistration{Contributor: e.executor.repository.Descriptor(), Operation: e.operation}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "identity.captcha.issued.v1", AfterVersion: 1}, Audits: []identitypostgres.AuditPlan{{EventType: "identity.captcha.verify", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: e.executor.retention, RetentionClass: "protected", BindingDigest: digest}}})
}

// Private lookup only after current recovery authorization; generic repository
// reads cannot disclose the response. Exact original intent and binding are
// authenticated before exposing any plaintext, including expired history.
func (e *CaptchaExecutor) original(ctx context.Context, i risk.CaptchaEvidenceIntent, observed identitypostgres.CommandRecord) (risk.CaptchaEvidenceExecution, error) {
	if observed.Validate() != nil || observed.Outcome != identity.CommitOutcomeCommitted || observed.Feature == nil || *observed.Feature != e.operation {
		return risk.CaptchaEvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	b := observed.Binding
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return risk.CaptchaEvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	var row captchaRecoveryRow
	err = e.executor.pool.Raw().QueryRow(ctx, `SELECT user_id,anonymous_flow_id,command_purpose,binding_digest,intent_digest,proof_digest,evidence_digest,key_version,hostname,issued_at,expires_at,state,response_envelope FROM `+e.executor.repository.schema+`.captcha_issued_evidence WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id).Scan(&row.user, &row.flow, &row.purpose, &row.binding, &row.intent, &row.proof, &row.lookup, &row.key, &row.record.Hostname, &row.record.IssuedAt, &row.record.ExpiresAt, &row.state, &row.envelope)
	defer clear(row.envelope)
	if err != nil || ctx.Err() != nil {
		return risk.CaptchaEvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	status, err := e.executor.repository.classifyCaptchaRecovery(ctx, b, &row)
	if err != nil || status != identitypostgres.RecoveryCommitted {
		return risk.CaptchaEvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	matched := false
	for _, candidate := range i.Bindings() {
		if int64(candidate.KeyVersion) == row.key && candidate.IntentDigest == [32]byte(row.intent) {
			matched = true
			break
		}
	}
	if !matched {
		return risk.CaptchaEvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	r := row.record
	r.KeyVersion, r.IntentDigest, r.ProofDigest, r.EvidenceDigest = uint32(row.key), [32]byte(row.intent), [32]byte(row.proof), [32]byte(row.lookup)
	r.IssuedAt, r.ExpiresAt = r.IssuedAt.UTC(), r.ExpiresAt.UTC()
	r, err = e.executor.repository.cipher.openCaptcha(ctx, b, r, row.envelope)
	if err != nil || ctx.Err() != nil {
		return risk.CaptchaEvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceCommitted, r)
}

// Format redacts trusted flow and runtime composition.
func (CaptchaExecutorConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.CaptchaExecutorConfig(redacted)")
}

// MarshalJSON rejects trusted runtime export.
func (CaptchaExecutorConfig) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText rejects trusted runtime export.
func (CaptchaExecutorConfig) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// Format redacts trusted flow and runtime composition.
func (CaptchaExecutor) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.CaptchaExecutor(redacted)")
}

// MarshalJSON rejects trusted runtime export.
func (CaptchaExecutor) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// MarshalText rejects trusted runtime export.
func (CaptchaExecutor) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
