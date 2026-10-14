package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// ExecutorConfig composes one authenticated caller's immutable authorization
// context with the caller-owned primary pool and durable effect adapters. Caller
// must come from verified server composition, never client-decoded Actor input.
// Its tenant/resource identify the exact user scope; use another executor for
// another verified scope. Coordinator requires both QueryPolicy and separately
// opt-in AdmissionPolicy at Caller's current policy revision. Repository is the
// exact instance registered internally, with copied retained custody keys.
// Effect adapters must implement RecoveryContributor as well as their typed
// persistence phase. Construction does no IO and transfers no resource ownership.
type ExecutorConfig struct {
	Pool                   *database.Pool
	Repository             *Repository
	Audit                  identitypostgres.AuditContributor
	Lifecycle              identitypostgres.LifecycleContributor
	Coordinator            identitypostgres.CoordinatorConfig
	Caller                 authorization.DecisionContext
	PolicyID               string
	RetentionPolicyVersion uint64
}

// Format hides verified caller attributes, pool settings and fingerprint keys.
func (ExecutorConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.ExecutorConfig(redacted)")
}

// MarshalJSON rejects serialization of trusted runtime composition.
func (ExecutorConfig) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// MarshalText rejects serialization of trusted runtime composition.
func (ExecutorConfig) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// Executor owns issuance and authorized original-response recovery through the
// sole identity Coordinator. It starts no goroutines, opens no private mutation
// transactions and never closes the caller's pool or effect adapters. Immutable
// composition supports concurrent calls; each Work is used serially. Zero is
// invalid. Pending/failed history never permits provider reevaluation. This
// issuance profile does not grant reservation or protected consumption authority.
type Executor struct {
	pool        *database.Pool
	repository  *Repository
	coordinator *identitypostgres.Coordinator
	registry    *identitypostgres.ContributorRegistry
	caller      authorization.DecisionContext
	policyID    string
	retention   uint64
	timeout     time.Duration
}

var _ risk.EvidenceExecutor = (*Executor)(nil)

// Format hides trusted caller and custody dependencies.
func (Executor) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "postgres.Executor(redacted)") }

// MarshalJSON rejects runtime composition serialization.
func (Executor) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// MarshalText rejects runtime composition serialization.
func (Executor) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// NewExecutor validates bounded trusted composition and constructs the exact
// four-participant registry. Invalid or incomplete composition fails redacted.
// The caller context is copied; services/adapters must retain their immutable
// policy revision and support concurrent calls for the executor's lifetime.
func NewExecutor(c ExecutorConfig) (*Executor, error) {
	return newExecutor(c, boundedExecutorCaller(c.Caller))
}

// Common owned resource/registry construction; each public constructor retains
// its distinct exact operation and trusted-subject admission rules.
func newExecutor(c ExecutorConfig, validCaller bool) (*Executor, error) {
	if c.Pool == nil || c.Pool.Raw() == nil || c.Repository == nil || c.Repository.schema == "" || !validCaller || !executorID(c.PolicyID) || c.RetentionPolicyVersion == 0 || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || uint64(c.Caller.PolicyRevision) != c.Coordinator.QueryPolicy.PolicyVersion || uint64(c.Caller.PolicyRevision) != c.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, risk.ErrInvalidPolicy
	}
	domain, err := identitypostgres.NewRepository(c.Pool, identitypostgres.Config{MaximumDuration: c.Coordinator.MaximumDuration})
	if err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{domain, c.Repository, c.Audit, c.Lifecycle})
	if err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	descriptors := registry.Descriptors()
	auditing := descriptors[2]
	// The owned audit adapter uses identity.security_audit. Keep the original
	// explicitly admitted v1 composition identity compatible, not arbitrary
	// phase-compatible contracts or versions from the same owner.
	if auditing.Owner != "audit/postgres" || auditing.Version != 1 || (auditing.ContractID != "identity.security_audit" && auditing.ContractID != "identity.audit") || descriptors[3] != (identitypostgres.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}) {
		return nil, risk.ErrInvalidPolicy
	}
	if _, ok := c.Audit.(identitypostgres.RecoveryContributor); !ok {
		return nil, risk.ErrInvalidPolicy
	}
	if _, ok := c.Lifecycle.(identitypostgres.RecoveryContributor); !ok {
		return nil, risk.ErrInvalidPolicy
	}
	coordinator, err := identitypostgres.NewCoordinator(c.Pool, registry, c.Coordinator)
	if err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	return &Executor{pool: c.Pool, repository: c.Repository, coordinator: coordinator, registry: registry, caller: c.Caller.Clone(), policyID: c.PolicyID, retention: c.RetentionPolicyVersion, timeout: c.Coordinator.MaximumDuration}, nil
}

// Resolve authorizes one uncached primary admission observation before provider
// work. Only actual global claim absence returns Missing. Committed responses
// require a private exact-intent row read and historical-AAD decryption; expired
// originals are preserved without renewal. Pending reconciliation invokes only
// frozen contributors through the coordinator. Unknown never carries a bearer.
func (e *Executor) Resolve(ctx context.Context, intent risk.EvidenceIntent) (risk.EvidenceExecution, error) {
	if ctx == nil || e == nil || e.coordinator == nil {
		return risk.EvidenceExecution{}, risk.ErrInvalidEvidenceExecution
	}
	q, err := e.query(intent)
	if err != nil {
		return risk.NewEvidenceExecution(intent, risk.EvidenceDenied, risk.EvidenceRecord{})
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	a, err := e.coordinator.ObserveCommandAdmission(bounded, q, e.caller)
	if a.Absent && err == nil && bounded.Err() == nil {
		return risk.NewEvidenceExecution(intent, risk.EvidenceMissing, risk.EvidenceRecord{})
	}
	if a.Validate() != nil {
		return e.observationFailure(intent, err)
	}
	// Admission grants only pre-provider absence/metadata observation. Protected
	// original-response disclosure always requires the distinct current recovery
	// policy, including already committed history with no reconciliation work.
	record, err := e.coordinator.RecoverCommand(bounded, q, e.caller)
	if bounded.Err() != nil {
		return risk.EvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	if record.Outcome == identity.CommitOutcomeCommitted && err == nil {
		return e.original(bounded, intent, record)
	}
	if record.Outcome == identity.CommitOutcomeNotCommitted {
		return risk.NewEvidenceExecution(intent, risk.EvidenceFailed, risk.EvidenceRecord{})
	}
	return e.observationFailure(intent, err)
}

func (e *Executor) observationFailure(i risk.EvidenceIntent, err error) (risk.EvidenceExecution, error) {
	var denied identity.ForbiddenError
	if errors.As(err, &denied) {
		return risk.NewEvidenceExecution(i, risk.EvidenceDenied, risk.EvidenceRecord{})
	}
	return risk.NewEvidenceExecution(i, risk.EvidenceUnknown, risk.EvidenceRecord{})
}

// Execute authorizes before reservation, freezes the signed native command and
// performs one same-Work mutation with protected audit/lifecycle/receipt. The
// encrypted original is disclosed only after independently authorized primary
// commitment resolution. Conflict, pending, failed and commit uncertainty never
// materialize a replacement reference or rerun providers.
func (e *Executor) Execute(ctx context.Context, issue risk.EvidenceIssue) (risk.EvidenceExecution, error) {
	if ctx == nil || e == nil || e.coordinator == nil || issue.Prepared().Binding.KeyVersion == 0 {
		return risk.EvidenceExecution{}, risk.ErrInvalidEvidenceExecution
	}
	intent := issue.Intent()
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	q, err := e.query(intent)
	if err != nil {
		return risk.NewEvidenceExecution(intent, risk.EvidenceDenied, risk.EvidenceRecord{})
	}
	a, err := e.coordinator.ObserveCommandAdmission(bounded, q, e.caller)
	if err != nil {
		return e.observationFailure(intent, err)
	}
	if !a.Absent {
		return e.afterSubmission(bounded, intent)
	}
	p := issue.Prepared()
	b := identity.CommandBinding{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, PolicyID: e.policyID, PolicyVersion: p.Binding.PolicyVersion, SchemaID: IssueOperation().SchemaID, SchemaVersion: 1, CorrelationID: string(q.CommandID)}
	command, err := MapIssue(issue, b)
	if err != nil {
		return risk.EvidenceExecution{}, risk.ErrInvalidEvidenceExecution
	}
	spec, _ := command.Feature()
	b = spec.Binding
	plan, err := e.plan(b, command, p.PreparedAt)
	if err != nil {
		return risk.EvidenceExecution{}, risk.ErrInvalidEvidenceExecution
	}
	reservation, result, err := e.coordinator.ReserveCommand(bounded, b, command, plan)
	if result.Outcome == identity.CommitOutcomeUnknown {
		return risk.NewEvidenceExecution(intent, risk.EvidenceUnknown, risk.EvidenceRecord{})
	}
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		return e.afterSubmission(bounded, intent)
	}
	w, err := e.coordinator.Begin(bounded, reservation)
	if err != nil {
		return e.afterSubmission(bounded, intent)
	}
	defer e.coordinator.Abort(w, identity.UnavailableError{})
	result, err = e.coordinator.ApplyFeature(bounded, w, command)
	if err != nil {
		_, _ = e.coordinator.Abort(w, err)
		return e.afterSubmission(bounded, intent)
	}
	result, err = e.coordinator.Commit(w, result)
	if err != nil || result.Outcome == identity.CommitOutcomeUnknown {
		return risk.NewEvidenceExecution(intent, risk.EvidenceUnknown, risk.EvidenceRecord{})
	}
	return e.afterSubmission(bounded, intent)
}

func (e *Executor) afterSubmission(ctx context.Context, i risk.EvidenceIntent) (risk.EvidenceExecution, error) {
	// Submitted command absence is never noncommit proof or evaluation permission.
	q, err := e.query(i)
	if err != nil {
		return risk.EvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	record, err := e.coordinator.RecoverCommand(ctx, q, e.caller)
	if record.Outcome == identity.CommitOutcomeCommitted && err == nil {
		return e.original(ctx, i, record)
	}
	if record.Outcome == identity.CommitOutcomeNotCommitted {
		return risk.NewEvidenceExecution(i, risk.EvidenceFailed, risk.EvidenceRecord{})
	}
	return risk.NewEvidenceExecution(i, risk.EvidenceUnknown, risk.EvidenceRecord{})
}

func (e *Executor) query(i risk.EvidenceIntent) (identity.RecoveryQuery, error) {
	bindings := i.Bindings()
	if len(bindings) == 0 || len(bindings) > 16 {
		return identity.RecoveryQuery{}, risk.ErrInvalidEvidenceExecution
	}
	b := bindings[0]
	r := e.caller.Request
	if b.Actor != string(r.Subject.ID) || b.Tenant != string(r.Tenant) || b.Subject != string(r.Resource.ID) || b.PolicyVersion != e.repository.policy {
		return identity.RecoveryQuery{}, risk.ErrInvalidEvidenceExecution
	}
	return identity.RecoveryQuery{CommandID: identity.CommandID(b.CommandID), TenantID: identity.TenantID(b.Tenant), UserID: identity.UserID(b.Subject), ActorID: identity.ActorID(b.Actor), ActorKind: r.Subject.Kind, OperationID: IssueOperation().OperationID, RecordID: b.CommandID}, nil
}

func (e *Executor) plan(b identity.CommandBinding, c identity.Command, at time.Time) (identitypostgres.CommandPlan, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at, Action: "identity.risk.decide", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "risk_evidence", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "risk_evidence", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	digest, err := identitypostgres.FeatureAuditBindingDigest(b, IssueOperation(), "risk_evidence", seed)
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	return e.coordinator.PrepareCommandPlan(b, c, identitypostgres.CommandPlan{Contributors: e.registry.Descriptors(), SubjectType: "risk_evidence", Feature: &identitypostgres.FeatureRegistration{Contributor: e.repository.Descriptor(), Operation: IssueOperation()}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "risk.evidence_issued.v1", AfterVersion: 1}, Audits: []identitypostgres.AuditPlan{{EventType: "identity.risk.decide", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: e.retention, RetentionClass: "protected", BindingDigest: digest}}})
}

func executorID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < '!' || b > '~' {
			return false
		}
	}
	return true
}

func boundedExecutorCaller(dc authorization.DecisionContext) bool {
	return dc.Request.Action == authorization.Action(IssueOperation().OperationID) && dc.Request.Resource.Type == "identity.user" && boundedExecutorCallerShape(dc)
}

func boundedExecutorCallerShape(dc authorization.DecisionContext) bool {
	if len(dc.Request.Subject.Groups) > 32 || dc.Validate() != nil {
		return false
	}
	if dc.Request.Subject.Kind != authorization.SubjectUser && dc.Request.Subject.Kind != authorization.SubjectAPIKey && dc.Request.Subject.Kind != authorization.SubjectServiceAccount {
		return false
	}
	for _, s := range []string{string(dc.Request.Subject.ID), string(dc.Request.Tenant), string(dc.Request.Resource.ID)} {
		if !executorID(s) {
			return false
		}
	}
	for _, s := range dc.Request.Subject.Groups {
		if !executorID(string(s)) {
			return false
		}
	}
	for _, attrs := range []authorization.Attributes{dc.Request.Subject.Attributes, dc.Request.Resource.Attributes, dc.Request.Environment.Attributes, dc.Request.Attributes} {
		if len(attrs) > 128 {
			return false
		}
		for name, value := range attrs {
			if !executorID(string(name)) || value.Kind() == authorization.ValueMissing {
				return false
			}
			if s, ok := value.String(); ok && (len(s) > 4096 || !utf8.ValidString(s)) {
				return false
			}
			if count, ok := value.CollectionLength(); ok {
				if count > 64 {
					return false
				}
				items, _ := value.StringSet()
				for _, s := range items {
					if len(s) > 4096 || !utf8.ValidString(s) {
						return false
					}
				}
			}
		}
	}
	return true
}

// Original response lookup remains private to the authorized executor. The
// native repository deliberately exposes no public bearer-read API.
func (e *Executor) original(ctx context.Context, i risk.EvidenceIntent, observed identitypostgres.CommandRecord) (risk.EvidenceExecution, error) {
	if observed.Validate() != nil || observed.Outcome != identity.CommitOutcomeCommitted || observed.Feature == nil || *observed.Feature != IssueOperation() {
		return risk.EvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	b := observed.Binding
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return risk.EvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	var r risk.EvidenceRecord
	var purpose, policy, state string
	var key int64
	var binding, intent, proof, lookup, envelope []byte
	err = e.pool.Raw().QueryRow(ctx, `SELECT purpose,policy_version::text,key_version,binding_digest,intent_digest,proof_digest,evidence_digest,issued_at,expires_at,state,response_envelope FROM `+e.repository.schema+`.issued_evidence WHERE tenant_id=$1 AND command_id=$2 AND record_id=$3 AND user_id=$4 AND command_purpose=$5`, string(b.TenantID), id, b.RecordID, string(b.UserID), b.OperationID).Scan(&purpose, &policy, &key, &binding, &intent, &proof, &lookup, &r.IssuedAt, &r.ExpiresAt, &state, &envelope)
	if err != nil || ctx.Err() != nil || key < 1 || key > 4294967295 || len(binding) != 32 || len(intent) != 32 || len(proof) != 32 || len(lookup) != 32 || len(envelope) < 100 || len(envelope) > 1024 || !issuedJournalState(state) {
		return risk.EvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	defer clear(envelope)
	want := bindingDigest(b)
	if [32]byte(binding) != want {
		return risk.EvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	r.KeyVersion = uint32(key)
	copy(r.IntentDigest[:], intent)
	copy(r.ProofDigest[:], proof)
	copy(r.EvidenceDigest[:], lookup)
	r.IssuedAt = r.IssuedAt.UTC()
	r.ExpiresAt = r.ExpiresAt.UTC()
	matched := false
	for _, candidate := range i.Bindings() {
		if candidate.KeyVersion == r.KeyVersion && candidate.IntentDigest == r.IntentDigest && candidate.Purpose == purpose && strconv.FormatUint(candidate.PolicyVersion, 10) == policy {
			matched = true
			break
		}
	}
	if !matched {
		return risk.EvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	r, err = e.repository.cipher.open(ctx, b, r, envelope)
	if err != nil || ctx.Err() != nil {
		return risk.EvidenceExecution{}, risk.ErrEvidenceUnavailable
	}
	return risk.NewEvidenceExecution(i, risk.EvidenceCommitted, r)
}

// Subsequent one-use state never reverses historical issuance commitment.
// Returning the original response cannot confer reservation rights; the native
// reservation CAS independently rejects terminal, expired and foreign ownership.
func issuedJournalState(state string) bool {
	switch state {
	case "issued", "reserved", "finalized", "released", "expired", "revoked":
		return true
	default:
		return false
	}
}
