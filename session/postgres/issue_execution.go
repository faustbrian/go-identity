package postgres

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	authorization "github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// IssueExecutorConfig selects trusted single-factor self-service composition.
// Coordinator must configure the same final-authentication authority used by
// the core issuer. PolicyID and positive versions are retained while commands
// exist. Clock and Authorization must be bounded, concurrency-safe dependencies.
// Repository/Profile retain their native constructor semantics. No transaction,
// registry, domain store or consumer workflow is accepted. Zero is invalid.
type IssueExecutorConfig struct {
	Repository                           Config
	Profile                              IssueAdmissionConfig
	Coordinator                          kernel.CoordinatorConfig
	Authorization                        authorization.Service
	Clock                                clock.Clock
	PolicyID                             string
	PolicyVersion, AuditRetentionVersion uint64
}

// IssueExecutor owns native session, kernel, audit and lifecycle composition.
// It borrows the primary pool and immutable policy/authenticator dependencies;
// the caller closes them after all calls finish. It starts no goroutines and
// is concurrency-safe. It never owns or reveals a bearer. Zero is invalid.
type IssueExecutor struct {
	coordinator                     *kernel.Coordinator
	registry                        *kernel.ContributorRegistry
	native                          *Repository
	authorize                       authorization.Service
	clock                           clock.Clock
	policyID                        string
	policyVersion, retentionVersion uint64
	maximumDuration                 time.Duration
}

var _ session.IssueExecutor = (*IssueExecutor)(nil)

// NewIssueExecutor composes the sole authoritative command owner without IO.
// Install kernel, proof-use, authorization, session, issuance, audit and outbox
// migrations first. Missing infrastructure fails closed during execution; this
// constructor never applies migrations or registers policy grants. QueryPolicy
// is fixed to this same current service/clock/revision for receipt recovery.
// Existing native repository constructors retain their contributor-only API.
func NewIssueExecutor(pool *database.Pool, c IssueExecutorConfig) (*IssueExecutor, error) {
	return newOwnedSessionExecution(pool, c, true)
}

func newOwnedSessionExecution(pool *database.Pool, c IssueExecutorConfig, requireFinalAuthentication bool) (*IssueExecutor, error) {
	if pool == nil || pool.Raw() == nil || nilIssueDependency(c.Authorization) || nilIssueDependency(c.Clock) || !scopeID(c.PolicyID) || c.PolicyVersion == 0 || c.AuditRetentionVersion == 0 || requireFinalAuthentication && (c.Coordinator.FinalAuthentication == nil || c.Coordinator.FinalAuthentication.Authority == nil) || c.Coordinator.MaximumDuration < time.Millisecond || c.Coordinator.MaximumDuration > 30*time.Second {
		return nil, session.ErrInvalidIssuer
	}
	native, err := NewRepositoryWithIssueAdmission(pool, c.Repository, c.Profile)
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Coordinator.MaximumDuration})
	if err != nil {
		return nil, err
	}
	auditing, err := auditpostgres.NewIdentityContributor(auditpostgres.Config{})
	if err != nil {
		return nil, session.ErrInvalidIssuer
	}
	lifecycle, err := identityoutbox.NewContributor()
	if err != nil {
		return nil, session.ErrInvalidIssuer
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, native, auditing, lifecycle})
	if err != nil {
		return nil, err
	}
	c.Coordinator.QueryPolicy = &kernel.CommandQueryPolicy{Authorization: c.Authorization, Clock: c.Clock, PolicyVersion: c.PolicyVersion}
	coordinator, err := kernel.NewCoordinator(pool, registry, c.Coordinator)
	if err != nil {
		return nil, err
	}
	return &IssueExecutor{coordinator, registry, native, c.Authorization, c.Clock, c.PolicyID, c.PolicyVersion, c.AuditRetentionVersion, c.Coordinator.MaximumDuration}, nil
}

func nilIssueDependency(value any) bool {
	if value == nil {
		return true
	}
	r := reflect.ValueOf(value)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

// ExecuteIssue validates original opaque admission and current policy before
// reservation. The kernel compares current owners and final expiry, consumes
// the original proof and commits session/audit/outbox atomically. Exact terminal
// replay returns Replayed and cannot trigger bearer delivery. Cancellation or
// ambiguous execution is not inferred to prove rollback. Earlier deadlines
// bound execution work, but synchronous detached kernel cleanup may outlive
// them; each cleanup phase has its own bounded coordinator budget.
func (e *IssueExecutor) ExecuteIssue(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || e == nil || e.coordinator == nil {
		return session.IssueExecution{}, session.ErrInvalidIssuance
	}
	bounded, stop := context.WithTimeout(ctx, e.maximumDuration)
	defer stop()
	b, command, plan, caller, record, err := e.prepare(request)
	if err != nil {
		return session.IssueExecution{}, err
	}
	proof, _ := request.AuthenticatedProof()
	if err = e.allow(bounded, caller); err != nil {
		return session.IssueExecution{}, err
	}
	reservation, result, err := e.coordinator.ReserveAuthenticatedCommand(bounded, b, command, proof, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return issueExecution(result, record, true), err
	}
	work, err := e.coordinator.Begin(bounded, reservation)
	if err != nil {
		return issueExecution(identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: session.IssueOperation()}}, record, false), err
	}
	defer e.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := e.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		result, err = e.coordinator.Abort(work, err)
		return issueExecution(result, record, false), err
	}
	result, err = e.coordinator.Commit(work, provisional)
	return issueExecution(result, record, false), err
}

// RecoverIssue observes/reconciles the exact original request on the primary
// under current policy. Original expired proof provenance is historical only.
// It never reserves missing commands, renews leases, executes a session or
// reveals a bearer. This request-bearing path requires original opaque custody;
// use RecoverIssueCommand for restart-safe historical metadata reconciliation.
func (e *IssueExecutor) RecoverIssue(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || e == nil || e.coordinator == nil {
		return session.IssueExecution{}, session.ErrInvalidIssuance
	}
	bounded, stop := context.WithTimeout(ctx, e.maximumDuration)
	defer stop()
	b, command, plan, caller, record, err := e.prepare(request)
	if err != nil {
		return session.IssueExecution{}, err
	}
	proof, _ := request.AuthenticatedProof()
	result, err := e.coordinator.RecoverAuthenticatedCommand(bounded, b, command, proof, plan, caller)
	return issueExecution(result, record, true), err
}

// RecoverIssueCommand reconciles issuance after process restart without the
// original proof or bearer. Query must retain every original safe scope field;
// caller comes from trusted current authentication, never decoded client
// identity. The configured current policy independently authorizes disclosure.
// Only historical command metadata is returned, never a session, credential,
// current validity or permission to retry issuance. Missing/denied scope cannot
// reserve a command. Live pending does not renew its lease; expired pending
// reconciles only the frozen participants under the sole kernel recovery owner.
// Incomplete/conflicting evidence fails closed without reconstructing success.
// Execution work and detached cleanup have the same budgets as ExecuteIssue.
func (e *IssueExecutor) RecoverIssueCommand(ctx context.Context, query identity.RecoveryQuery, caller authorization.DecisionContext) (kernel.CommandRecord, error) {
	if ctx == nil || e == nil || e.coordinator == nil {
		return kernel.CommandRecord{}, session.ErrInvalidIssuance
	}
	if query.OperationID != session.IssueOperation().OperationID || !scopeID(query.RecordID) || query.LinkMode != 0 || query.ActorKind != authorization.SubjectUser || string(query.ActorID) != string(query.UserID) {
		return kernel.CommandRecord{}, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, e.maximumDuration)
	defer stop()
	result, err := e.coordinator.RecoverCommand(bounded, query, caller)
	if result.Binding.CommandID == "" {
		return result, err
	}
	if result.Feature == nil || *result.Feature != session.IssueOperation() {
		return kernel.CommandRecord{}, identity.UnavailableError{}
	}
	return result, err
}

func issueExecution(receipt identity.CommandResult, original session.Session, replay bool) session.IssueExecution {
	result := session.IssueExecution{Receipt: receipt, Replayed: replay}
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		result.Session = original
	}
	return result
}

func (e *IssueExecutor) prepare(request session.IssueRequest) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, session.Session, error) {
	fail := func(err error) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, session.Session, error) {
		return identity.CommandBinding{}, identity.Command{}, kernel.CommandPlan{}, authorization.DecisionContext{}, session.Session{}, err
	}
	native, ok := request.Command()
	proof, proved := request.AuthenticatedProof()
	issue, issued := native.Issue()
	if !ok || !proved || !issued {
		return fail(session.ErrInvalidIssuance)
	}
	b := issue.Binding
	if b.PolicyID != e.policyID || b.PolicyVersion != e.policyVersion || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) {
		return fail(identity.ForbiddenError{})
	}
	command, err := MapCommand(native)
	if err != nil {
		return fail(err)
	}
	spec, _ := issue.Session.Bindings()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return fail(session.ErrIssuerUnavailable)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: spec.IssuedAt.UTC().Truncate(time.Microsecond), Action: "identity.session.create", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": "session", "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "standard"}})
	if err != nil {
		return fail(session.ErrIssuerUnavailable)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, session.IssueOperation(), "session", record)
	if err != nil {
		return fail(err)
	}
	declaration := kernel.CommandPlan{Contributors: e.registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: e.native.Descriptor(), Operation: session.IssueOperation()}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.create", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "standard", RetentionPolicyVersion: e.retentionVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
	plan, err := e.coordinator.PrepareAuthenticatedCommandPlan(b, command, proof, declaration)
	if err != nil {
		return fail(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(e.policyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
	return b, command, plan, caller, issue.Session, nil
}

func (e *IssueExecutor) allow(ctx context.Context, caller authorization.DecisionContext) (err error) {
	defer func() {
		if recover() != nil {
			err = session.ErrIssuerUnavailable
		}
	}()
	if ctx.Err() != nil {
		return readError(ctx, ctx.Err())
	}
	now := e.clock.Now()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
		return session.ErrIssuerUnavailable
	}
	caller.Request.Environment.Time = now.UTC()
	decision, err := e.authorize.Decide(ctx, caller)
	if ctx.Err() != nil {
		return readError(ctx, ctx.Err())
	}
	if err != nil {
		return session.ErrIssuerUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return identity.ForbiddenError{}
	}
	return nil
}

// Format prevents diagnostic traversal of runtime composition and retained keys.
func (IssueExecutor) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.IssueExecutor(redacted)"))
}

// MarshalJSON rejects implicit export of runtime composition.
func (IssueExecutor) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format redacts secret configuration for every formatting verb.
func (IssueExecutorConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.IssueExecutorConfig(redacted)"))
}

// MarshalJSON rejects implicit export of configuration and retained keys.
func (IssueExecutorConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
