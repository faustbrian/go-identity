package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	authorization "github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// PreAuthIssueExecutorConfig selects one server-owned initiation profile.
// Action, Origin and CallbackURL are exact trusted allowlist choices, not
// client-selected policy; empty CallbackURL explicitly disables redirection.
// ActorID is the trusted service actor, separate from the anonymous flow target.
// Authorization must bound callbacks and be concurrency-safe. Dependencies
// are borrowed; install kernel, pre-auth, issuance, audit and outbox migrations.
// Coordinator, policy and digest keys must be retained while commands exist.
type PreAuthIssueExecutorConfig struct {
	Repository                            Config
	Coordinator                           kernel.CoordinatorConfig
	Authorization                         authorization.Service
	Clock                                 clock.Clock
	ActorID                               identity.ActorID
	Action, Origin, CallbackURL, PolicyID string
	PolicyVersion, AuditRetentionVersion  uint64
	// Purpose selects only the matching core profile; zero preserves login.
	// Phone recovery has no session choice and requires identifier binding.
	Purpose session.PreAuthPurpose
}

// PreAuthIssueCommand freezes a server-prepared original flow with a stable
// command identity and correlation. Record is structural, not authentication.
// Server initiation owns nonce, cookie commitment, original time and resolved
// remember policy; never decode this value directly from HTTP input. The same
// complete command must be retained across retries; no raw cookie is accepted.
type PreAuthIssueCommand = session.PreAuthIssueCommand

// PreAuthIssueExecutor owns native initiation and outcome-only restart recovery
// through the sole kernel coordinator. It opens no second journal and accepts
// no user-supplied store, transaction or workflow. Calls are concurrency-safe;
// keep its borrowed pool/policy/clock alive until all calls finish. Zero denies.
// Cookie generation/delivery belong to the storage-neutral initiation owner.
type PreAuthIssueExecutor struct{ owned *IssueExecutor }

var _ session.PreAuthIssueExecutor = (*PreAuthIssueExecutor)(nil)
var _ session.PreAuthIssuanceExecutor = (*PreAuthIssueExecutor)(nil)

// NewPreAuthIssueExecutor freezes one profile and native participants without
// IO. It does not authenticate a user, mint a cookie, apply migrations or grant
// policy access. Original persisted scope is distinct from verified actors.
func NewPreAuthIssueExecutor(pool *database.Pool, c PreAuthIssueExecutorConfig) (*PreAuthIssueExecutor, error) {
	if pool == nil || pool.Raw() == nil || nilIssueDependency(c.Authorization) || nilIssueDependency(c.Clock) || !scopeID(string(c.ActorID)) || !scopeID(c.PolicyID) || c.PolicyVersion == 0 || c.AuditRetentionVersion == 0 || c.Coordinator.MaximumDuration < time.Millisecond || c.Coordinator.MaximumDuration > 30*time.Second {
		return nil, session.ErrInvalidInput
	}
	// The core owns exact URL/action validation. Use a fixed non-issuing template
	// to reject malformed trusted configuration without randomness or IO.
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		return nil, session.ErrInvalidInput
	}
	var identifier [32]byte
	if c.Purpose == session.PreAuthPhonePasswordRecovery {
		remember = session.RememberPolicy{}
		identifier = [32]byte{1}
	}
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: "AQEBAQEBAQEBAQEBAQEBAQ", Intent: session.PreAuthIntent{TenantID: "configuration", Action: c.Action, Origin: c.Origin, CallbackURL: c.CallbackURL, Nonce: [32]byte{1}, Remember: remember, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, IdentifierBinding: identifier, Purpose: c.Purpose}, IssuedAt: stamp, ExpiresAt: stamp.Add(5 * time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, Version: 1})
	if err != nil {
		return nil, session.ErrInvalidInput
	}
	native, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	native.preAuthIssue = &preAuthIssueProfile{actor: identity.ActorID(strings.Clone(string(c.ActorID))), action: strings.Clone(c.Action), origin: strings.Clone(c.Origin), callback: strings.Clone(c.CallbackURL), policy: strings.Clone(c.PolicyID), version: c.PolicyVersion, purpose: c.Purpose}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Coordinator.MaximumDuration})
	if err != nil {
		return nil, err
	}
	auditing, err := auditpostgres.NewIdentityContributor(auditpostgres.Config{})
	if err != nil {
		return nil, session.ErrUnavailable
	}
	lifecycle, err := identityoutbox.NewContributor()
	if err != nil {
		return nil, session.ErrUnavailable
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
	owned := &IssueExecutor{coordinator, registry, native, c.Authorization, c.Clock, strings.Clone(c.PolicyID), c.PolicyVersion, c.AuditRetentionVersion, c.Coordinator.MaximumDuration}
	return &PreAuthIssueExecutor{owned}, nil
}

func (e *PreAuthIssueExecutor) preparePreAuth(input PreAuthIssueCommand) (identity.CommandBinding, identity.Command, error) {
	if e == nil || e.owned == nil || e.owned.native == nil || e.owned.native.preAuthIssue == nil {
		return identity.CommandBinding{}, identity.Command{}, session.ErrInvalidInput
	}
	s, err := input.Record.Bindings()
	if err != nil {
		return identity.CommandBinding{}, identity.Command{}, session.ErrInvalidPreAuthTransaction
	}
	p := e.owned.native.preAuthIssue
	op := preAuthIssueOperation()
	b := identity.CommandBinding{CommandID: input.CommandID, TenantID: s.Binding.Intent.TenantID, AnonymousFlowID: string(s.Binding.ID), ActorID: p.actor, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, RecordID: string(s.Binding.ID), PolicyID: p.policy, PolicyVersion: p.version, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: input.CorrelationID}
	if !p.matches(b, input.Record) {
		return identity.CommandBinding{}, identity.Command{}, identity.ForbiddenError{}
	}
	command, err := mapPreAuthIssue(b, input.Record)
	return b, command, err
}

func (e *PreAuthIssueExecutor) preAuthCaller(b identity.CommandBinding) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(e.owned.policyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
}

func (e *PreAuthIssueExecutor) preAuthPlan(b identity.CommandBinding, command identity.Command) (kernel.CommandPlan, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, session.ErrUnavailable
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: e.owned.clock.Now().UTC().Truncate(time.Microsecond), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "preauth_transaction", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": "preauth_transaction", "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "standard"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, preAuthIssueOperation(), "preauth_transaction", record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return e.owned.coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: e.owned.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: e.owned.native.Descriptor(), Operation: preAuthIssueOperation()}, SubjectType: "preauth_transaction", Lifecycle: &kernel.LifecyclePlan{EventType: "session.preauth-issued.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard", RetentionPolicyVersion: e.owned.retentionVersion, BindingDigest: digest, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}})
}

// ExecutePreAuthIssue authorizes trusted service scope, then commits the original
// flow, retained native evidence, audit/lifecycle and command receipt atomically.
// Exact replay returns only historical metadata, never a cookie or renewal.
// Changed intent conflicts; cancellation/failed acknowledgement cannot prove
// rollback. Recover the exact original command after Unknown. Earlier deadlines
// win; kernel detached cleanup retains its independently bounded budget.
func (e *PreAuthIssueExecutor) ExecutePreAuthIssue(ctx context.Context, input PreAuthIssueCommand) (identity.CommandResult, error) {
	out, err := e.ExecutePreAuthIssuance(ctx, input)
	return out.Receipt, err
}

// ExecutePreAuthIssuance preserves ExecutePreAuthIssue's atomic execution and
// adds explicit original-versus-historical metadata. Only acquisition of the
// sole coordinator reservation clears Replayed; observing a committed receipt
// never does. Replayed remains true on conflicts, pending observations and
// pre-reservation failures. Cookie delivery also requires exact newly committed
// receipt validation, no error/cancellation and an unexpired original flow.
// Earlier deadlines and detached cleanup budgets match ExecutePreAuthIssue.
func (e *PreAuthIssueExecutor) ExecutePreAuthIssuance(ctx context.Context, input PreAuthIssueCommand) (out session.PreAuthIssueExecution, err error) {
	out.Replayed = true
	entered := false
	var b identity.CommandBinding
	defer func() {
		if recover() != nil {
			err = session.ErrUnavailable
			if entered {
				out.Receipt = unknownPreAuthIssue(b)
				err = identity.UnknownCommitError{CommandID: b.CommandID}
			}
		}
	}()
	if ctx == nil || e == nil || e.owned == nil || e.owned.coordinator == nil {
		return out, session.ErrInvalidInput
	}
	b, command, err := e.preparePreAuth(input)
	if err != nil {
		return out, err
	}
	bounded, stop := context.WithTimeout(ctx, e.owned.maximumDuration)
	defer stop()
	if err = e.owned.allow(bounded, e.preAuthCaller(b)); err != nil {
		return out, err
	}
	plan, err := e.preAuthPlan(b, command)
	if err != nil {
		return out, err
	}
	entered = true
	reservation, receipt, err := e.owned.coordinator.ReserveCommand(bounded, b, command, plan)
	out.Receipt = receipt
	if err != nil || reservation == (kernel.Reservation{}) {
		return out, err
	}
	out.Replayed = false
	work, err := e.owned.coordinator.Begin(bounded, reservation)
	if err != nil {
		out.Receipt = unknownPreAuthIssue(b)
		return out, err
	}
	defer e.owned.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := e.owned.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		out.Receipt, err = e.owned.coordinator.Abort(work, err)
		return out, err
	}
	out.Receipt, err = e.owned.coordinator.Commit(work, provisional)
	return out, err
}

func unknownPreAuthIssue(b identity.CommandBinding) identity.CommandResult {
	return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: preAuthIssueOperation()}}
}

// RecoverPreAuthIssue observes or reconciles one original anonymous-flow command
// under current configured service policy. It accepts no cookie, does not mint
// or renew state, reserve a missing command or infer noncommit from flow absence.
// Restart scope must retain tenant, flow, actor, operation and record exactly.
// Live pending retains its lease; expired pending uses frozen native evidence.
func (e *PreAuthIssueExecutor) RecoverPreAuthIssue(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	if ctx == nil || e == nil || e.owned == nil || e.owned.coordinator == nil || e.owned.native == nil || e.owned.native.preAuthIssue == nil {
		return identity.CommandResult{}, session.ErrInvalidInput
	}
	p := e.owned.native.preAuthIssue
	if q.OperationID != preAuthIssueOperation().OperationID || q.ActorKind != authorization.SubjectServiceAccount || q.ActorID != p.actor || q.UserID != "" || q.AnonymousFlowID == "" || q.RecordID != q.AnonymousFlowID || q.LinkMode != 0 {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, e.owned.maximumDuration)
	defer stop()
	b := identity.CommandBinding{TenantID: q.TenantID, AnonymousFlowID: q.AnonymousFlowID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID}
	return e.owned.coordinator.RecoverFeatureCommand(bounded, q, e.preAuthCaller(b))
}

// Format redacts composition and private correlation for every formatting verb.
func (PreAuthIssueExecutor) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.PreAuthIssueExecutor(redacted)"))
}

// MarshalJSON prevents automatic runtime composition disclosure.
func (PreAuthIssueExecutor) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format redacts borrowed configuration and keys.
func (PreAuthIssueExecutorConfig) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.PreAuthIssueExecutorConfig(redacted)"))
}

// MarshalJSON prevents automatic configuration/key disclosure.
func (PreAuthIssueExecutorConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
