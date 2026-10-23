//go:build integration

package postgres

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This contributor opens a genuine registered token Work to exercise only the
// session owner's predicate. It always aborts; it issues no OAuth credential.
type oidcTokenFencePhase struct {
	effect   *OIDCEndSessionEffect
	command  identity.Command
	source   session.Session
	op       identity.FeatureOperation
	reached  bool
	observed error
}

func (*oidcTokenFencePhase) Descriptor() kernel.ContributorDescriptor { return oidcEndSessionOwner() }
func (p *oidcTokenFencePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (p *oidcTokenFencePhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return session.ErrInvalidSessionCommand
	}
	return nil
}
func (p *oidcTokenFencePhase) ApplyFeature(ctx context.Context, w kernel.Work, _ identity.Command) (identity.FeatureReceipt, error) {
	p.reached = true
	p.observed = p.effect.RequireNotRevoked(ctx, w, p, p.source)
	// No token mutation belongs to this owner-component test. Force rollback
	// after recording the predicate result, including the allowed control.
	return identity.FeatureReceipt{}, identity.UnavailableError{}
}
func (*oidcTokenFencePhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, identity.UnavailableError{}
}

func oidcOwnerTestPlan(t *testing.T, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, owner kernel.ContributorDescriptor, command identity.Command, event, lifecycle string, before uint64) kernel.CommandPlan {
	t.Helper()
	f, _ := command.Feature()
	b := f.Binding
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: event, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(before, 10), "aggregate.after_version": strconv.FormatUint(before+1, 10), "retention.class": "standard"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, "session", seed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: owner, Operation: f.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: lifecycle, BeforeVersion: before, AfterVersion: before + 1}, Audits: []kernel.AuditPlan{{EventType: event, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "standard", BindingDigest: digest}}})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testOIDCTokenFence(t *testing.T, ctx context.Context, pool *database.Pool, c IssueExecutorConfig, effect *OIDCEndSessionEffect, source session.Session, denied bool, scope ...string) {
	t.Helper()
	s, _ := source.Bindings()
	op := identity.FeatureOperation{Owner: "oauth-server", OperationID: "identity.oauth-server.token", SchemaID: "identity.oauth-server.token.public-password-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := revokeBinding()
	b.CommandID, _ = identity.NewCommandID()
	b.TenantID, b.UserID, b.ActorID, b.RecordID = s.TenantID, s.UserID, identity.ActorID(s.UserID), s.SessionID
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	if len(scope) != 0 {
		switch scope[0] {
		case "foreign-user":
			b.UserID, b.ActorID = "foreign-token-user", "foreign-token-user"
		case "wrong-schema":
			op.SchemaID += ".other"
			b.SchemaID = op.SchemaID
		default:
			t.Fatal("unknown token-Work fixture scope")
		}
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "fixture.predicate", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	p := &oidcTokenFencePhase{effect: effect, command: command, source: source, op: op}
	domain, _ := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	a, _ := auditpg.NewIdentityContributor(auditpg.Config{})
	l, _ := lifecyclepg.NewContributor()
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, a, l, p})
	if err != nil {
		t.Fatal(err)
	}
	configuration := c.Coordinator
	query := kernel.CommandQueryPolicy{Authorization: c.Authorization, Clock: c.Clock, PolicyVersion: c.PolicyVersion}
	configuration.QueryPolicy, configuration.AdmissionPolicy = &query, &query
	coordinator, err := kernel.NewCoordinator(pool, registry, configuration)
	if err != nil {
		t.Fatal(err)
	}
	plan := oidcOwnerTestPlan(t, coordinator, registry, p.Descriptor(), command, "identity.oauth_server.token", "oauth.token.issued.v1", 0)
	reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	w, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = coordinator.ApplyFeature(ctx, w, command)
	_, _ = coordinator.Abort(w, identity.UnavailableError{})
	var forbidden identity.ForbiddenError
	denialMatches := errors.As(p.observed, &forbidden)
	if len(scope) != 0 {
		denialMatches = errors.Is(p.observed, session.ErrInvalidSessionCommand)
	}
	if !p.reached || denied && !denialMatches || !denied && p.observed != nil {
		t.Fatal("real token-Work RP disposition mismatch", denied, p.reached, p.observed)
	}
}

func testOIDCOrdinarySignoutFence(t *testing.T, ctx context.Context, pool *database.Pool, c IssueExecutorConfig, executor *IssueExecutor, effect *OIDCEndSessionEffect, source session.Session) {
	t.Helper()
	s, _ := source.Bindings()
	op := session.RevokeOneOperation()
	b := revokeBinding()
	b.CommandID, _ = identity.NewCommandID()
	b.TenantID, b.UserID, b.ActorID, b.RecordID = s.TenantID, s.UserID, identity.ActorID(s.UserID), s.SessionID
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	native, err := session.NewRevokeOneCommand(b, source)
	if err != nil {
		t.Fatal(err)
	}
	command, err := MapCommand(native)
	if err != nil {
		t.Fatal(err)
	}
	plan := oidcOwnerTestPlan(t, executor.coordinator, executor.registry, executor.native.Descriptor(), command, "identity.session.revoke", "session.revoked.v1", s.Version)
	reservation, _, err := executor.coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	w, err := executor.coordinator.Begin(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.coordinator.Abort(w, identity.UnavailableError{})
	provisional, err := executor.coordinator.ApplyFeature(ctx, w, command)
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.coordinator.Commit(w, provisional)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("ordinary signout prerequisite", err, result.Outcome)
	}
	testOIDCTokenFence(t, ctx, pool, c, effect, source, false)
}
