//go:build integration

package passwordpostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// This native test participant exercises the real MFA transaction seam, not a
// complete reset service: it issues no token and replaces no credential.
type resetFactorPhase struct {
	command  identity.Command
	user     identity.UserID
	expected uint64
	mode     string
	pool     *database.Pool
	checked  bool
}

func (*resetFactorPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *resetFactorPhase) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.Feature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *resetFactorPhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *resetFactorPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	owner := kernel.FeatureExecutionContributor(p)
	if p.mode == "foreign-command" {
		s, _ := c.Feature()
		c, _ = identity.NewFeatureCommand(s)
	}
	if p.mode == "foreign-participant" {
		owner = &resetFactorPhase{command: p.command}
	}
	state, err := mfapg.RequireEmailRecovery(ctx, w, owner, c, p.user, p.expected)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.checked = state.Version() == 1
	if p.mode == "locked" {
		// The competing transaction is bounded and uses another connection.
		// Its lock timeout proves this authoritative read retained the fence.
		tx, err := p.pool.Raw().Begin(ctx)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout='50ms'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
		_, err = tx.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, string(p.user))
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
	}
	if p.mode == "rollback" {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	s, _ := c.Feature()
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (*resetFactorPhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func testResetFactorAuthority(t *testing.T, ctx context.Context, pool *database.Pool, directory *kernel.Repository) {
	t.Helper()
	var selected string
	if err := pool.Raw().QueryRow(ctx, `SELECT user_id FROM identity_mfa.factor_authorities WHERE tenant_id=$1 ORDER BY user_id LIMIT 1`, signinTestTenant).Scan(&selected); err != nil {
		t.Fatal("genuine signup factor authority unavailable", err)
	}
	for _, mode := range []string{"known-empty", "locked", "unknown", "enrolled", "stale-generation", "foreign-command", "foreign-participant", "rollback"} {
		t.Run("factor-"+mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=1,active_factors=0 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, selected); err != nil {
				t.Fatal(err)
			}
			if mode == "enrolled" || mode == "stale-generation" {
				active := 0
				if mode == "enrolled" {
					active = 1
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=$3 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, selected, active); err != nil {
					t.Fatal(err)
				}
			}
			id, _ := identity.NewCommandID()
			op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-request", SchemaID: "password-reset-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			b := identity.CommandBinding{CommandID: id, TenantID: signinTestTenant, AnonymousFlowID: string(id), ActorID: signinTestActor, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "reset", PolicyVersion: 1, CorrelationID: string(id)}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "request", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "factor-authority-test"}}}})
			if err != nil {
				t.Fatal(err)
			}
			p := &resetFactorPhase{command: command, user: identity.UserID(selected), expected: 1, mode: mode, pool: pool}
			if mode == "unknown" {
				p.user = signinTestUser
				p.expected = 0
			}
			audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
			if err != nil {
				t.Fatal(err)
			}
			outbox, err := lifecyclepg.NewContributor()
			if err != nil {
				t.Fatal(err)
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, audits, outbox, p})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "user", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, op, "user", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, SubjectType: "user", Lifecycle: &kernel.LifecyclePlan{EventType: "password.reset-requested.v1"}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if err != nil {
				t.Fatal("factor plan", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			w, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			result, err := coordinator.ApplyFeature(ctx, w, command)
			if err == nil {
				result, err = coordinator.Commit(w, result)
			} else {
				result, _ = coordinator.Abort(w, err)
			}
			want := mode == "known-empty" || mode == "locked"
			if want && (err != nil || !p.checked || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("known-empty factor fence failed", err)
			}
			if !want && (err == nil || result.Outcome != identity.CommitOutcomeNotCommitted) {
				t.Fatal("unsafe factor state admitted")
			}
		})
	}
}
