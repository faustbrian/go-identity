//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
)

// This controlled approval owner exercises the original requester's current
// account and epoch in real Work. It does not authenticate either administrator
// or stand in for a durable grant/approval adapter.
type impersonationRequesterPhase struct {
	op             identity.FeatureOperation
	requester      identity.User
	policy         UserAuthorizationAdmission
	approver       identity.User
	approverPolicy UserAuthorizationAdmission
	beforeVersion  uint64
	mode           string
	denied         error
	applied        bool
	final          bool
	scopeChanged   bool
	retained       Work
}

func (*impersonationRequesterPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}
}

func (p *impersonationRequesterPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}

func (*impersonationRequesterPhase) ValidateFeatureCommand(identity.Command, CommandPlan) error {
	return nil
}

func (*impersonationRequesterPhase) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func (p *impersonationRequesterPhase) check(ctx context.Context, w Work, command identity.Command) error {
	before := w.state.binding
	err := w.RequireActiveImpersonationRequester(ctx, p, command, p.requester, p.policy)
	if err == nil && p.approver.ID != "" {
		err = w.RequireActiveImpersonationApprover(ctx, p, command, p.approver, p.approverPolicy)
	}
	p.scopeChanged = p.scopeChanged || w.state.binding != before
	if err != nil {
		p.denied = err
	}
	return err
}

func (p *impersonationRequesterPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.retained = w
	spec, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_requester_guard(command_id) VALUES($1)`, string(spec.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	checking := command
	if p.mode == "reconstructed-command" {
		var err error
		checking, err = identity.NewFeatureCommand(spec)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := p.check(ctx, w, checking); err != nil {
		if p.mode == "ignored-denial" {
			// Work must preserve a denied prerequisite even if its owner ignores it.
			return identity.FeatureReceipt{Operation: p.op, BeforeVersion: p.beforeVersion, AfterVersion: p.beforeVersion + 1}, nil
		}
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: p.op, BeforeVersion: p.beforeVersion, AfterVersion: p.beforeVersion + 1}, nil
}

func (p *impersonationRequesterPhase) CheckFeatureCommit(ctx context.Context, w Work, command identity.Command) error {
	if err := p.check(ctx, w, command); err != nil {
		return err
	}
	p.final = true
	return nil
}

func TestRequireActiveImpersonationRequesterPostgres(t *testing.T) {
	ctx, pool, repository := newAccountAuthorityStore(t)
	migration, err := authority.AuthoritySchemaMigration(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, migration.Up); err != nil {
		t.Fatal("native authorization epoch schema", err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE,no_change boolean,outcome smallint,reason text);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_requester_guard(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"current", "stale-account", "stale-authority", "suspended", "reconstructed-command", "ignored-denial", "approval-approver-version-drift", "start-current", "start-stale-approver", "start-suspended-requester"} {
		t.Run(mode, func(t *testing.T) {
			start := strings.HasPrefix(mode, "start-")
			tenant := identity.TenantID("requester-" + mode)
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'requester','active',3),($1,'approver','active',3),($1,'target','active',3)`, string(tenant)); err != nil {
				t.Fatal(err)
			}
			scope := authority.AuthorityScope{TenantID: authorization.TenantID(tenant), SubjectID: "requester", PolicyNamespace: "administrators"}
			for _, subject := range []authorization.SubjectID{"requester", "approver", "target"} {
				current := scope
				current.SubjectID = subject
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackAuthorizationFixture(tx)
				if _, err := authority.InitializeAuthority(ctx, tx, current, time.Second); err != nil {
					t.Fatal(err)
				}
				if mode == "stale-authority" && subject == "requester" || mode == "start-stale-approver" && subject == "approver" {
					if _, err := authority.AdvanceAuthority(ctx, tx, current, 1, time.Second); err != nil {
						t.Fatal(err)
					}
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "stale-account" || mode == "ignored-denial" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=4 WHERE tenant_id=$1 AND user_id='requester'`, string(tenant)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "suspended" || mode == "start-suspended-requester" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id='requester'`, string(tenant)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "approval-approver-version-drift" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=4 WHERE tenant_id=$1 AND user_id='approver'`, string(tenant)); err != nil {
					t.Fatal(err)
				}
			}
			op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: "identity.impersonation.approve", SchemaID: "impersonation-approve", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			before, actor, event := uint64(1), identity.ActorID("approver"), "impersonation.approved.v1"
			if start {
				op.OperationID, op.SchemaID = "identity.impersonation.start", "impersonation-start"
				before, actor, event = 2, "requester", "impersonation.started.v1"
			}
			phase := &impersonationRequesterPhase{op: op, requester: identity.User{ID: "requester", TenantID: tenant, Status: identity.StatusActive, Version: 3}, policy: UserAuthorizationAdmission{Scope: scope, Version: 1}, mode: mode, beforeVersion: before}
			if start || mode == "approval-approver-version-drift" {
				phase.approver = identity.User{ID: "approver", TenantID: tenant, Status: identity.StatusActive, Version: 3}
				phase.approverPolicy = UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: scope.TenantID, SubjectID: "approver", PolicyNamespace: scope.PolicyNamespace}, Version: 1}
			}
			registry, err := NewContributorRegistry([]Contributor{repository, &accountLinkSQLAudit{}, &recoveryLifecyclePhase{}, phase})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			grant, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			binding := identity.CommandBinding{CommandID: id, TenantID: tenant, UserID: "target", ActorID: actor, ActorKind: authorization.SubjectUser, RecordID: string(grant), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "impersonation-admin", PolicyVersion: 1, CorrelationID: string(id)}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{
				{Name: "impersonation.requester-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "requester"}},
				{Name: "impersonation.requester-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 3}},
				{Name: "impersonation.requester-namespace", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "administrators"}},
				{Name: "impersonation.requester-authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}},
				{Name: "impersonation.approver-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "approver"}},
				{Name: "impersonation.approver-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 3}},
				{Name: "impersonation.approver-namespace", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "administrators"}},
				{Name: "impersonation.approver-authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := securityMutationAudit(ctx, binding, before, before+1, time.Now().UTC().Truncate(time.Microsecond), "committed", op.OperationID, "impersonation", binding.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := FeatureAuditBindingDigest(binding, op, "impersonation", seed)
			if err != nil {
				t.Fatal(err)
			}
			declaration := CommandPlan{Contributors: registry.Descriptors(), SubjectType: "impersonation", Feature: &FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, Lifecycle: &LifecyclePlan{EventType: event, BeforeVersion: before, AfterVersion: before + 1}, Audits: []AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			plan, err := coordinator.PrepareCommandPlan(binding, command, declaration)
			if err != nil {
				t.Fatal("prepare original requester-bound approval", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, binding, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			result, applyErr := coordinator.ApplyFeature(ctx, work, command)
			result, commitErr := coordinator.Commit(work, result)
			if phase.scopeChanged || work.state.binding != binding {
				t.Fatal("requester lookup replaced the approver or target in original Work")
			}
			var effects, audits, noChangeAudits, events int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_requester_guard WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1 AND no_change),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(id)).Scan(&effects, &audits, &noChangeAudits, &events); err != nil {
				t.Fatal(err)
			}
			if mode == "current" || mode == "start-current" {
				if applyErr != nil || commitErr != nil || result.Outcome != identity.CommitOutcomeCommitted || !phase.applied || !phase.final || effects != 1 || audits != 1 || noChangeAudits != 0 || events != 1 {
					t.Fatal("current original requester was not admitted atomically", result.Outcome, effects, audits, events, applyErr, commitErr)
				}
			} else {
				var forbidden identity.ForbiddenError
				var invalid identity.InvalidInputError
				denied := errors.As(phase.denied, &forbidden)
				if mode == "reconstructed-command" {
					denied = errors.As(phase.denied, &invalid)
				}
				if !denied || applyErr == nil || result.Outcome != identity.CommitOutcomeNotCommitted || phase.applied || phase.final || effects != 0 || audits != 1 || noChangeAudits != 1 || events != 0 {
					t.Fatal("lost requester authority or reconstructed command did not roll back", result.Outcome, effects, audits, events, phase.denied, applyErr, commitErr)
				}
			}
			if err := phase.retained.RequireActiveImpersonationRequester(ctx, phase, command, phase.requester, phase.policy); err == nil {
				t.Fatal("closed Work retained requester authority")
			}
		})
	}
}
