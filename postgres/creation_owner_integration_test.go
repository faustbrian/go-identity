//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testCreationOwner(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	auditPhase, lifecyclePhase := &domainAuditPhase{}, &domainLifecyclePhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, auditPhase, lifecyclePhase})
	if err != nil {
		t.Fatal(err)
	}
	config := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}
	coordinator, err := NewCoordinator(pool, registry, config)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewCreationUnitOfWork(coordinator, repo, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	var denyRedaction bool
	service, err := identity.NewUserCreationService(owner, queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}),
		func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			if denyRedaction {
				return identity.RedactionPolicyDecision{}, nil
			}
			return identity.RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "policy", PolicyVersion: 1, Reason: "visible"}, nil
		}, identity.UserCreationConfig{Query: identity.UserQueryConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "policy", PolicyVersion: 1, RedactionReasons: []identity.PolicyReason{"visible"}, ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil }}, Schema: storageSchema(), Normalize: func(context.Context, identity.NormalizationPolicy, identity.AttributeScalar) (identity.AttributeScalar, error) {
			panic("unexpected normalization")
		}, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	request := func() identity.UserCreateRequest {
		b := codecBinding()
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		id, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		b.UserID = identity.UserID(id)
		_, caller := queryInputs(b)
		caller.PolicyRevision = 1
		return identity.UserCreateRequest{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, SchemaVersion: 1, Fields: storageValues(), ActorScope: caller, CorrelationID: b.CorrelationID}
	}
	count := func(req identity.UserCreateRequest, users, audits, effects int) {
		t.Helper()
		var u, a, e int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3)`, string(req.TenantID), string(req.UserID), string(req.CommandID)).Scan(&u, &a, &e); err != nil || u != users || a != audits || e != effects {
			t.Fatal("wrong owned creation effects", u, a, e, err)
		}
	}
	t.Run("consistent public self-profile reads", func(t *testing.T) { testProfileReads(t, ctx, pool, repo, owner, service, request) })
	t.Run("durable public self-profile updates", func(t *testing.T) { testProfileUpdates(t, ctx, pool) })
	t.Run("public creation recovery replay and redaction", func(t *testing.T) {
		req := request()
		first, err := service.UserCreate(ctx, req)
		if err != nil || first.CommitOutcome != identity.CommitOutcomeCommitted || first.User.ID != req.UserID {
			t.Fatal("public creation failed", err)
		}
		count(req, 1, 1, 1)
		recovery := identity.UserCreateRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope}
		got, err := service.RecoverUserCreate(ctx, recovery)
		if err != nil || got != first {
			t.Fatal("lost-response recovery changed historical result", err)
		}
		replay, err := service.UserCreate(ctx, req)
		if err != nil || replay != first {
			t.Fatal("exact replay changed result", err)
		}
		count(req, 1, 1, 1)
		config.CurrentFingerprintKeyVersion = 2
		config.RetainedFingerprintKeys[2] = [32]byte{2}
		rotated, e := NewCoordinator(pool, registry, config)
		if e != nil {
			t.Fatal(e)
		}
		rotatedOwner, e := NewCreationUnitOfWork(rotated, repo, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
		if e != nil {
			t.Fatal(e)
		}
		raw, e := rotatedOwner.Recover(ctx, identity.RecoveryQuery{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorID: identity.ActorID(req.ActorScope.Request.Subject.ID), ActorKind: req.ActorScope.Request.Subject.Kind, OperationID: "identity.user.create"})
		if e != nil || raw.Binding.PolicyVersion != 1 || raw.AuditEventID == "" {
			t.Fatal("historical recovery failed", e)
		}
		command, e := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: raw.Binding, Status: identity.StatusActive, Attributes: req.Fields})
		if e != nil {
			t.Fatal(e)
		}
		again, e := rotatedOwner.Execute(ctx, command)
		if e != nil || again != raw {
			t.Fatal("retained-key replay changed receipt", e)
		}
		req.Fields[0].Value.Scalar.String = "changed"
		got, err = service.UserCreate(ctx, req)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || got.CommitOutcome != identity.CommitOutcomeConflict || got.User != (identity.User{}) {
			t.Fatal("changed fields not classified conflict", err)
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned',version=2 WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID)); e != nil {
			t.Fatal(e)
		}
		got, err = service.RecoverUserCreate(ctx, recovery)
		if err != nil || got != first {
			t.Fatal("current user replaced historical creation", err)
		}
		denyRedaction = true
		got, err = service.RecoverUserCreate(ctx, recovery)
		denyRedaction = false
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || got.CommitOutcome != identity.CommitOutcomeCommitted || got.User != (identity.User{}) {
			t.Fatal("recovery bypassed current redaction", err)
		}
		recovery.ActorScope.Request.Subject.ID = "wrong"
		got, err = service.RecoverUserCreate(ctx, recovery)
		if err == nil || got.User != (identity.User{}) {
			t.Fatal("foreign actor recovered payload")
		}
		count(req, 1, 1, 1)
	})
	t.Run("rollback terminal audit and panic cleanup", func(t *testing.T) {
		for _, mode := range []string{"outbox-error", "outbox-panic", "audit-error"} {
			req := request()
			lifecyclePhase.fail = mode == "outbox-error"
			lifecyclePhase.panicAfterWrite = mode == "outbox-panic"
			auditPhase.fail = mode == "audit-error"
			got, err := service.UserCreate(ctx, req)
			lifecyclePhase.fail = false
			lifecyclePhase.panicAfterWrite = false
			auditPhase.fail = false
			if err == nil || got.User != (identity.User{}) || got.CommitOutcome == identity.CommitOutcomeCommitted {
				t.Fatal("failed participant committed", mode)
			}
			if mode == "audit-error" {
				count(req, 0, 0, 0)
			} else {
				count(req, 0, 1, 0)
				if got.CommitOutcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("proved rollback lost audited outcome", mode)
				}
			}
			connection, e := pool.Acquire(ctx)
			if e != nil {
				t.Fatal("panic leaked pool ownership", e)
			}
			connection.Release()
		}
	})
	t.Run("same command concurrent owned execution", func(t *testing.T) {
		req := request()
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make(chan identity.UserCreateResult, 8)
		failures := make(chan error, 8)
		for range 8 {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; r, e := service.UserCreate(ctx, req); results <- r; failures <- e }()
		}
		close(start)
		wg.Wait()
		close(results)
		close(failures)
		committed := 0
		for r := range results {
			if r.CommitOutcome == identity.CommitOutcomeCommitted {
				committed++
			} else if r.CommitOutcome != identity.CommitOutcomeInProgress {
				t.Fatal("contention changed durable observation", r.CommitOutcome)
			}
		}
		for e := range failures {
			var busy identity.InProgressError
			if e != nil && !errors.As(e, &busy) {
				t.Fatal("contention returned wrong classification", e)
			}
		}
		if committed == 0 {
			t.Fatal("no owned creation completed")
		}
		count(req, 1, 1, 1)
	})
	t.Run("pending primary recovery cannot take ownership", func(t *testing.T) {
		req := request()
		binding := codecBinding()
		binding.CommandID, binding.UserID = req.CommandID, req.UserID
		command, e := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: binding, Status: identity.StatusActive, Attributes: req.Fields})
		if e != nil {
			t.Fatal(e)
		}
		record, e := creationAudit(ctx, binding, time.Now().UTC().Truncate(time.Microsecond), "committed")
		if e != nil {
			t.Fatal(e)
		}
		digest, e := AuditBindingDigest(binding, record)
		if e != nil {
			t.Fatal(e)
		}
		plan, e := coordinator.PrepareCommandPlan(binding, command, CommandPlan{Contributors: registry.Descriptors(), Audits: []AuditPlan{{EventType: "identity.user.create", SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}})
		if e != nil {
			t.Fatal(e)
		}
		_, result, e := coordinator.ReserveCommand(ctx, binding, command, plan)
		if e != nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("pending reservation failed", e)
		}
		key, e := base64.RawURLEncoding.DecodeString(string(req.CommandID))
		if e != nil {
			t.Fatal(e)
		}
		query := creationRecoveryQuery(binding)
		snapshot := func() string {
			t.Helper()
			var row string
			if e := pool.Raw().QueryRow(ctx, `SELECT row_to_json(j)::text FROM identity.commands j WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3`, string(binding.TenantID), binding.OperationID, key).Scan(&row); e != nil {
				t.Fatal(e)
			}
			return row
		}
		// Use the fixed binary ID representation, not a text normalization path.
		for _, expired := range []bool{false, true} {
			if expired {
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3`, string(binding.TenantID), binding.OperationID, key); e != nil {
					t.Fatal(e)
				}
			}
			before := snapshot()
			observed, e := owner.Recover(ctx, query)
			if e != nil || observed.Outcome != identity.CommitOutcomeInProgress || observed.RetryAfter <= 0 || snapshot() != before {
				t.Fatal("recovery mutated pending ownership", e)
			}
		}
		query.ActorID = "foreign"
		observed, e := owner.Recover(ctx, query)
		if e == nil || observed != (identity.CommandResult{}) {
			t.Fatal("foreign pending scope disclosed")
		}
		count(req, 0, 0, 0)
	})
	t.Run("new command cannot create existing user", func(t *testing.T) {
		req := request()
		if _, e := service.UserCreate(ctx, req); e != nil {
			t.Fatal(e)
		}
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		req.CommandID = id
		got, e := service.UserCreate(ctx, req)
		var notCommitted identity.NotCommittedError
		if !errors.As(e, &notCommitted) || got.CommitOutcome != identity.CommitOutcomeNotCommitted || got.User != (identity.User{}) {
			t.Fatal("uniqueness failure lost audited terminal outcome", e)
		}
		count(req, 1, 1, 0)
	})
}
