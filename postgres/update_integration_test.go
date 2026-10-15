//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testAdministrativeUpdates(t *testing.T, ctx context.Context, pool *database.Pool) {
	schema := storageSchema()
	schema.ID = "administrative-fields"
	schema.Fields[0].InputPermission = identity.FieldReadWrite
	schema.Fields[3].OutputPermission = identity.FieldDenied
	// The administrative feature must not depend on enabling self-profile reads.
	repo, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{schema}})
	if err != nil {
		t.Fatal(err)
	}
	audits, effects := &recoveryAuditPhase{}, &recoveryLifecyclePhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, audits, effects})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	creationOwner, err := NewCreationUnitOfWork(c, repo, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewUserUpdateUnitOfWork(c, repo, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	allow := queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	config := identity.UserCreationConfig{Query: identity.UserQueryConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "policy", PolicyVersion: 1, RedactionReasons: []identity.PolicyReason{"visible"}, ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil }}, Schema: schema, Normalize: func(_ context.Context, _ identity.NormalizationPolicy, s identity.AttributeScalar) (identity.AttributeScalar, error) {
		return s, nil
	}, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil }}
	var withhold bool
	redact := func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		if withhold {
			return identity.RedactionPolicyDecision{}, nil
		}
		return identity.RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "policy", PolicyVersion: 1, Reason: "visible"}, nil
	}
	creation, err := identity.NewUserCreationService(creationOwner, allow, redact, config)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewUserUpdateAdminService(repo, owner, allow, redact, config)
	if err != nil {
		t.Fatal(err)
	}
	newID := func(t *testing.T) identity.CommandID {
		t.Helper()
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		return id
	}
	newRequest := func(t *testing.T) identity.UserUpdateAdminRequest {
		t.Helper()
		b := codecBinding()
		b.CommandID = newID(t)
		id, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		b.UserID = identity.UserID(id)
		_, dc := queryInputs(b)
		dc.PolicyRevision = 1
		result, e := creation.UserCreate(ctx, identity.UserCreateRequest{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, SchemaVersion: 1, Fields: storageValues(), ActorScope: dc, CorrelationID: b.CorrelationID})
		if e != nil || result.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("administrative fixture creation", e)
		}
		dc.Request.Action = "identity.user.update-admin"
		return identity.UserUpdateAdminRequest{CommandID: newID(t), TenantID: b.TenantID, UserID: b.UserID, ExpectedVersion: 1, SchemaVersion: 1, Fields: []identity.AttributeUpdate{{Name: "flag", Value: identity.AttributeValue{Kind: identity.AttributeBool, Scalar: identity.AttributeScalar{Kind: identity.AttributeBool, Bool: true}}}}, ActorScope: dc, CorrelationID: b.CorrelationID}
	}
	state := func(t *testing.T, req identity.UserUpdateAdminRequest) (identity.User, []identity.AttributeUpdate) {
		t.Helper()
		user, e := repo.Get(ctx, identity.GetUserQuery{TenantID: req.TenantID, UserID: req.UserID})
		if e != nil {
			t.Fatal(e)
		}
		var data []byte
		if e := pool.Raw().QueryRow(ctx, `SELECT document FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID)).Scan(&data); e != nil {
			t.Fatal(e)
		}
		values, e := decodeAttributeDocument(schema, data)
		if e != nil {
			t.Fatal(e)
		}
		return user, values
	}
	counts := func(t *testing.T, req identity.UserUpdateAdminRequest, wantAudit, wantEffect int) {
		t.Helper()
		var a, e int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(req.CommandID)).Scan(&a, &e); err != nil || a != wantAudit || e != wantEffect {
			t.Fatal("administrative phase effects", a, e, err)
		}
	}
	t.Run("partial values and original replay recovery", func(t *testing.T) {
		req := newRequest(t)
		first, err := service.UserUpdateAdmin(ctx, req)
		if err != nil || first.CommitOutcome != identity.CommitOutcomeCommitted || first.Version != 2 {
			t.Fatal("administrative public update", err)
		}
		user, values := state(t, req)
		want := storageValues()
		want[1].Value.Scalar.Bool = true
		if user.Version != 2 || !reflect.DeepEqual(values, want) {
			t.Fatal("administrative partial update lost omitted values")
		}
		counts(t, req, 1, 1)
		again, err := service.UserUpdateAdmin(ctx, req)
		if err != nil || again != first {
			t.Fatal("administrative replay changed receipt", err)
		}
		next := req
		next.CommandID, next.ExpectedVersion = newID(t), 2
		next.Fields = storageValues()[:1]
		if updated, e := service.UserUpdateAdmin(ctx, next); e != nil || updated.Version != 3 {
			t.Fatal("read-write field replacement", e)
		}
		recovered, err := service.RecoverUserUpdateAdmin(ctx, identity.UserUpdateAdminRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
		if err != nil || recovered != first {
			t.Fatal("administrative recovery changed receipt", err)
		}
		withhold = true
		withheld, e := service.RecoverUserUpdateAdmin(ctx, identity.UserUpdateAdminRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
		withhold = false
		var forbidden identity.ForbiddenError
		if !errors.As(e, &forbidden) || withheld.CommitOutcome != identity.CommitOutcomeCommitted || withheld.User.ID != "" {
			t.Fatal("administrative historic receipt bypassed current redaction", e)
		}
		changed := req
		changed.Fields = storageValues()[:1]
		conflict, err := service.UserUpdateAdmin(ctx, changed)
		var conflicting identity.ConflictError
		if conflict.CommitOutcome != identity.CommitOutcomeConflict || !errors.As(err, &conflicting) {
			t.Fatal("different intent reused command", err)
		}
		counts(t, req, 1, 1)
		current, values := state(t, req)
		if current.Version != 3 || !reflect.DeepEqual(values, want) {
			t.Fatal("historical recovery remutated current fields")
		}
	})
	t.Run("nonterminal status preserved and terminal rows denied", func(t *testing.T) {
		for _, status := range []identity.Status{identity.StatusBanned, identity.StatusSuspended, identity.StatusDeleted, identity.StatusAnonymized} {
			req := newRequest(t)
			if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status=$3 WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID), string(status)); e != nil {
				t.Fatal(e)
			}
			got, e := service.UserUpdateAdmin(ctx, req)
			if status == identity.StatusDeleted || status == identity.StatusAnonymized {
				var denied identity.ForbiddenError
				if !errors.As(e, &denied) || got.User.ID != "" {
					t.Fatal("terminal administrative update admitted", e)
				}
				counts(t, req, 0, 0)
			} else {
				if e != nil || got.User.Status != status || got.Version != 2 {
					t.Fatal("administrative attributes changed lifecycle status", e)
				}
				counts(t, req, 1, 1)
			}
		}
	})
	t.Run("service actor and full width successor remain exact", func(t *testing.T) {
		req := newRequest(t)
		req.ActorScope.Request.Subject = authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "administrative-service"}
		req.ExpectedVersion = ^uint64(0) - 1
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=$3::numeric WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID), strconv.FormatUint(req.ExpectedVersion, 10)); e != nil {
			t.Fatal(e)
		}
		got, e := service.UserUpdateAdmin(ctx, req)
		if e != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Version != ^uint64(0) {
			t.Fatal("service administrative successor lost uint64 precision", e)
		}
		again, e := service.RecoverUserUpdateAdmin(ctx, identity.UserUpdateAdminRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
		if e != nil || again != got {
			t.Fatal("full width historical service receipt changed", e)
		}
		counts(t, req, 1, 1)
	})
	t.Run("rollback panic and cancellation preserve all original values", func(t *testing.T) {
		for _, mode := range []string{"outbox-error", "outbox-panic", "audit-error", "cancelled"} {
			req := newRequest(t)
			beforeUser, beforeValues := state(t, req)
			effects.fail, effects.panicAfterWrite, audits.fail = mode == "outbox-error", mode == "outbox-panic", mode == "audit-error"
			run := ctx
			if mode == "cancelled" {
				cancelled, stop := context.WithCancel(ctx)
				stop()
				run = cancelled
			}
			got, e := service.UserUpdateAdmin(run, req)
			effects.fail, effects.panicAfterWrite, audits.fail = false, false, false
			if e == nil || got.CommitOutcome == identity.CommitOutcomeCommitted || got.User.ID != "" {
				t.Fatal("administrative failure returned success", mode)
			}
			afterUser, afterValues := state(t, req)
			if afterUser != beforeUser || !reflect.DeepEqual(afterValues, beforeValues) {
				t.Fatal("administrative failure retained domain prefix", mode)
			}
			if mode == "audit-error" || mode == "cancelled" {
				counts(t, req, 0, 0)
			} else {
				counts(t, req, 1, 0)
			}
		}
	})
	t.Run("same command concurrent retries and different command CAS", func(t *testing.T) {
		req := newRequest(t)
		var group sync.WaitGroup
		results := make(chan identity.UserUpdateAdminResult, 8)
		failures := make(chan error, 8)
		for range 8 {
			group.Go(func() { result, e := service.UserUpdateAdmin(ctx, req); results <- result; failures <- e })
		}
		group.Wait()
		close(results)
		close(failures)
		for e := range failures {
			var pending identity.InProgressError
			if e != nil && !errors.As(e, &pending) {
				t.Fatal("concurrent administrative replay", e)
			}
		}
		committedRetries := 0
		for got := range results {
			if got.CommitOutcome == identity.CommitOutcomeCommitted && got.Version == 2 {
				committedRetries++
				continue
			}
			if got.CommitOutcome != identity.CommitOutcomeInProgress || got.User.ID != "" {
				t.Fatal("concurrent administrative receipt changed")
			}
		}
		if committedRetries == 0 {
			t.Fatal("no administrative retry completed")
		}
		recovered, e := service.RecoverUserUpdateAdmin(ctx, identity.UserUpdateAdminRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
		if e != nil || recovered.Version != 2 || recovered.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("concurrent pending retry did not resolve original receipt", e)
		}
		counts(t, req, 1, 1)
		user, _ := state(t, req)
		if user.Version != 2 {
			t.Fatal("same command bumped version twice")
		}
		a := newRequest(t)
		b := a
		b.CommandID = newID(t)
		b.Fields = storageValues()[1:2]
		out := make(chan identity.UserUpdateAdminResult, 2)
		errout := make(chan error, 2)
		for _, input := range []identity.UserUpdateAdminRequest{a, b} {
			group.Go(func() { result, e := service.UserUpdateAdmin(ctx, input); out <- result; errout <- e })
		}
		group.Wait()
		close(out)
		close(errout)
		committed, aborted := 0, 0
		for got := range out {
			if got.CommitOutcome == identity.CommitOutcomeCommitted {
				committed++
			} else if got.CommitOutcome == identity.CommitOutcomeNotCommitted {
				aborted++
			} else {
				t.Fatal("unexpected CAS outcome", got.CommitOutcome)
			}
		}
		if committed != 1 || aborted != 1 {
			t.Fatal("competing administrative commands both won")
		}
		for e := range errout {
			var aborted identity.NotCommittedError
			if e != nil && !errors.As(e, &aborted) {
				t.Fatal(e)
			}
		}
		for _, input := range []identity.UserUpdateAdminRequest{a, b} {
			var n int
			if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1`, string(input.CommandID)).Scan(&n); e != nil || n != 1 {
				t.Fatal("CAS attempt lacks terminal audit", e)
			}
		}
		user, _ = state(t, a)
		if user.Version != 2 {
			t.Fatal("different commands bypassed CAS")
		}
	})
	t.Run("expired recovery needs unchanged aggregate and all frozen evidence", func(t *testing.T) {
		for _, changed := range []bool{false, true} {
			req := newRequest(t)
			binding := codecBinding()
			binding.CommandID, binding.UserID, binding.OperationID, binding.SchemaID = req.CommandID, req.UserID, "identity.user.update-admin", schema.ID
			command, e := identity.NewUserUpdateCommand(identity.UpdateUserCommand{Binding: binding, ExpectedVersion: 1, Attributes: req.Fields})
			if e != nil {
				t.Fatal(e)
			}
			record, e := kernelMutationAudit(ctx, binding, 1, time.Now().UTC().Truncate(time.Microsecond), "committed")
			if e != nil {
				t.Fatal(e)
			}
			digest, e := AuditBindingDigest(binding, record)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := c.PrepareCommandPlan(binding, command, CommandPlan{Contributors: registry.Descriptors(), Audits: []AuditPlan{{EventType: "identity.user.update", SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &LifecyclePlan{EventType: "identity.updated.v1", BeforeVersion: 1, AfterVersion: 2}})
			if e != nil {
				t.Fatal(e)
			}
			_, pending, e := c.ReserveCommand(ctx, binding, command, plan)
			if e != nil || pending.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("administrative reservation", e)
			}
			id, e := base64.RawURLEncoding.DecodeString(string(req.CommandID))
			if e != nil {
				t.Fatal(e)
			}
			if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); e != nil {
				t.Fatal(e)
			}
			if changed {
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=2 WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID)); e != nil {
					t.Fatal(e)
				}
			}
			got, e := service.RecoverUserUpdateAdmin(ctx, identity.UserUpdateAdminRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
			if changed {
				var inProgress identity.InProgressError
				if got.CommitOutcome != identity.CommitOutcomeInProgress || !errors.As(e, &inProgress) {
					t.Fatal("changed domain evidence invented receipt", got.CommitOutcome, e)
				}
				counts(t, req, 0, 0)
			} else {
				var notCommitted identity.NotCommittedError
				if got.CommitOutcome != identity.CommitOutcomeNotCommitted || !errors.As(e, &notCommitted) {
					t.Fatal("negative administrative recovery", got.CommitOutcome, e)
				}
				counts(t, req, 1, 0)
			}
		}
	})
}
