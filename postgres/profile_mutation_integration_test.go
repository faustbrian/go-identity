//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testProfileUpdates(t *testing.T, ctx context.Context, pool *database.Pool) {
	schema := storageSchema()
	schema.ID = "profile-self"
	for i := range schema.Fields {
		schema.Fields[i].WriteAuthorization = identity.FieldWriteSelf
	}
	repo, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{schema}, ProfileSchema: ProfileSchemaRef{ID: schema.ID, Version: 1}})
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
	owner, err := NewProfileUnitOfWork(c, repo, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	authorize := queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	var hide bool
	redact := func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		d := identity.RedactionPolicyDecision{PolicyID: "policy", PolicyVersion: 1, Reason: "visible"}
		for _, f := range in.Fields {
			if hide && f.Value == "name" {
				d.RedactedFields = append(d.RedactedFields, f)
			} else {
				d.VisibleFields = append(d.VisibleFields, f)
			}
		}
		return d, nil
	}
	config := identity.UserCreationConfig{Query: identity.UserQueryConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "policy", PolicyVersion: 1, RedactionReasons: []identity.PolicyReason{"visible"}, ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil }}, Schema: schema, Normalize: func(_ context.Context, _ identity.NormalizationPolicy, s identity.AttributeScalar) (identity.AttributeScalar, error) {
		return s, nil
	}, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil }}
	creation, err := identity.NewUserCreationService(creationOwner, authorize, redact, config)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewProfileService(repo, owner, authorize, redact, identity.ProfileConfig{Fields: config, AllowedImageOrigins: []string{"https://images.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	newID := func() identity.CommandID {
		t.Helper()
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		return id
	}
	newUser := func() identity.ProfileUpdateRequest {
		t.Helper()
		b := codecBinding()
		b.CommandID = newID()
		id, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		b.UserID = identity.UserID(id)
		_, dc := queryInputs(b)
		dc.PolicyRevision = 1
		dc.Request.Subject = authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}
		created, e := creation.UserCreate(ctx, identity.UserCreateRequest{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, SchemaVersion: 1, Fields: storageValues(), ActorScope: dc, CorrelationID: b.CorrelationID})
		if e != nil || created.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("self-profile fixture creation", e)
		}
		dc.Request.Subject = authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}
		dc.Request.Action = "identity.profile.update"
		dc.Request.Resource.Type = "identity.user"
		dc.Request.Resource.ID = authorization.ResourceID(b.UserID)
		return identity.ProfileUpdateRequest{TenantID: b.TenantID, Context: dc, CommandID: newID(), SchemaVersion: 1, ExpectedVersion: 1, Name: "first", Image: "https://images.example.test/first.png", CorrelationID: b.CorrelationID}
	}
	state := func(req identity.ProfileUpdateRequest) identity.ProfileRecord {
		t.Helper()
		r, e := repo.GetProfile(ctx, identity.ProfileQuery{TenantID: req.TenantID, UserID: identity.UserID(req.Context.Request.Subject.ID)})
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	count := func(id identity.CommandID, wantAudit, wantEffect int) {
		t.Helper()
		var a, e int
		err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(id)).Scan(&a, &e)
		if err != nil || a != wantAudit || e != wantEffect {
			t.Fatal("wrong atomic profile effects", a, e, err)
		}
	}
	t.Run("merge original receipt replay and current redaction", func(t *testing.T) {
		req := newUser()
		req.AdditionalFields = []identity.AttributeUpdate{storageValues()[1]}
		req.AdditionalFields[0].Value.Scalar.Bool = true
		first, e := service.ProfileUpdate(ctx, req)
		if e != nil || first.CommitOutcome != identity.CommitOutcomeCommitted || first.User.Version != 2 || first.User.Name != "first" || first.User.Image != req.Image || len(first.User.AdditionalFields) != 6 || !first.User.AdditionalFields[1].Value.Scalar.Bool {
			t.Fatal("profile command did not compose atomically", e)
		}
		count(req.CommandID, 1, 1)
		original := req
		req.CommandID = newID()
		req.ExpectedVersion = 2
		req.Name = "second"
		req.Image = ""
		req.AdditionalFields = nil
		second, e := service.ProfileUpdate(ctx, req)
		if e != nil || second.User.Version != 3 || second.User.Name != "second" || second.User.Image != original.Image || !reflect.DeepEqual(second.User.AdditionalFields, first.User.AdditionalFields) {
			t.Fatal("omitted fields changed", e)
		}
		replay, e := service.ProfileUpdate(ctx, original)
		if e != nil || !reflect.DeepEqual(replay, first) {
			t.Fatal("replay did CAS instead of original receipt", e)
		}
		recovery := identity.ProfileRecoveryRequest{TenantID: original.TenantID, CommandID: original.CommandID, Context: original.Context}
		recovered, e := service.RecoverProfileUpdate(ctx, recovery)
		if e != nil || !reflect.DeepEqual(recovered, first) {
			t.Fatal("profile recovery replaced original result", e)
		}
		hide = true
		recovered, e = service.RecoverProfileUpdate(ctx, recovery)
		hide = false
		if e != nil || recovered.User.Name != "" || recovered.User.Version != 2 || recovered.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("historic result bypassed current redaction", e)
		}
		original.Name = "different"
		conflicted, e := service.ProfileUpdate(ctx, original)
		var conflict identity.ConflictError
		if !errors.As(e, &conflict) || conflicted.CommitOutcome != identity.CommitOutcomeConflict {
			t.Fatal("changed command reused original receipt", e)
		}
		count(original.CommandID, 1, 1)
		current := state(req)
		if current.User.Version != 3 || current.Profile.Name != "second" {
			t.Fatal("replay remutated current state")
		}
		req.CommandID = newID()
		req.ExpectedVersion = 2
		req.Name = "stale"
		stale, e := service.ProfileUpdate(ctx, req)
		var notCommitted identity.NotCommittedError
		if !errors.As(e, &notCommitted) || stale.CommitOutcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("stale version did not close auditable rollback", e)
		}
		count(req.CommandID, 1, 0)
		if current := state(req); current.User.Version != 3 || current.Profile.Name != "second" {
			t.Fatal("stale CAS mutated profile")
		}
	})
	t.Run("participant failure rollback and panic cleanup", func(t *testing.T) {
		for _, mode := range []string{"outbox-error", "outbox-panic", "audit-error"} {
			req := newUser()
			before := state(req)
			effects.fail = mode == "outbox-error"
			effects.panicAfterWrite = mode == "outbox-panic"
			audits.fail = mode == "audit-error"
			result, e := service.ProfileUpdate(ctx, req)
			effects.fail = false
			effects.panicAfterWrite = false
			audits.fail = false
			if e == nil || result.CommitOutcome == identity.CommitOutcomeCommitted || result.User.ID != "" {
				t.Fatal("failed participant exposed success", mode)
			}
			if after := state(req); !reflect.DeepEqual(after, before) {
				t.Fatal("failure left profile/domain prefix", mode)
			}
			if mode == "audit-error" {
				count(req.CommandID, 0, 0)
			} else {
				count(req.CommandID, 1, 0)
				if result.CommitOutcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("proved rollback lost terminal receipt", mode)
				}
			}
		}
	})
	t.Run("same command concurrent public retries", func(t *testing.T) {
		req := newUser()
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make(chan identity.ProfileUpdateResult, 8)
		failures := make(chan error, 8)
		for range 8 {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; r, e := service.ProfileUpdate(ctx, req); results <- r; failures <- e }()
		}
		close(start)
		wg.Wait()
		close(results)
		close(failures)
		committed := 0
		for r := range results {
			if r.CommitOutcome == identity.CommitOutcomeCommitted {
				committed++
				if r.User.Version != 2 {
					t.Fatal("retry changed original successor")
				}
			} else if r.CommitOutcome != identity.CommitOutcomeInProgress {
				t.Fatal("same command lost known observation", r.CommitOutcome)
			}
		}
		for e := range failures {
			var busy identity.InProgressError
			if e != nil && !errors.As(e, &busy) {
				t.Fatal("concurrent retry failed", e)
			}
		}
		if committed == 0 || state(req).User.Version != 2 {
			t.Fatal("profile retries never completed")
		}
		count(req.CommandID, 1, 1)
	})
	t.Run("concurrent commands fence one aggregate successor", func(t *testing.T) {
		a := newUser()
		b := a
		b.CommandID = newID()
		b.Name = "other"
		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		results := make(chan identity.ProfileUpdateResult, 2)
		for _, req := range []identity.ProfileUpdateRequest{a, b} {
			go func() { defer wg.Done(); <-start; r, _ := service.ProfileUpdate(ctx, req); results <- r }()
		}
		close(start)
		wg.Wait()
		close(results)
		successes, failures := 0, 0
		for r := range results {
			if r.CommitOutcome == identity.CommitOutcomeCommitted {
				successes++
				count(r.CommandID, 1, 1)
			} else if r.CommitOutcome == identity.CommitOutcomeNotCommitted {
				failures++
				count(r.CommandID, 1, 0)
			}
		}
		if successes != 1 || failures != 1 || state(a).User.Version != 2 {
			t.Fatal("concurrent writers lost CAS", successes, failures)
		}
	})
	t.Run("full unsigned version and pre-cancellation", func(t *testing.T) {
		req := newUser()
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=$3::numeric WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.Context.Request.Subject.ID), "18446744073709551614"); e != nil {
			t.Fatal(e)
		}
		req.ExpectedVersion = math.MaxUint64 - 1
		r, e := service.ProfileUpdate(ctx, req)
		if e != nil || r.User.Version != math.MaxUint64 {
			t.Fatal("uint64 version truncated", e)
		}
		count(req.CommandID, 1, 1)
		req = newUser()
		cancelled, stop := context.WithCancel(ctx)
		stop()
		r, e = service.ProfileUpdate(cancelled, req)
		if !errors.Is(e, context.Canceled) || r.User.ID != "" {
			t.Fatal("cancellation allowed write", e)
		}
		count(req.CommandID, 0, 0)
	})
	t.Run("expired unexecuted profile reconciles original frozen participants", func(t *testing.T) {
		req := newUser()
		b := codecBinding()
		b.CommandID, b.UserID, b.ActorID, b.ActorKind = req.CommandID, identity.UserID(req.Context.Request.Subject.ID), identity.ActorID(req.Context.Request.Subject.ID), authorization.SubjectUser
		b.OperationID, b.SchemaID = "identity.profile.update", schema.ID
		command, e := identity.NewProfileUpdateCommand(identity.ProfileUpdateCommand{Binding: b, ExpectedVersion: 1, Name: req.Name, Image: req.Image})
		if e != nil {
			t.Fatal(e)
		}
		record, e := kernelMutationAudit(ctx, b, 1, time.Now().UTC().Truncate(time.Microsecond), "committed")
		if e != nil {
			t.Fatal(e)
		}
		digest, e := AuditBindingDigest(b, record)
		if e != nil {
			t.Fatal(e)
		}
		plan, e := c.PrepareCommandPlan(b, command, CommandPlan{Contributors: registry.Descriptors(), Audits: []AuditPlan{{EventType: "identity.user.update", SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &LifecyclePlan{EventType: "identity.updated.v1", BeforeVersion: 1, AfterVersion: 2}})
		if e != nil {
			t.Fatal(e)
		}
		_, pending, e := c.ReserveCommand(ctx, b, command, plan)
		if e != nil || pending.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("profile reservation", e)
		}
		key, e := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if e != nil {
			t.Fatal(e)
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3`, key, string(b.TenantID), b.OperationID); e != nil {
			t.Fatal(e)
		}
		recovered, e := service.RecoverProfileUpdate(ctx, identity.ProfileRecoveryRequest{TenantID: req.TenantID, CommandID: req.CommandID, Context: req.Context})
		var notCommitted identity.NotCommittedError
		if !errors.As(e, &notCommitted) || recovered.CommitOutcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("expired profile did not reconcile negative evidence", e)
		}
		count(req.CommandID, 1, 0)
		if state(req).User.Version != 1 {
			t.Fatal("recovery executed profile")
		}
	})
}
