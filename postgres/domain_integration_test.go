//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// These typed SQL seams test Coordinator phase ownership and rollback, not
// production audit/outbox interoperability. Real adapter composition is a
// separate required journey; no application implementation is recommended.
type domainAuditPhase struct{ fail bool }

func (*domainAuditPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}
}
func (p *domainAuditPhase) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_audits(event_id,command_id) VALUES($1,$2)`, record.Record.ID(), string(w.state.binding.CommandID)); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}

type domainLifecyclePhase struct{ fail, panicAfterWrite bool }

func (*domainLifecyclePhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
}
func (p *domainLifecyclePhase) PersistLifecycle(ctx context.Context, w Work) error {
	records, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_lifecycle(event_id,command_id) VALUES($1,$2)`, record.ID, string(record.CommandID)); err != nil {
			return err
		}
	}
	if p.panicAfterWrite {
		panic("test contributor panic")
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}

func testDomainExecution(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);`); err != nil {
		t.Fatal(err)
	}
	auditPhase := &domainAuditPhase{}
	lifecyclePhase := &domainLifecyclePhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, auditPhase, lifecyclePhase})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(t *testing.T, attributes ...identity.AttributeUpdate) (identity.CommandBinding, identity.Command, CommandPlan, audit.Record, Reservation) {
		t.Helper()
		binding := codecBinding()
		binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		user, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		binding.UserID = identity.UserID(user)
		_, original, ap := auditFixture(t)
		record := changedAudit(t, original, func(in *audit.RecordInput) {
			in.Subject.ID = string(binding.UserID)
			in.Attributes["command.id"] = string(binding.CommandID)
			in.Attributes["aggregate.id"] = string(binding.UserID)
			in.Changes = audit.ChangeSetInput{Redacted: true}
		}, "", true)
		ap.BindingDigest, err = AuditBindingDigest(binding, record)
		if err != nil {
			t.Fatal(err)
		}
		command, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: binding, Status: identity.StatusActive, Attributes: attributes})
		if err != nil {
			t.Fatal(err)
		}
		plan, err := c.PrepareCommandPlan(binding, command, CommandPlan{Contributors: registry.Descriptors(), Audits: []AuditPlan{ap}, Lifecycle: &LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}})
		if err != nil {
			t.Fatal(err)
		}
		reservation, result, err := c.ReserveCommand(ctx, binding, command, plan)
		if err != nil || reservation.state == nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("domain reservation failed", err)
		}
		return binding, command, plan, record, reservation
	}
	counts := func(t *testing.T, binding identity.CommandBinding, users, audits, effects int) {
		t.Helper()
		var u, a, e, document int
		err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3),(SELECT count(*) FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2)`, string(binding.TenantID), string(binding.UserID), string(binding.CommandID)).Scan(&u, &a, &e, &document)
		if err != nil || u != users || a != audits || e != effects || document != users {
			t.Fatalf("atomic state %d/%d/%d/%d", u, a, e, document)
		}
	}
	stage := func(t *testing.T, w Work, record audit.Record) {
		t.Helper()
		now, err := w.DatabaseTime(ctx)
		if err != nil {
			t.Fatal(err)
		}
		record = changedAudit(t, record, func(in *audit.RecordInput) {
			in.OccurredAt = now
			in.Changes = audit.ChangeSetInput{Redacted: true}
		}, record.ID(), true)
		if !record.Changes().Redacted() || record.Changes().NoChange() {
			t.Fatal("creation fixture lost its structural-change audit")
		}
		if err := w.StageAudit(0, record); err != nil {
			t.Fatal(err)
		}
		if err := w.StageLifecycle(0, now); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("atomic creation and replay", func(t *testing.T) {
		binding, command, plan, record, reservation := prepare(t)
		w, err := c.Begin(ctx, reservation)
		if err != nil {
			t.Fatal("domain Begin failed", err)
		}
		defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
		alias := w
		user, err := repo.ApplyUserCreation(ctx, w, command)
		if err != nil {
			_, _ = c.Abort(w, err)
			t.Fatal("creation apply failed", err)
		}
		stage(t, w, record)
		receipt, err := c.Commit(w, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
		if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Validate() != nil {
			t.Fatal("atomic creation commit failed", err)
		}
		counts(t, binding, 1, 1, 1)
		if _, err := alias.Scope(); err == nil {
			t.Fatal("alias survived commit")
		}
		if _, err := c.Begin(ctx, reservation); err == nil {
			t.Fatal("consumed reservation reused")
		}
		if r, replayed, err := c.ReserveCommand(ctx, binding, command, plan); err != nil || r.state != nil || replayed.User != receipt.User || replayed.AuditEventID != receipt.AuditEventID {
			t.Fatal("committed creation replay changed", err)
		}
		counts(t, binding, 1, 1, 1)
	})
	t.Run("typed attributes survive atomic creation", func(t *testing.T) {
		values := storageValues()
		binding, command, plan, record, reservation := prepare(t, values...)
		w, err := c.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
		user, err := repo.ApplyUserCreation(ctx, w, command)
		if err != nil {
			t.Fatal("declared attribute creation rejected", err)
		}
		stage(t, w, record)
		result, err := c.Commit(w, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("attribute creation not committed", err)
		}
		var document []byte
		if err := pool.Raw().QueryRow(ctx, `SELECT document FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2`, string(binding.TenantID), string(binding.UserID)).Scan(&document); err != nil {
			t.Fatal("typed attribute document missing")
		}
		got, err := decodeStoredAttributes(binding, storageSchema(), document)
		if err != nil || !reflect.DeepEqual(got, values) {
			t.Fatal("durable typed attributes changed")
		}
		counts(t, binding, 1, 1, 1)
		if r, result, err := c.ReserveCommand(ctx, binding, command, plan); err != nil || r.state != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("attribute replay changed")
		}
		counts(t, binding, 1, 1, 1)
	})
	t.Run("undeclared attributes leave no user", func(t *testing.T) {
		value := storageValues()[0]
		value.Name = "undeclared"
		binding, command, _, _, reservation := prepare(t, value)
		w, err := c.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
		if _, err := repo.ApplyUserCreation(ctx, w, command); err == nil {
			t.Fatal("undeclared field stored")
		}
		_, _ = c.Abort(w, identity.InvalidInputError{Field: "attribute_storage"})
		counts(t, binding, 0, 0, 0)
	})
	t.Run("incompatible schema redeclaration fails", func(t *testing.T) {
		schema := storageSchema()
		schema.Fields[0].OutputPermission = identity.FieldDenied
		other, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{schema}})
		if err != nil {
			t.Fatal(err)
		}
		registered, err := NewContributorRegistry([]Contributor{other, auditPhase, lifecyclePhase})
		if err != nil {
			t.Fatal(err)
		}
		coordinator, err := NewCoordinator(pool, registered, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
		if err != nil {
			t.Fatal(err)
		}
		original := c
		c = coordinator
		defer func() { c = original }()
		binding, command, _, _, reservation := prepare(t, storageValues()...)
		w, err := c.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
		var conflict identity.ConflictError
		if _, err := other.ApplyUserCreation(ctx, w, command); !errors.As(err, &conflict) {
			t.Fatal("registered version acquired different meaning", err)
		}
		_, _ = c.Abort(w, conflict)
		counts(t, binding, 0, 0, 0)
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.attribute_schemas SET definition=definition WHERE tenant_id=$1 AND schema_id=$2`, string(binding.TenantID), binding.SchemaID); err == nil {
			t.Fatal("immutable schema updated")
		}
	})
	t.Run("phase failure rolls back every prefix", func(t *testing.T) {
		binding, command, _, record, reservation := prepare(t)
		w, err := c.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
		user, err := repo.ApplyUserCreation(ctx, w, command)
		if err != nil {
			t.Fatal(err)
		}
		stage(t, w, record)
		lifecyclePhase.fail = true
		receipt, err := c.Commit(w, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
		lifecyclePhase.fail = false
		if err == nil || receipt.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("missing failure audit fabricated terminal receipt")
		}
		counts(t, binding, 0, 0, 0)
		if _, err := w.Scope(); err == nil {
			t.Fatal("failed commit leaked Work")
		}
	})
	t.Run("forged receipt cannot commit", func(t *testing.T) {
		binding, command, _, record, reservation := prepare(t)
		w, err := c.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
		user, err := repo.ApplyUserCreation(ctx, w, command)
		if err != nil {
			t.Fatal(err)
		}
		stage(t, w, record)
		user.Version = 2
		receipt, err := c.Commit(w, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
		if err == nil || receipt.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("forged result committed")
		}
		counts(t, binding, 0, 0, 0)
	})
	t.Run("denial audit terminalization", func(t *testing.T) {
		binding, command, plan, record, reservation := prepare(t)
		w, err := c.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
		denied := changedAudit(t, record, func(in *audit.RecordInput) {
			in.Outcome = audit.OutcomeDenied
			in.ReasonCode = "not_authorized"
			in.Changes = audit.ChangeSetInput{NoChange: true}
			in.Attributes["aggregate.after_version"] = "0"
		}, "", true)
		if err := w.StageAudit(0, denied); err != nil {
			t.Fatal(err)
		}
		result, err := c.Abort(w, identity.ForbiddenError{})
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("denial not terminalized", err)
		}
		counts(t, binding, 0, 1, 0)
		if _, result, err := c.ReserveCommand(ctx, binding, command, plan); err != nil || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("aborted receipt replay failed", err)
		}
	})
	t.Run("repeated apply poisons and rolls back", func(t *testing.T) {
		binding, command, _, _, reservation := prepare(t)
		w, err := c.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
		if _, err := repo.ApplyUserCreation(ctx, w, command); err != nil {
			t.Fatal(err)
		}
		_, err = repo.ApplyUserCreation(ctx, w, command)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) {
			t.Fatal("repeat lost conflict classification", err)
		}
		if _, err := w.Scope(); !errors.As(err, &conflict) {
			t.Fatal("repeat did not poison Work")
		}
		if result, err := c.Abort(w, conflict); err == nil || result.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("missing denial audit fabricated known result")
		}
		counts(t, binding, 0, 0, 0)
	})
	for _, profile := range []string{"missing audit", "missing lifecycle", "active cursor", "cancelled", "audit phase failure", "phase panic"} {
		t.Run(profile, func(t *testing.T) {
			binding, command, _, record, reservation := prepare(t)
			call, cancel := context.WithCancel(ctx)
			defer cancel()
			w, err := c.Begin(call, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
			user, err := repo.ApplyUserCreation(call, w, command)
			if err != nil {
				t.Fatal(err)
			}
			if profile == "missing lifecycle" {
				if err := w.StageAudit(0, record); err != nil {
					t.Fatal(err)
				}
			} else if profile != "missing audit" {
				stage(t, w, record)
			}
			var rows *WorkRows
			if profile == "active cursor" {
				rows, err = w.Query(call, "SELECT 1")
				if err != nil {
					t.Fatal(err)
				}
			}
			if profile == "cancelled" {
				cancel()
			}
			auditPhase.fail = profile == "audit phase failure"
			lifecyclePhase.panicAfterWrite = profile == "phase panic"
			defer func() { auditPhase.fail = false; lifecyclePhase.panicAfterWrite = false }()
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				result, err := c.Commit(w, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
				if err == nil || result.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("invalid transition committed")
				}
			}()
			if panicked != (profile == "phase panic") {
				t.Fatal("unexpected panic classification")
			}
			if _, err := w.Scope(); err == nil {
				t.Fatal("failed transition retained Work")
			}
			if rows != nil && rows.Next() {
				t.Fatal("failed commit retained cursor")
			}
			counts(t, binding, 0, 0, 0)
		})
	}
	t.Run("domain commit ambiguity preserves pending reservation", func(t *testing.T) {
		binding, command, _, record, reservation := prepare(t)
		if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION identity.identity_test_domain_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='test deferred domain failure'; END $$;
CREATE CONSTRAINT TRIGGER identity_test_domain_commit AFTER INSERT ON identity.users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity.identity_test_domain_commit();`); err != nil {
			t.Fatal("deferred domain fixture failed")
		}
		defer func() {
			if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER identity_test_domain_commit ON identity.users; DROP FUNCTION identity.identity_test_domain_commit();`); err != nil {
				t.Error("deferred fixture cleanup failed")
			}
		}()
		w, err := c.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
		user, err := repo.ApplyUserCreation(ctx, w, command)
		if err != nil {
			t.Fatal(err)
		}
		stage(t, w, record)
		result, err := c.Commit(w, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
		if err == nil || result.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("domain commit failure was not unknown")
		}
		counts(t, binding, 0, 0, 0)
		id, _ := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
		var status string
		if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, id).Scan(&status); err != nil || status != "pending" {
			t.Fatal("domain commit retried or lost durable reservation")
		}
	})
	for _, abort := range []bool{false, true} {
		name := "commit keeps original short lease"
		if abort {
			name = "abort terminal commit keeps original short lease"
		}
		t.Run(name, func(t *testing.T) {
			short, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: 100 * time.Millisecond, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			previous := c
			c = short
			defer func() { c = previous }()
			binding, command, _, record, reservation := prepare(t)
			if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.identity_test_delayed_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); RETURN NEW; END $$;
CREATE CONSTRAINT TRIGGER identity_test_delayed_commit AFTER INSERT ON public.identity_test_audits DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_test_delayed_commit();`); err != nil {
				t.Fatal("delayed commit fixture failed")
			}
			defer func() {
				if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER identity_test_delayed_commit ON public.identity_test_audits; DROP FUNCTION public.identity_test_delayed_commit();`); err != nil {
					t.Error("delayed commit fixture cleanup failed")
				}
			}()
			w, err := c.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
			var result identity.CommandResult
			if abort {
				denied := changedAudit(t, record, func(in *audit.RecordInput) {
					in.Outcome = audit.OutcomeDenied
					in.ReasonCode = "not_authorized"
					in.Attributes["aggregate.after_version"] = "0"
				}, "", true)
				if err := w.StageAudit(0, denied); err != nil {
					t.Fatal(err)
				}
				result, err = c.Abort(w, identity.ForbiddenError{})
			} else {
				user, applyErr := repo.ApplyUserCreation(ctx, w, command)
				if applyErr != nil {
					t.Fatal(applyErr)
				}
				stage(t, w, record)
				result, err = c.Commit(w, identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
			}
			if err == nil || result.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("commit renewed expired original lease")
			}
			counts(t, binding, 0, 0, 0)
		})
	}
	t.Run("foreign and stale reservation", func(t *testing.T) {
		_, _, _, _, reservation := prepare(t)
		foreign := *c
		if _, err := foreign.Begin(ctx, reservation); err == nil {
			t.Fatal("foreign coordinator began")
		}
		q := reservation.state.request
		id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Begin(ctx, reservation); err == nil {
			t.Fatal("expired reservation began")
		}
	})
}
