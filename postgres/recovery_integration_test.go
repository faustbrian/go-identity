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

// SQL seams establish coordinator phase/atomicity behavior; production audit
// and outbox recovery implementations remain a separate interoperability gate.
type recoveryAuditPhase struct {
	domainAuditPhase
	panicStatus    bool
	swallowFailure bool
	retained       RecoveryWork
}

func (p *recoveryAuditPhase) PersistAudits(ctx context.Context, w Work) error {
	err := p.domainAuditPhase.PersistAudits(ctx, w)
	if err == nil && p.swallowFailure {
		// Local parameter rejection poisons Work without aborting the SQL tx.
		// An adapter must not erase that failure by returning nil.
		_, _ = w.Query(ctx, "SELECT $1", struct{}{})
	}
	return err
}

func (p *recoveryAuditPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	p.retained = w
	if p.panicStatus {
		panic("private participant panic")
	}
	if _, err := w.AuditPlan(); err != nil {
		return RecoveryUnknown, err
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_audits")
}

type recoveryLifecyclePhase struct{ domainLifecyclePhase }

func (*recoveryLifecyclePhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, err := w.LifecyclePlan(); err != nil {
		return RecoveryUnknown, err
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_lifecycle")
}

func recoveryTestEvidence(ctx context.Context, w RecoveryWork, table string) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	// table is one of the two fixed test seam constants, never caller input.
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if err := rows.Scan(&exists); err != nil {
		return RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return RecoveryCommitted, nil
	}
	return RecoveryNotCommitted, nil
}

func testCommandRecovery(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	auditing := &recoveryAuditPhase{}
	lifecycle := &recoveryLifecyclePhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func() (identity.CommandBinding, Reservation) {
		t.Helper()
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
		command, e := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: b, Status: identity.StatusActive})
		if e != nil {
			t.Fatal(e)
		}
		record, e := creationAudit(ctx, b, time.Now().UTC().Truncate(time.Microsecond), "committed")
		if e != nil {
			t.Fatal(e)
		}
		digest, e := AuditBindingDigest(b, record)
		if e != nil {
			t.Fatal(e)
		}
		plan, e := c.PrepareCommandPlan(b, command, CommandPlan{Contributors: registry.Descriptors(), Audits: []AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}})
		if e != nil {
			t.Fatal(e)
		}
		r, _, e := c.ReserveCommand(ctx, b, command, plan)
		if e != nil || r.state == nil {
			t.Fatal("reserve recovery fixture", e)
		}
		return b, r
	}
	expire := func(b identity.CommandBinding) {
		key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); e != nil {
			t.Fatal(e)
		}
	}
	snapshot := func(b identity.CommandBinding) string {
		key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var row string
		if e := pool.Raw().QueryRow(ctx, `SELECT row_to_json(j)::text FROM identity.commands j WHERE command_id=$1`, key).Scan(&row); e != nil {
			t.Fatal(e)
		}
		return row
	}
	t.Run("live then proven abort and stale owner", func(t *testing.T) {
		b, old := prepare()
		before := snapshot(b)
		got, e := c.recoverCommandReceipt(ctx, creationRecoveryQuery(b))
		if e != nil || got.Outcome != identity.CommitOutcomeInProgress || snapshot(b) != before {
			t.Fatal("live recovery changed ownership", e)
		}
		expire(b)
		got, e = c.recoverCommandReceipt(ctx, creationRecoveryQuery(b))
		var unavailable identity.UnavailableError
		if got.Outcome != identity.CommitOutcomeNotCommitted || got.Binding != b || !errors.As(e, &unavailable) {
			t.Fatal("recovery did not prove aborted", got.Outcome, e)
		}
		var generation, attempts string
		var audits, users, effects int
		key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		e = pool.Raw().QueryRow(ctx, `SELECT generation::text,attempt::text,(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$2),(SELECT count(*) FROM identity.users WHERE tenant_id=$3 AND user_id=$4),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$2) FROM identity.commands WHERE command_id=$1`, key, string(b.CommandID), string(b.TenantID), string(b.UserID)).Scan(&generation, &attempts, &audits, &users, &effects)
		if e != nil || generation != "2" || attempts != "2" || audits != 1 || users != 0 || effects != 0 {
			t.Fatal("wrong recovery atomic state", e)
		}
		before = snapshot(b)
		if repeat, _ := c.recoverCommandReceipt(ctx, creationRecoveryQuery(b)); repeat != got || snapshot(b) != before {
			t.Fatal("terminal recovery changed receipt")
		}
		missing := *c
		missing.registry, err = NewContributorRegistry([]Contributor{repo})
		if err != nil {
			t.Fatal(err)
		}
		query, caller := queryInputs(b)
		if metadata, e := missing.RecoverCommand(ctx, query, caller); metadata.Binding != b || metadata.Outcome != identity.CommitOutcomeNotCommitted || e == nil {
			t.Fatal("terminal history required current registry", e)
		}
		if _, e := auditing.retained.Scope(); e == nil {
			t.Fatal("participant retained recovery authority")
		}
		if _, e := c.Begin(ctx, old); e == nil {
			t.Fatal("stale reservation admitted")
		}
	})
	t.Run("missing frozen participant does not take over", func(t *testing.T) {
		b, _ := prepare()
		expire(b)
		before := snapshot(b)
		missing := *c
		missing.registry, err = NewContributorRegistry([]Contributor{repo})
		if err != nil {
			t.Fatal(err)
		}
		q, caller := queryInputs(b)
		got, e := missing.RecoverCommand(ctx, q, caller)
		if e == nil || got.Outcome != identity.CommitOutcomeInProgress || snapshot(b) != before {
			t.Fatal("missing participant bypassed frozen plan")
		}
	})
	for _, partial := range []string{"audit", "outbox", "existing-user", "panic", "failure-audit", "swallowed-work-failure"} {
		t.Run(partial, func(t *testing.T) {
			b, _ := prepare()
			expire(b)
			switch partial {
			case "audit":
				_, err = pool.Raw().Exec(ctx, `INSERT INTO public.identity_test_audits(event_id,command_id) VALUES($1,$2)`, string(b.CommandID), string(b.CommandID))
			case "outbox":
				_, err = pool.Raw().Exec(ctx, `INSERT INTO public.identity_test_lifecycle(event_id,command_id) VALUES($1,$2)`, string(b.CommandID), string(b.CommandID))
			case "existing-user":
				_, err = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(b.TenantID), string(b.UserID))
			case "panic":
				auditing.panicStatus = true
			case "failure-audit":
				auditing.fail = true
			case "swallowed-work-failure":
				auditing.swallowFailure = true
			}
			if err != nil {
				t.Fatal(err)
			}
			before := snapshot(b)
			got, e := c.recoverCommandReceipt(ctx, creationRecoveryQuery(b))
			auditing.panicStatus, auditing.fail, auditing.swallowFailure = false, false, false
			if got.Outcome != identity.CommitOutcomeInProgress || e == nil || snapshot(b) != before {
				t.Fatal("unresolved evidence terminalized", got.Outcome, e)
			}
			if partial == "failure-audit" || partial == "swallowed-work-failure" {
				var count int
				if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1`, string(b.CommandID)).Scan(&count); e != nil || count != 0 {
					t.Fatal("failed recovery leaked audit prefix")
				}
			}
		})
	}
	t.Run("concurrent recovery", func(t *testing.T) {
		b, _ := prepare()
		expire(b)
		var wg sync.WaitGroup
		results := make(chan identity.CommandResult, 2)
		for range 2 {
			wg.Go(func() { r, _ := c.recoverCommandReceipt(ctx, creationRecoveryQuery(b)); results <- r })
		}
		wg.Wait()
		close(results)
		for r := range results {
			if r.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("competing recovery diverged")
			}
		}
	})
}
