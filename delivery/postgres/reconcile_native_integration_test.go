//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testNativeReconciliation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owned *database.Pool, repo *identitypostgres.Repository, audits *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor, custody *Contributor, original identity.CommandBinding) {
	t.Helper()
	worker, err := newAttemptStore(pool, "test", custody.store.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: delivery.TenantID(original.TenantID), WorkerID: "reconcile-worker"})
	if err != nil || !claim.Claimed {
		t.Fatal("reconcile claim", err)
	}
	if _, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, IntentID: claim.Attempt.IntentID, WorkerID: "reconcile-worker", Generation: claim.Attempt.Generation, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC()}}); err != nil {
		t.Fatal("unknown completion", err)
	}
	native := &reconciliationContributor{store: &receiptStore{deployment: "test", namespaceKey: [32]byte{1}}}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, native, audits, lifecycle})
	if err != nil {
		t.Fatal("reconciliation registry", err)
	}
	coordinator, err := identitypostgres.NewCoordinator(owned, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: enqueueDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	b := original
	op := reconciliationOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	q := delivery.ReceiptRecordRequest{TenantID: delivery.TenantID(b.TenantID), IntentID: delivery.IntentID(b.RecordID), Generation: 1, Provider: "test-provider", ProviderEventID: "synthetic-native-query-event", Status: delivery.StateDelivered, ObservedAt: time.Now().UTC(), IdempotencyKey: "synthetic-native-query"}
	var step int64
	prepare := func(binding identity.CommandBinding, version uint64) (identity.Command, identitypostgres.CommandPlan) {
		t.Helper()
		command, err := newReconciliationCommand(binding, q, version, step, [32]byte{}, [32]byte{}, native.store)
		if err != nil {
			t.Fatal("reconciliation command", err)
		}
		digest, err := deliveryFeatureAuditDigest(binding, op)
		if err != nil {
			t.Fatal(err)
		}
		plan := identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "delivery_intent", Feature: &identitypostgres.FeatureRegistration{Contributor: native.Descriptor(), Operation: op}, Audits: []identitypostgres.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "delivery.reconciled.v1", BeforeVersion: version, AfterVersion: version + 1}}
		plan, err = coordinator.PrepareCommandPlan(binding, command, plan)
		if err != nil {
			t.Fatal("reconciliation plan", err)
		}
		return command, plan
	}
	// First poll remains unknown and closes only its query sequence. The next
	// poll must use the latest step and must not rewrite the first command result.
	q.Status = delivery.StateOutcomeUnknown
	b.CommandID, _ = identity.NewCommandID()
	firstCommand, firstPlan := prepare(b, 3)
	firstBinding := b
	reservation, _, err := coordinator.ReserveCommand(ctx, b, firstCommand, firstPlan)
	if err != nil {
		t.Fatal(err)
	}
	firstWork, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	provisional, err := coordinator.ApplyFeature(ctx, firstWork, firstCommand)
	if err != nil {
		coordinator.Abort(firstWork, err)
		t.Fatal(err)
	}
	firstResult, err := coordinator.Commit(firstWork, provisional)
	if err != nil {
		t.Fatal(err)
	}
	var uncertain bool
	if err := pool.QueryRow(ctx, `SELECT state='outcome-unknown' AND ciphertext IS NOT NULL AND status_version=4 AND (SELECT count(*) FROM identity.delivery_reconciliation_checkpoints WHERE step=1)=1 AND (SELECT count(*) FROM identity.delivery_attempt_history)=1 FROM identity.delivery_intents`).Scan(&uncertain); err != nil || !uncertain {
		t.Fatal("unknown poll granted retry or erased custody", err)
	}
	step = 1
	q.Status = delivery.StateDelivered
	q.ProviderEventID = "synthetic-native-terminal-query"
	q.ObservedAt = q.ObservedAt.Add(time.Millisecond)
	for _, fail := range []bool{true, false} {
		b.CommandID, _ = identity.NewCommandID()
		command, plan := prepare(b, 4)
		reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
		if err != nil {
			t.Fatal(err)
		}
		work, err := coordinator.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer coordinator.Abort(work, identity.UnavailableError{})
		if _, err := native.ApplyFeature(ctx, work, command); err == nil {
			t.Fatal("foreign invocation admitted")
		}
		provisional, err := coordinator.ApplyFeature(ctx, work, command)
		if err != nil {
			t.Fatal("reconciliation apply", err)
		}
		if fail {
			if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages ADD CONSTRAINT reconcile_failure CHECK(topic<>'delivery.reconciled.v1') NOT VALID`); err != nil {
				t.Fatal(err)
			}
		}
		committed, err := coordinator.Commit(work, provisional)
		if fail {
			if err == nil || committed.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("lifecycle failure committed reconciliation", err)
			}
			var restored bool
			if err := pool.QueryRow(ctx, `SELECT state='outcome-unknown' AND ciphertext IS NOT NULL AND status_version=4 AND (SELECT count(*) FROM identity.delivery_receipts)=1 AND (SELECT count(*) FROM identity.delivery_reconciliation_checkpoints)=1 AND (SELECT count(*) FROM identity.delivery_reconciliation_commands)=1 FROM identity.delivery_intents`).Scan(&restored); err != nil || !restored {
				t.Fatal("rollback retained prefix", err)
			}
			if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages DROP CONSTRAINT reconcile_failure`); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err != nil || committed.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("reconciliation commit", err)
		}
		var settled bool
		if err := pool.QueryRow(ctx, `SELECT state='confirmed' AND ciphertext IS NULL AND status_version=5 AND (SELECT count(*) FROM identity.delivery_receipts)=2 AND (SELECT count(*) FROM identity.delivery_reconciliation_checkpoints WHERE step=2)=1 AND (SELECT count(*) FROM identity.delivery_reconciliation_commands WHERE result_state=4 AND advanced)=1 AND (SELECT count(*) FROM identity.delivery_attempt_history WHERE outcome=8)=1 FROM identity.delivery_intents`).Scan(&settled); err != nil || !settled {
			t.Fatal("atomic result absent", err)
		}
		_, replay, err := coordinator.ReserveCommand(ctx, b, command, plan)
		if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != committed.AuditEventID {
			t.Fatal("original replay lost", err)
		}
		_, historical, err := coordinator.ReserveCommand(ctx, firstBinding, firstCommand, firstPlan)
		if err != nil || historical.AuditEventID != firstResult.AuditEventID || historical.Feature.BeforeVersion != 3 || historical.Feature.AfterVersion != 4 {
			t.Fatal("earlier unknown result rewritten", err)
		}
		changed, err := newReconciliationCommand(b, q, 4, step, [32]byte{}, [32]byte{1}, native.store)
		if err != nil {
			t.Fatal(err)
		}
		changedPlan, err := coordinator.PrepareCommandPlan(b, changed, plan)
		if err != nil {
			t.Fatal("changed reconciliation plan", err)
		}
		var conflict identity.ConflictError
		if _, _, err := coordinator.ReserveCommand(ctx, b, changed, changedPlan); !errors.As(err, &conflict) {
			t.Fatal("changed cursor replay admitted", err)
		}
		// Exact old provider evidence under a NEW command does not waive the
		// status fence, even when its historical after-version equals current.
		staleBinding := b
		staleBinding.CommandID, _ = identity.NewCommandID()
		staleCommand, stalePlan := prepare(staleBinding, 4)
		staleReservation, _, err := coordinator.ReserveCommand(ctx, staleBinding, staleCommand, stalePlan)
		if err != nil {
			t.Fatal(err)
		}
		staleWork, err := coordinator.Begin(ctx, staleReservation)
		if err != nil {
			t.Fatal(err)
		}
		_, err = coordinator.ApplyFeature(ctx, staleWork, staleCommand)
		coordinator.Abort(staleWork, identity.UnavailableError{})
		if !errors.As(err, &conflict) {
			t.Fatal("stale native status admitted historical event", err)
		}
		var fenced bool
		if err := pool.QueryRow(ctx, `SELECT state='confirmed' AND ciphertext IS NULL AND status_version=5 AND (SELECT count(*) FROM identity.delivery_receipts)=2 AND (SELECT count(*) FROM identity.delivery_reconciliation_checkpoints)=2 AND (SELECT count(*) FROM identity.delivery_reconciliation_commands)=2 AND (SELECT count(*) FROM outbox_messages WHERE topic='delivery.reconciled.v1')=2 FROM identity.delivery_intents`).Scan(&fenced); err != nil || !fenced {
			t.Fatal("stale native status changed effects", err)
		}
		abandoned := b
		abandoned.CommandID, _ = identity.NewCommandID()
		abandonedCommand, abandonedPlan := prepare(abandoned, 5)
		if _, _, err := coordinator.ReserveCommand(ctx, abandoned, abandonedCommand, abandonedPlan); err != nil {
			t.Fatal(err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(abandoned.CommandID))
		if _, err := pool.Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		query := identity.RecoveryQuery{CommandID: abandoned.CommandID, TenantID: abandoned.TenantID, UserID: abandoned.UserID, ActorID: abandoned.ActorID, ActorKind: abandoned.ActorKind, OperationID: abandoned.OperationID, RecordID: abandoned.RecordID}
		caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: abandoned.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(abandoned.TenantID), Action: authorization.Action(abandoned.OperationID), Subject: authorization.Subject{ID: authorization.SubjectID(abandoned.ActorID), Kind: abandoned.ActorKind}, Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(abandoned.UserID)}}}
		recovered, err := coordinator.RecoverCommand(ctx, query, caller)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || recovered.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("negative recovery lost", err)
		}
		for _, sql := range []string{`UPDATE identity.delivery_reconciliation_commands SET advanced=false`, `DELETE FROM identity.delivery_reconciliation_commands`, `TRUNCATE identity.delivery_reconciliation_commands`} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatal("immutable command result mutable")
			}
		}
	}
}
