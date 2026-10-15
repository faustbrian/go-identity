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

func testNativeReceipt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owned *database.Pool, repo *identitypostgres.Repository, audits *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor, custody *Contributor, original identity.CommandBinding) {
	t.Helper()
	worker, err := newAttemptStore(pool, "test", custody.store.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: delivery.TenantID(original.TenantID), WorkerID: "receipt-worker"})
	if err != nil || !claim.Claimed {
		t.Fatal("native receipt claim", err)
	}
	native := &receiptContributor{store: &receiptStore{deployment: "test", namespaceKey: [32]byte{1}}}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, native, audits, lifecycle})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := identitypostgres.NewCoordinator(owned, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: enqueueDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	b := original
	op := receiptOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	q := delivery.ReceiptRecordRequest{TenantID: delivery.TenantID(b.TenantID), IntentID: delivery.IntentID(b.RecordID), Generation: 1, Provider: "test-provider", ProviderEventID: "synthetic-native-event", Status: delivery.StateDelivered, ObservedAt: time.Now().UTC(), IdempotencyKey: "synthetic-native-receipt"}
	for _, fail := range []bool{true, false} {
		b.CommandID, _ = identity.NewCommandID()
		command, err := newReceiptCommand(b, q, 2, native.store)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := deliveryFeatureAuditDigest(b, op)
		if err != nil {
			t.Fatal(err)
		}
		declaration := identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "delivery_intent", Feature: &identitypostgres.FeatureRegistration{Contributor: native.Descriptor(), Operation: op}, Audits: []identitypostgres.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "delivery.receipt-recorded.v1", BeforeVersion: 2, AfterVersion: 3}}
		plan, err := coordinator.PrepareCommandPlan(b, command, declaration)
		if err != nil {
			t.Fatal("receipt plan", err)
		}
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
			t.Fatal("foreign receipt invocation admitted")
		}
		provisional, err := coordinator.ApplyFeature(ctx, work, command)
		if err != nil {
			t.Fatal("receipt apply", err)
		}
		if fail {
			if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages ADD CONSTRAINT receipt_test_failure CHECK(topic<>'delivery.receipt-recorded.v1') NOT VALID`); err != nil {
				t.Fatal(err)
			}
		}
		committed, err := coordinator.Commit(work, provisional)
		if fail {
			if err == nil || committed.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("failed lifecycle committed receipt", err)
			}
			var restored bool
			if err := pool.QueryRow(ctx, `SELECT state='submitted' AND ciphertext IS NOT NULL AND status_version=2 AND NOT EXISTS(SELECT 1 FROM identity.delivery_receipts) AND NOT EXISTS(SELECT 1 FROM identity.delivery_receipt_commands) FROM identity.delivery_intents`).Scan(&restored); err != nil || !restored {
				t.Fatal("downstream rollback retained receipt prefix", err)
			}
			if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages DROP CONSTRAINT receipt_test_failure`); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err != nil || committed.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("native receipt commit", err)
		}
		var settled bool
		if err := pool.QueryRow(ctx, `SELECT state='confirmed' AND ciphertext IS NULL AND status_version=3 AND (SELECT count(*) FROM identity.delivery_receipts)=1 AND (SELECT count(*) FROM identity.delivery_receipt_commands WHERE result_state=4 AND advanced AND NOT deduplicated)=1 FROM identity.delivery_intents`).Scan(&settled); err != nil || !settled {
			t.Fatal("atomic native receipt missing", err)
		}
		reservation, replay, err := coordinator.ReserveCommand(ctx, b, command, plan)
		if err != nil || reservation != (identitypostgres.Reservation{}) || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != committed.AuditEventID {
			t.Fatal("receipt replay lost original command", err)
		}
		changed := q
		changed.Status = delivery.StateRejected
		other, err := newReceiptCommand(b, changed, 2, native.store)
		if err != nil {
			t.Fatal(err)
		}
		otherPlan, err := coordinator.PrepareCommandPlan(b, other, declaration)
		if err != nil {
			t.Fatal(err)
		}
		var conflict identity.ConflictError
		if _, _, err := coordinator.ReserveCommand(ctx, b, other, otherPlan); !errors.As(err, &conflict) {
			t.Fatal("changed event reused committed command", err)
		}
		// A reservation abandoned before domain effects must recover through the
		// real native participant's negative evidence and the required failure audit.
		abandoned := b
		abandoned.CommandID, _ = identity.NewCommandID()
		abandonedCommand, _ := newReceiptCommand(abandoned, q, 3, native.store)
		abandonedPlan := declaration
		abandonedPlan.Audits = append([]identitypostgres.AuditPlan(nil), declaration.Audits...)
		abandonedPlan.Audits[0].BindingDigest, _ = deliveryFeatureAuditDigest(abandoned, op)
		abandonedPlan.Lifecycle = &identitypostgres.LifecyclePlan{EventType: "delivery.receipt-recorded.v1", BeforeVersion: 3, AfterVersion: 4}
		abandonedPlan, err = coordinator.PrepareCommandPlan(abandoned, abandonedCommand, abandonedPlan)
		if err != nil {
			t.Fatal(err)
		}
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
		if !errors.As(err, &unavailable) || recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Validate() != nil {
			t.Fatal("native receipt noncommit recovery", err, recovered.Outcome)
		}
		var unchanged bool
		if err := pool.QueryRow(ctx, `SELECT status_version=3 AND (SELECT count(*) FROM identity.delivery_receipt_commands)=1 AND (SELECT count(*) FROM identity.delivery_receipts)=1 FROM identity.delivery_intents`).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("recovery reapplied receipt", err)
		}
		duplicate := b
		duplicate.CommandID, _ = identity.NewCommandID()
		duplicateCommand, _ := newReceiptCommand(duplicate, q, 3, native.store)
		duplicatePlan := abandonedPlan
		duplicatePlan.Audits = append([]identitypostgres.AuditPlan(nil), abandonedPlan.Audits...)
		duplicatePlan.Audits[0].BindingDigest, _ = deliveryFeatureAuditDigest(duplicate, op)
		duplicatePlan, err = coordinator.PrepareCommandPlan(duplicate, duplicateCommand, duplicatePlan)
		if err != nil {
			t.Fatal(err)
		}
		reservation, _, err = coordinator.ReserveCommand(ctx, duplicate, duplicateCommand, duplicatePlan)
		if err != nil {
			t.Fatal(err)
		}
		duplicateWork, err := coordinator.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		duplicateResult, err := coordinator.ApplyFeature(ctx, duplicateWork, duplicateCommand)
		if err != nil {
			coordinator.Abort(duplicateWork, err)
			t.Fatal(err)
		}
		if _, err := coordinator.Commit(duplicateWork, duplicateResult); err != nil {
			t.Fatal(err)
		}
		var conserved bool
		if err := pool.QueryRow(ctx, `SELECT status_version=4 AND state='confirmed' AND ciphertext IS NULL AND (SELECT count(*) FROM identity.delivery_receipts)=1 AND (SELECT count(*) FROM identity.delivery_receipt_commands WHERE deduplicated AND NOT advanced AND result_state=4)=1 AND (SELECT count(*) FROM outbox_messages WHERE topic='delivery.receipt-recorded.v1')=2 FROM identity.delivery_intents`).Scan(&conserved); err != nil || !conserved {
			t.Fatal("new command duplicated provider event or lost protected observation", err)
		}
		b.CommandID, _ = identity.NewCommandID()
		stale, _ := newReceiptCommand(b, q, 2, native.store)
		declaration.Audits[0].BindingDigest, _ = deliveryFeatureAuditDigest(b, op)
		stalePlan, err := coordinator.PrepareCommandPlan(b, stale, declaration)
		if err != nil {
			t.Fatal(err)
		}
		reservation, _, err = coordinator.ReserveCommand(ctx, b, stale, stalePlan)
		if err != nil {
			t.Fatal(err)
		}
		staleWork, err := coordinator.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		_, err = coordinator.ApplyFeature(ctx, staleWork, stale)
		coordinator.Abort(staleWork, err)
		if !errors.As(err, &conflict) {
			t.Fatal("new receipt command ignored stale fence", err)
		}
		for _, sql := range []string{`UPDATE identity.delivery_receipt_commands SET advanced=false`, `DELETE FROM identity.delivery_receipt_commands`, `TRUNCATE identity.delivery_receipt_commands`} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatal("native receipt result mutable")
			}
		}
	}
}
