//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auditpostgres "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testNativeCancellation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owned *database.Pool, repo *identitypostgres.Repository, audits *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor, custody *Contributor, original identity.CommandBinding) {
	t.Helper()
	worker, err := newAttemptStore(pool, "test", custody.store.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	native := &cancelContributor{store: worker}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, native, audits, lifecycle})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := identitypostgres.NewCoordinator(owned, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	b := original
	op := cancelOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	// First prove a downstream lifecycle failure cannot commit a local stop.
	for _, fail := range []bool{true, false} {
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		command, err := newCancellationCommand(b, 0, 1, [32]byte{9})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := cancellationAuditDigest(b)
		if err != nil {
			t.Fatal(err)
		}
		declaration := identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "delivery_intent", Feature: &identitypostgres.FeatureRegistration{Contributor: native.Descriptor(), Operation: op}, Audits: []identitypostgres.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "delivery.cancelled.v1", BeforeVersion: 1, AfterVersion: 2}}
		plan, err := coordinator.PrepareCommandPlan(b, command, declaration)
		if err != nil {
			t.Fatal("cancel declaration", err)
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
			t.Fatal("foreign invocation entered cancellation")
		}
		result, err := coordinator.ApplyFeature(ctx, work, command)
		if err != nil {
			t.Fatal("cancel apply", err)
		}
		if fail {
			// Reject only the new cancellation lifecycle event, not the existing rows.
			if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages ADD CONSTRAINT cancellation_test_failure CHECK (topic<>'delivery.cancelled.v1')`); err != nil {
				t.Fatal(err)
			}
		}
		committed, err := coordinator.Commit(work, result)
		if fail {
			if err == nil || committed.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("failed lifecycle committed cancellation", err)
			}
			var restored bool
			if err := pool.QueryRow(ctx, `SELECT ((no_op AND state='cancelled' AND ciphertext IS NULL) OR (NOT no_op AND state='planned' AND ciphertext IS NOT NULL)) AND status_version=1 AND local_stop_state IS NULL AND (SELECT count(*) FROM identity.delivery_cancellations)=0 FROM identity.delivery_intents`).Scan(&restored); err != nil || !restored {
				t.Fatal("failed lifecycle retained cancellation prefix", err)
			}
			if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages DROP CONSTRAINT cancellation_test_failure`); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err != nil || committed.Outcome != identity.CommitOutcomeCommitted || committed.Feature.BeforeVersion != 1 || committed.Feature.AfterVersion != 2 {
			t.Fatal("native cancel commit", err)
		}
		var stopped bool
		if err := pool.QueryRow(ctx, `SELECT state='cancelled' AND ciphertext IS NULL AND status_version=2 AND (SELECT count(*) FROM identity.delivery_cancellations WHERE result_state=7 AND local_cancelled)=1 FROM identity.delivery_intents`).Scan(&stopped); err != nil || !stopped {
			t.Fatal("atomic cancellation receipt absent", err)
		}
		reserved, replay, err := coordinator.ReserveCommand(ctx, b, command, plan)
		if err != nil || reserved != (identitypostgres.Reservation{}) || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != committed.AuditEventID {
			t.Fatal("original cancellation replay", err)
		}
		var version string
		if err := pool.QueryRow(ctx, `SELECT status_version::text FROM identity.delivery_intents`).Scan(&version); err != nil || version != "2" {
			t.Fatal("replay renewed status", err)
		}
		changed, _ := command.Feature()
		changed.Fields[1].Value.Bytes[0]++
		changedCommand, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		var conflict identity.ConflictError
		changedPlan, err := coordinator.PrepareCommandPlan(b, changedCommand, declaration)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := coordinator.ReserveCommand(ctx, b, changedCommand, changedPlan); !errors.As(err, &conflict) {
			t.Fatal("changed-reason replay accepted", err)
		}
		for _, sql := range []string{`UPDATE identity.delivery_cancellations SET result_state=10`, `DELETE FROM identity.delivery_cancellations`, `TRUNCATE identity.delivery_cancellations`} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatal("recorded result rewritable")
			}
		}
		for _, kind := range []string{"version", "generation", "subject", "intent"} {
			bad := b
			bad.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			v, g := uint64(2), uint32(0)
			switch kind {
			case "version":
				v = 1
			case "generation":
				g = 1
			case "subject":
				user, err := identity.NewSubjectID()
				if err != nil {
					t.Fatal(err)
				}
				bad.UserID = identity.UserID(user)
			case "intent":
				bad.RecordID = strings.Repeat("b", 64)
			}
			cmd, err := newCancellationCommand(bad, g, v, [32]byte{9})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := cancellationAuditDigest(bad)
			if err != nil {
				t.Fatal(err)
			}
			badPlan := declaration
			badPlan.Audits = append([]identitypostgres.AuditPlan(nil), declaration.Audits...)
			badPlan.Audits[0].BindingDigest = digest
			badPlan.Lifecycle = &identitypostgres.LifecyclePlan{EventType: "delivery.cancelled.v1", BeforeVersion: v, AfterVersion: v + 1}
			badPlan, err = coordinator.PrepareCommandPlan(bad, cmd, badPlan)
			if err != nil {
				t.Fatal(err)
			}
			reserved, _, err := coordinator.ReserveCommand(ctx, bad, cmd, badPlan)
			if err != nil {
				t.Fatal(err)
			}
			w, err := coordinator.Begin(ctx, reserved)
			if err != nil {
				t.Fatal(err)
			}
			_, err = coordinator.ApplyFeature(ctx, w, cmd)
			if !errors.As(err, &conflict) {
				coordinator.Abort(w, err)
				t.Fatal("foreign/stale native fence accepted", kind, err)
			}
			coordinator.Abort(w, err)
			if err := pool.QueryRow(ctx, `SELECT status_version::text FROM identity.delivery_intents`).Scan(&version); err != nil || version != "2" {
				t.Fatal("failed fence mutated current state", err)
			}
		}
	}
}
