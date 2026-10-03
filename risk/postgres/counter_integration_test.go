//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// Only the protected feature owner is a seam; native counter policy, SQL,
// migrations and coordinator reservations are real. No password mutation runs.
type counterFeature struct{}

func (*counterFeature) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*counterFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change-test-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (*counterFeature) ValidateFeatureCommand(identity.Command, identitypostgres.CommandPlan) error {
	return nil
}
func (*counterFeature) ApplyFeature(context.Context, identitypostgres.Work, identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, identity.UnavailableError{}
}
func (*counterFeature) RecoverParticipant(context.Context, identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	return identitypostgres.RecoveryNotCommitted, nil
}

func testNativeProtectedCounters(t *testing.T, ctx context.Context, pool *database.Pool) {
	history, e := (CounterMigrationSource{Base: ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}, Version: 22}, Version: 23}).Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Raw().Exec(ctx, history[3].UpSQL()); e != nil {
		t.Fatal(e)
	}
	old, _ := risk.NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	newer, _ := risk.NewCounterDigestKey(8, bytes.Repeat([]byte{0x32}, 32))
	cfg := protectedConfig(t, old)
	native, e := NewRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	prepare := func(r *Repository, tenant string, at ...time.Time) (*identitypostgres.Coordinator, identity.CommandBinding, identity.Command, identitypostgres.CommandPlan) {
		t.Helper()
		c := protectedCommand(t, tenant)
		preparedAt := time.Now().UTC().Truncate(time.Microsecond)
		if len(at) == 1 {
			preparedAt = at[0]
		}
		c, cp, e := r.PrepareCommandCounters(c, risk.Subject{User: "subject", Session: "session", Network: "2001:db8::1"}, preparedAt)
		if e != nil {
			t.Fatal(e)
		}
		s, _ := c.Feature()
		b := s.Binding
		kernel, e := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: time.Second})
		if e != nil {
			t.Fatal(e)
		}
		feature := &counterFeature{}
		registry, e := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{kernel, &issuanceAudit{}, &issuanceOutbox{}, feature, r})
		if e != nil {
			t.Fatal(e)
		}
		coord, e := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceQueryPolicy{}}})
		if e != nil {
			t.Fatal(e)
		}
		builder, _ := audit.NewBuilder(audit.BuilderConfig{})
		seed, e := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "password.change", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "password", ID: b.RecordID}, Context: audit.ContextInput{TenantID: tenant, CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "password", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
		if e != nil {
			t.Fatal(e)
		}
		digest, e := identitypostgres.FeatureAuditBindingDigest(b, s.Operation, "password", seed)
		if e != nil {
			t.Fatal(e)
		}
		p, e := coord.PrepareCommandPlan(b, c, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "password", Feature: &identitypostgres.FeatureRegistration{Contributor: feature.Descriptor(), Operation: s.Operation}, CommandCounters: &cp, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "password.changed.v1", AfterVersion: 1}, Audits: []identitypostgres.AuditPlan{{EventType: "password.change", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if e != nil {
			t.Fatal(e)
		}
		return coord, b, c, p
	}
	var firstB identity.CommandBinding
	var firstC identity.Command
	var firstP identitypostgres.CommandPlan
	var firstCoord *identitypostgres.Coordinator
	for i := 1; i <= 6; i++ {
		coord, b, c, p := prepare(native, "native-counter")
		_, result, e := coord.ReserveCommand(ctx, b, c, p)
		if i <= 5 {
			if e != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("allowed charge", i, e)
			}
		} else if e == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("denial not committed", e)
		}
		if i == 1 {
			firstCoord, firstB, firstC, firstP = coord, b, c, p
		}
		_, replayed, e := coord.ReserveCommand(ctx, b, c, p)
		if e != nil || replayed.Outcome != result.Outcome {
			t.Fatal("exact replay changed", e)
		}
	}
	var value string
	var charges, windows, snapshots int
	if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT max(value)::text FROM risk_store.counter_windows WHERE tenant_id='native-counter'),(SELECT count(*) FROM risk_store.counter_charges WHERE tenant_id='native-counter'),(SELECT count(*) FROM risk_store.counter_windows WHERE tenant_id='native-counter'),(SELECT count(*) FROM risk_store.counter_snapshots s JOIN risk_store.counter_charges c USING(command_id) WHERE c.tenant_id='native-counter')`).Scan(&value, &charges, &windows, &snapshots); e != nil || value != "6" || charges != 6 || windows != 4 || snapshots != 24 {
		t.Fatal("wrong exact-once snapshots", e, value, charges, windows, snapshots)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(firstB.CommandID))
	if _, e = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); e != nil {
		t.Fatal(e)
	}
	if _, result, e := firstCoord.ReserveCommand(ctx, firstB, firstC, firstP); e != nil || result.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("takeover", e)
	}
	if e = pool.Raw().QueryRow(ctx, `SELECT generation::text FROM risk_store.counter_charges WHERE command_id=$1`, raw).Scan(&value); e != nil || value != "2" {
		t.Fatal("charge generation did not follow owner", e)
	}
	if _, e = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); e != nil {
		t.Fatal(e)
	}
	q := identity.RecoveryQuery{CommandID: firstB.CommandID, TenantID: firstB.TenantID, UserID: firstB.UserID, ActorID: firstB.ActorID, ActorKind: firstB.ActorKind, OperationID: firstB.OperationID, RecordID: firstB.RecordID}
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(firstB.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(firstB.ActorID), Kind: firstB.ActorKind}, Action: authorization.Action(firstB.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(firstB.UserID)}}}
	if result, e := firstCoord.RecoverCommand(ctx, q, caller); result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("matching charge blocked proved domain noncommit", e, result.Outcome)
	}
	if e = pool.Raw().QueryRow(ctx, `SELECT max(value)::text FROM risk_store.counter_windows WHERE tenant_id='native-counter'`).Scan(&value); e != nil || value != "6" {
		t.Fatal("recovery refunded charged attempt", e)
	}
	rotated, e := NewRepository(protectedConfig(t, newer, old))
	if e != nil {
		t.Fatal(e)
	}
	coord, b, c, p := prepare(rotated, "native-counter")
	if _, result, e := coord.ReserveCommand(ctx, b, c, p); e == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("rotation reset allowance", e)
	}
	if e = pool.Raw().QueryRow(ctx, `SELECT max(value)::text,count(*) FROM risk_store.counter_windows WHERE tenant_id='native-counter'`).Scan(&value, &windows); e != nil || value != "7" || windows != 4 {
		t.Fatal("rotation forked counter", e)
	}
	removed, e := NewRepository(protectedConfig(t, newer))
	if e != nil {
		t.Fatal(e)
	}
	coord, b, c, p = prepare(removed, "native-counter")
	if _, _, e := coord.ReserveCommand(ctx, b, c, p); e == nil {
		t.Fatal("unretired key omission admitted")
	}
	if e = pool.Raw().QueryRow(ctx, `SELECT max(value)::text FROM risk_store.counter_windows WHERE tenant_id='native-counter'`).Scan(&value); e != nil || value != "7" {
		t.Fatal("failed rotation leaked increment", e)
	}
	t.Run("exclusive-preparation-expiry", func(t *testing.T) {
		coord, b, c, p := prepare(native, "counter-expired", time.Now().UTC().Truncate(time.Microsecond).Add(-15*time.Minute))
		if _, _, e := coord.ReserveCommand(ctx, b, c, p); e == nil {
			t.Fatal("expired preparation charged")
		}
		var n int
		if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.counter_windows WHERE tenant_id='counter-expired')+(SELECT count(*) FROM risk_store.counter_key_history WHERE tenant_id='counter-expired')+(SELECT count(*) FROM identity.commands WHERE tenant_id='counter-expired')`).Scan(&n); e != nil || n != 0 {
			t.Fatal("expired preparation leaked prefix", e, n)
		}
	})
	t.Run("window-expiry-and-saturation", func(t *testing.T) {
		if _, e := pool.Raw().Exec(ctx, `UPDATE risk_store.counter_windows SET started_at=started_at-interval '15 minutes',expires_at=expires_at-interval '15 minutes' WHERE tenant_id='native-counter'`); e != nil {
			t.Fatal(e)
		}
		coord, b, c, p := prepare(rotated, "native-counter")
		if _, _, e := coord.ReserveCommand(ctx, b, c, p); e != nil {
			t.Fatal("expired windows not reset", e)
		}
		if e := pool.Raw().QueryRow(ctx, `SELECT max(value)::text FROM risk_store.counter_windows WHERE tenant_id='native-counter'`).Scan(&value); e != nil || value != "1" {
			t.Fatal("window reset lost original boundary", e)
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE risk_store.counter_windows SET value=18446744073709551615 WHERE tenant_id='native-counter'`); e != nil {
			t.Fatal(e)
		}
		coord, b, c, p = prepare(rotated, "native-counter")
		if _, result, e := coord.ReserveCommand(ctx, b, c, p); e == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("overflow permitted attempt", e)
		}
		if e := pool.Raw().QueryRow(ctx, `SELECT min(value)::text FROM risk_store.counter_windows WHERE tenant_id='native-counter'`).Scan(&value); e != nil || value != "18446744073709551615" {
			t.Fatal("counter wrapped", e)
		}
	})
	t.Run("snapshot-failure-rolls-back-all-prefixes", func(t *testing.T) {
		if _, e := pool.Raw().Exec(ctx, `ALTER TABLE risk_store.counter_snapshots ADD CONSTRAINT test_snapshot_failure CHECK(false) NOT VALID`); e != nil {
			t.Fatal(e)
		}
		coord, b, c, p := prepare(native, "counter-rollback")
		_, _, reserveErr := coord.ReserveCommand(ctx, b, c, p)
		if _, e := pool.Raw().Exec(ctx, `ALTER TABLE risk_store.counter_snapshots DROP CONSTRAINT test_snapshot_failure`); e != nil {
			t.Fatal(e)
		}
		if reserveErr == nil {
			t.Fatal("snapshot failure granted ownership")
		}
		var n int
		if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.counter_windows WHERE tenant_id='counter-rollback')+(SELECT count(*) FROM risk_store.counter_key_history WHERE tenant_id='counter-rollback')+(SELECT count(*) FROM risk_store.counter_charges WHERE tenant_id='counter-rollback')+(SELECT count(*) FROM identity.commands WHERE tenant_id='counter-rollback')`).Scan(&n); e != nil || n != 0 {
			t.Fatal("snapshot error left durable prefix", e, n)
		}
	})
	t.Run("concurrent-hot-keys", func(t *testing.T) {
		type input struct {
			c       *identitypostgres.Coordinator
			b       identity.CommandBinding
			command identity.Command
			p       identitypostgres.CommandPlan
		}
		inputs := make([]input, 8)
		for i := range inputs {
			c, b, command, p := prepare(native, "counter-hot")
			inputs[i] = input{c, b, command, p}
		}
		type resolution struct {
			outcome identity.CommitOutcome
			err     error
		}
		results := make(chan resolution, len(inputs))
		start := make(chan struct{})
		for _, v := range inputs {
			go func(v input) {
				<-start
				_, result, e := v.c.ReserveCommand(ctx, v.b, v.command, v.p)
				results <- resolution{result.Outcome, e}
			}(v)
		}
		close(start)
		allowed, denied := 0, 0
		valid := true
		for range inputs {
			result := <-results
			switch result.outcome {
			case identity.CommitOutcomeInProgress:
				allowed++
				valid = valid && result.err == nil
			case identity.CommitOutcomeNotCommitted:
				denied++
				var forbidden identity.ForbiddenError
				valid = valid && errors.As(result.err, &forbidden)
			default:
				valid = false
			}
		}
		if !valid || allowed != 5 || denied != 3 {
			t.Fatal("concurrent threshold undercounted", allowed, denied)
		}
		if e := pool.Raw().QueryRow(ctx, `SELECT min(value)::text FROM risk_store.counter_windows WHERE tenant_id='counter-hot'`).Scan(&value); e != nil || value != "8" {
			t.Fatal("lost concurrent increment", e)
		}
	})
}
