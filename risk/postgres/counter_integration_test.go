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
type counterFeature struct{ delay time.Duration }

func (*counterFeature) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*counterFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change-test-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (*counterFeature) ValidateFeatureCommand(identity.Command, identitypostgres.CommandPlan) error {
	return nil
}
func (f *counterFeature) ApplyFeature(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	b, registration, _, e := w.FeatureScope(f)
	if e != nil {
		return identity.FeatureReceipt{}, e
	}
	if _, e := w.Exec(ctx, `INSERT INTO public.native_counter_effect(command_id,tenant_id) VALUES($1,$2)`, string(b.CommandID), string(b.TenantID)); e != nil {
		return identity.FeatureReceipt{}, e
	}
	if f.delay > 0 {
		// Deliberately outlive the selected original evidence interval while
		// staying within Work's lease; this tests the final native check.
		if _, e := w.Exec(ctx, `SELECT pg_sleep($1)`, f.delay.Seconds()); e != nil {
			return identity.FeatureReceipt{}, e
		}
	}
	return identity.FeatureReceipt{Operation: registration.Operation, AfterVersion: 1}, nil
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
	if _, e = pool.Raw().Exec(ctx, `CREATE TABLE public.native_counter_effect(command_id text PRIMARY KEY,tenant_id text NOT NULL)`); e != nil {
		t.Fatal(e)
	}
	old, _ := risk.NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	newer, _ := risk.NewCounterDigestKey(8, bytes.Repeat([]byte{0x32}, 32))
	cfg := protectedConfig(t, old)
	native, e := NewRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	type originalInput struct {
		command  identity.Command
		counters identitypostgres.CommandCounterPlan
	}
	prepareWithFeature := func(r *Repository, tenant string, feature *counterFeature, original *originalInput, at ...time.Time) (*identitypostgres.Coordinator, identity.CommandBinding, identity.Command, identitypostgres.CommandPlan) {
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
		if original != nil {
			c, cp = original.command, original.counters
		}
		s, _ := c.Feature()
		b := s.Binding
		kernel, e := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: time.Second})
		if e != nil {
			t.Fatal(e)
		}
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
	prepare := func(r *Repository, tenant string, at ...time.Time) (*identitypostgres.Coordinator, identity.CommandBinding, identity.Command, identitypostgres.CommandPlan) {
		return prepareWithFeature(r, tenant, &counterFeature{}, nil, at...)
	}
	t.Run("original-evidence-expires-before-commit", func(t *testing.T) {
		shortConfig := protectedConfig(t, old)
		policyConfig := risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}}
		for _, action := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.admin.user-ban", "identity.profile.get"} {
			a, e := shortConfig.CommandCounters.Policy.Admit(action)
			if e != nil {
				t.Fatal(e)
			}
			profile := a.Profile
			if profile.Class == risk.CredentialMutation {
				profile.EvidenceTTL = 500 * time.Millisecond
			}
			policyConfig.Profiles = append(policyConfig.Profiles, profile)
		}
		shortConfig.CommandCounters.Policy, e = risk.NewPolicy(policyConfig)
		if e != nil {
			t.Fatal(e)
		}
		short, e := NewRepository(shortConfig)
		if e != nil {
			t.Fatal(e)
		}
		coord, b, command, p := prepareWithFeature(short, "native-late-expiry", &counterFeature{delay: 650 * time.Millisecond}, nil)
		r, _, e := coord.ReserveCommand(ctx, b, command, p)
		if e != nil {
			t.Fatal(e)
		}
		w, e := coord.Begin(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		defer coord.Abort(w, identity.UnavailableError{})
		result, e := coord.ApplyFeature(ctx, w, command)
		if e != nil {
			t.Fatal("positive original interval failed before mutation", e)
		}
		result, e = coord.Commit(w, result)
		var forbidden identity.ForbiddenError
		if !errors.As(e, &forbidden) || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("expired original evidence renewed at final commit", e, result.Outcome)
		}
		var effects, outbox, audits, charges int
		if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.native_counter_effect WHERE command_id=$1),(SELECT count(*) FROM public.risk_outbox WHERE command_id=$1),(SELECT count(*) FROM public.risk_audit WHERE command_id=$1),(SELECT count(*) FROM risk_store.counter_charges WHERE tenant_id=$2)`, string(b.CommandID), string(b.TenantID)).Scan(&effects, &outbox, &audits, &charges); e != nil || effects != 0 || outbox != 0 || audits != 1 || charges != 1 {
			t.Fatal("late denial lost rollback or charge custody", e, effects, outbox, audits, charges)
		}
	})
	t.Run("current-native-admission", func(t *testing.T) {
		for _, mode := range []string{"allow", "takeover", "rotation-takeover", "missing-original-alias", "denied-current-window", "missing-charge", "missing-window", "changed-key-history", "missing-snapshot"} {
			t.Run(mode, func(t *testing.T) {
				tenant := "native-admission-" + mode
				coord, b, c, p := prepare(native, tenant)
				r, result, e := coord.ReserveCommand(ctx, b, c, p)
				if e != nil || result.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("reserve native attempt", e)
				}
				raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				switch mode {
				case "rotation-takeover", "missing-original-alias":
					rotated, e := NewRepository(protectedConfig(t, newer, old))
					if e != nil {
						t.Fatal(e)
					}
					if mode == "missing-original-alias" {
						other, ob, oc, op := prepare(rotated, tenant)
						if _, _, e := other.ReserveCommand(ctx, ob, oc, op); e != nil {
							t.Fatal(e)
						}
						if _, e := pool.Raw().Exec(ctx, `DELETE FROM risk_store.counter_aliases WHERE tenant_id=$1 AND key_version=7`, tenant); e != nil {
							t.Fatal(e)
						}
					}
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); e != nil {
						t.Fatal(e)
					}
					coord, b, c, p = prepareWithFeature(rotated, tenant, &counterFeature{}, &originalInput{c, *p.CommandCounters})
					r, result, e = coord.ReserveCommand(ctx, b, c, p)
					if e != nil {
						t.Fatal(e)
					}
				case "takeover":
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); e != nil {
						t.Fatal(e)
					}
					r, result, e = coord.ReserveCommand(ctx, b, c, p)
					if e != nil {
						t.Fatal(e)
					}
				case "denied-current-window":
					for range 5 {
						other, ob, oc, op := prepare(native, tenant)
						_, _, _ = other.ReserveCommand(ctx, ob, oc, op)
					}
				case "missing-charge":
					if _, e := pool.Raw().Exec(ctx, `DELETE FROM risk_store.counter_snapshots WHERE command_id=$1;`, raw); e != nil {
						t.Fatal(e)
					}
					if _, e := pool.Raw().Exec(ctx, `DELETE FROM risk_store.counter_charges WHERE command_id=$1`, raw); e != nil {
						t.Fatal(e)
					}
				case "missing-window":
					if _, e := pool.Raw().Exec(ctx, `DELETE FROM risk_store.counter_aliases WHERE tenant_id=$1`, tenant); e != nil {
						t.Fatal(e)
					}
				case "changed-key-history":
					if _, e := pool.Raw().Exec(ctx, `UPDATE risk_store.counter_key_history SET tenant_key=$2 WHERE tenant_id=$1`, tenant, "rc1:7:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); e != nil {
						t.Fatal(e)
					}
				case "missing-snapshot":
					if _, e := pool.Raw().Exec(ctx, `DELETE FROM risk_store.counter_snapshots WHERE command_id=$1 AND dimension='session'`, raw); e != nil {
						t.Fatal(e)
					}
				}
				w, e := coord.Begin(ctx, r)
				if e != nil {
					t.Fatal("native current admission cannot enter domain", e)
				}
				defer coord.Abort(w, identity.UnavailableError{})
				result, e = coord.ApplyFeature(ctx, w, c)
				if mode == "allow" || mode == "takeover" || mode == "rotation-takeover" {
					if e != nil {
						t.Fatal("native current admission denied matching charge", e)
					}
					result, e = coord.Commit(w, result)
					if e != nil || result.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("native guarded commit", e)
					}
				} else {
					if e == nil {
						t.Fatal("invalid current authority allowed domain mutation")
					}
					result, _ = coord.Abort(w, e)
					if result.Outcome != identity.CommitOutcomeNotCommitted {
						t.Fatal("native denied rollback unresolved", result.Outcome)
					}
				}
				var effects, outbox, audits int
				if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.native_counter_effect WHERE command_id=$1),(SELECT count(*) FROM public.risk_outbox WHERE command_id=$1),(SELECT count(*) FROM public.risk_audit WHERE command_id=$1)`, string(b.CommandID)).Scan(&effects, &outbox, &audits); e != nil {
					t.Fatal(e)
				}
				if mode == "allow" || mode == "takeover" || mode == "rotation-takeover" {
					if effects != 1 || outbox != 1 {
						t.Fatal("native mutation/receipt not atomic", effects, outbox)
					}
				} else if effects != 0 || outbox != 0 {
					t.Fatal("native denial leaked domain prefix", effects, outbox)
				}
				if audits != 1 {
					t.Fatal("missing native classified audit", audits)
				}
			})
		}
	})
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
