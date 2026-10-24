//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// The deliberate seam is the passkey owner, not counter/coordinator authority.
// This proves no WebAuthn, cookie authentication or account/session creation.
type passkeySignupCounterFeature struct {
	counterFeature
	operation identity.FeatureOperation
}

func (*passkeySignupCounterFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (f *passkeySignupCounterFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{f.operation}
}
func (*passkeySignupCounterFeature) AdmitFeaturePreparation(context.Context, kernel.Work, identity.Command) error {
	return nil
}
func (f *passkeySignupCounterFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	b, registration, _, err := w.FeatureScope(f)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.native_counter_effect(command_id,tenant_id) VALUES($1,$2)`, string(b.CommandID), string(b.TenantID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: registration.Operation, AfterVersion: 1}, nil
}

func testNativePasskeySignupCounters(t *testing.T, ctx context.Context, pool *database.Pool, prepare func(*Repository, string, ...time.Time) (*kernel.Coordinator, identity.CommandBinding, identity.Command, kernel.CommandPlan)) {
	t.Helper()
	// Keep the populated predecessor composition independent of sibling tests
	// that deliberately select a different historical migration sequence.
	base, err := (CounterMigrationSource{Base: ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "signup_counter_store", Version: 20}, Version: 21}, Version: 22}, Version: 23}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range base {
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	cfg := protectedConfig(t)
	cfg.Schema = "signup_counter_store"
	r, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Populate every counter-owned table through real predecessor authority.
	coord, binding, original, plan := prepare(r, "signup-predecessor")
	reservation, _, err := coord.ReserveCommand(ctx, binding, original, plan)
	if err != nil {
		t.Fatal(err)
	}
	work, err := coord.Begin(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coord.ApplyFeature(ctx, work, original)
	if err != nil {
		_, _ = coord.Abort(work, err)
		t.Fatal(err)
	}
	if result, err = coord.Commit(work, result); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("predecessor counter effect", err)
	}
	for _, source := range []migrations.Source{
		VerificationCounterMigrationSource{Schema: "signup_counter_store", Version: 39},
		MFACompletionCounterMigrationSource{Schema: "signup_counter_store", Version: 66},
		MFARecoveryCounterMigrationSource{Schema: "signup_counter_store", Version: 67},
		MFALoginSendCounterMigrationSource{Schema: "signup_counter_store", Version: 68},
		MFAOTPCompletionCounterMigrationSource{Schema: "signup_counter_store", Version: 69},
		EmailChangeCounterMigrationSource{Schema: "signup_counter_store", Version: 70},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	key := "rc1:7:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	insert := `INSERT INTO signup_counter_store.counter_windows VALUES('signup-legacy',$1,$2,$3,2,900000000,'2026-10-13 18:00:00Z','2026-10-13 18:15:00Z')`
	legacy := [][2]string{{"identity.password.change", "session"}, {"identity.email.verification-confirm", "capability"}, {"identity.email.change-confirm", "capability"}, {"identity.mfa.totp-verify", "capability"}, {"identity.mfa.recovery-use", "capability"}, {"identity.mfa.otp-verify", "capability"}, {"identity.mfa.otp-send", "browser-flow"}}
	for _, pair := range legacy {
		if _, err := pool.Raw().Exec(ctx, insert, pair[0], pair[1], key); err != nil {
			t.Fatal("legacy dimension unavailable", pair, err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, insert, "identity.passkey.register-options", "device", key); err == nil {
		t.Fatal("signup dimension silently enabled before migration")
	}
	const snapshot = `SELECT jsonb_build_array((SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY tenant_id,operation,dimension,counter_id),'[]') FROM signup_counter_store.counter_windows w),(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY tenant_id,operation,dimension,key_version,key_id),'[]') FROM signup_counter_store.counter_aliases a),(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY command_id),'[]') FROM signup_counter_store.counter_charges c),(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY command_id,dimension),'[]') FROM signup_counter_store.counter_snapshots s),(SELECT COALESCE(jsonb_agg(to_jsonb(k) ORDER BY tenant_id,operation,key_version),'[]') FROM signup_counter_store.counter_key_history k))::text`
	var before, after string
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	history, err := (PasskeySignupCounterMigrationSource{Schema: "signup_counter_store", Version: 71}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("signup migration", err)
	}
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("migration changed populated authority", err)
	}
	for _, partition := range []struct{ table, replacement string }{
		{"counter_windows", "CHECK(value>=0)"},
		{"counter_windows", "CHECK(dimension<>'' AND value>=0)"},
		{"counter_windows", "CHECK(dimension<>'') NOT VALID"},
		{"counter_windows", ""},
		{"counter_snapshots", "CHECK(value>=1)"},
		{"counter_snapshots", "CHECK(dimension<>'') NOT VALID"},
		{"counter_snapshots", ""},
	} {
		t.Run("invalid-predecessor-"+partition.table+partition.replacement, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			constraint := partition.table + "_dimension_check"
			if _, err := tx.Exec(ctx, "ALTER TABLE signup_counter_store."+partition.table+" DROP CONSTRAINT "+constraint); err != nil {
				t.Fatal(err)
			}
			if partition.replacement != "" {
				if _, err := tx.Exec(ctx, "ALTER TABLE signup_counter_store."+partition.table+" ADD CONSTRAINT "+constraint+" "+partition.replacement); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, history[0].UpSQL()); err == nil {
				t.Fatal("foreign/missing/unvalidated check accepted as dimension authority")
			}
		})
	}
	for _, pair := range legacy {
		if _, err := pool.Raw().Exec(ctx, insert, pair[0], pair[1], "rc1:7:"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))); err != nil {
			t.Fatal("migration removed installed dimension", pair, err)
		}
	}
	for _, pair := range [][2]string{{"identity.mfa.otp-send", "device"}, {"identity.passkey.signin-options", "browser-flow"}, {"identity.password.change", "device"}} {
		if _, err := pool.Raw().Exec(ctx, insert, pair[0], pair[1], key); err == nil {
			t.Fatal("foreign action adopted signup dimensions", pair)
		}
	}
	// Verification requires the kernel's actual PasskeyRegistration owner and
	// creation/outbox lifecycle. Its atomic account/session proof is exercised by
	// native passkey signup, not a counter-only feature pretending to provide it.
	for _, action := range []string{"identity.passkey.register-options"} {
		t.Run(action, func(t *testing.T) {
			tenant := "signup-budget-" + action[len("identity.passkey.register-"):]
			for index := 0; index < 6; index++ {
				command := passkeySignupCommand(t, tenant, action)
				command, cp, err := r.PreparePasskeySignupCommandCounters(command, risk.Subject{Network: "192.0.2.1", Device: "original-device"}, time.Now().UTC().Truncate(time.Microsecond))
				if err != nil {
					t.Fatal(err)
				}
				s, _ := command.Feature()
				b := s.Binding
				feature := &passkeySignupCounterFeature{operation: s.Operation}
				directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, &issuanceAudit{}, &issuanceOutbox{}, feature, r})
				if err != nil {
					t.Fatal(err)
				}
				coord, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceQueryPolicy{}}})
				if err != nil {
					t.Fatal(err)
				}
				builder, _ := audit.NewBuilder(audit.BuilderConfig{})
				seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "passkey", ID: b.RecordID}, Context: audit.ContextInput{TenantID: tenant, CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "passkey", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
				if err != nil {
					t.Fatal(err)
				}
				digest, err := kernel.FeatureAuditBindingDigest(b, s.Operation, "passkey", seed)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := coord.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "passkey", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: s.Operation}, CommandCounters: &cp, Lifecycle: &kernel.LifecyclePlan{EventType: "passkey.registered.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
				if err != nil {
					t.Fatal("signup counter plan", err)
				}
				reservation, result, err := coord.ReserveCommand(ctx, b, command, plan)
				if index == 5 {
					var forbidden identity.ForbiddenError
					if !errors.As(err, &forbidden) || result.Outcome != identity.CommitOutcomeNotCommitted {
						t.Fatal("sixth signup escaped canonical budget", err, result.Outcome)
					}
					continue
				}
				if err != nil {
					t.Fatal("signup counter reservation", err)
				}
				work, err := coord.Begin(ctx, reservation)
				if err != nil {
					t.Fatal(err)
				}
				result, err = coord.ApplyFeature(ctx, work, command)
				if err != nil {
					_, _ = coord.Abort(work, err)
					t.Fatal(err)
				}
				result, err = coord.Commit(work, result)
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("signup protected effect", err)
				}
				if _, replay, err := coord.ReserveCommand(ctx, b, command, plan); err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("signup replay", err)
				}
			}
			var charges, allowed, snapshots, effects, browsers, devices, sessions int
			var value string
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE allowed),(SELECT count(*) FROM signup_counter_store.counter_snapshots s JOIN signup_counter_store.counter_charges c USING(command_id) WHERE c.tenant_id=$1),(SELECT count(*) FROM public.native_counter_effect WHERE tenant_id=$1) FROM signup_counter_store.counter_charges WHERE tenant_id=$1`, tenant).Scan(&charges, &allowed, &snapshots, &effects); err != nil || charges != 6 || allowed != 5 || snapshots != 24 || effects != 5 {
				t.Fatal("signup debit/replay/effect divergence", err, charges, allowed, snapshots, effects)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FILTER(WHERE dimension='browser-flow'),count(*) FILTER(WHERE dimension='device'),count(*) FILTER(WHERE dimension IN('subject','session')),max(value)::text FROM signup_counter_store.counter_windows WHERE tenant_id=$1`, tenant).Scan(&browsers, &devices, &sessions, &value); err != nil || browsers != 1 || devices != 1 || sessions != 0 || value != "6" {
				t.Fatal("signup budget reset or invented account/session", err)
			}
		})
	}
}
