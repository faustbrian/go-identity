//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// Only the feature's authenticated source/domain effect is a deliberate seam.
// Counters, keys, migration constraints, snapshots and the coordinator are real.
// This is not signed-primary/factor/browser authentication or a public sender.
type mfaSendCounterFeature struct {
	user identity.UserID
}

func (*mfaSendCounterFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (*mfaSendCounterFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}}
}
func (*mfaSendCounterFeature) ValidateFeatureCommand(identity.Command, kernel.CommandPlan) error {
	return nil
}
func (*mfaSendCounterFeature) AdmitFeaturePreparation(context.Context, kernel.Work, identity.Command) error {
	return nil
}
func (f *mfaSendCounterFeature) MFALoginSendCounterSubject(identity.Command) (identity.UserID, error) {
	return f.user, nil
}
func (f *mfaSendCounterFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	b, registration, _, err := w.FeatureScope(f)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.native_counter_effect(command_id,tenant_id) VALUES($1,$2)`, string(b.CommandID), string(b.TenantID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: registration.Operation, AfterVersion: 1}, nil
}
func (*mfaSendCounterFeature) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryNotCommitted, nil
}

func testNativeMFALoginSendCounters(t *testing.T, ctx context.Context, pool *database.Pool, r *Repository) {
	t.Helper()
	forward, err := (MFALoginSendCounterMigrationSource{Schema: "risk_store", Version: 68}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Populate a legacy window before upgrading. Its original value and times
	// must survive along with all preceding charge/alias/snapshot evidence.
	key := "rc1:7:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO risk_store.counter_windows VALUES('mfa-send-legacy','identity.username.update','session',$1,2,900000000,'2026-10-13 18:00:00Z','2026-10-13 18:15:00Z')`, key); err != nil {
		t.Fatal(err)
	}
	const snapshot = `SELECT jsonb_build_array((SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY tenant_id,operation,dimension,counter_id),'[]') FROM risk_store.counter_windows w),(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY tenant_id,operation,dimension,key_version,key_id),'[]') FROM risk_store.counter_aliases a),(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY command_id),'[]') FROM risk_store.counter_charges c),(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY command_id,dimension),'[]') FROM risk_store.counter_snapshots s))::text`
	var before, after string
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// Install the exact predecessor profiles, then the new atomic forward delta.
	for _, source := range []migrations.Source{VerificationCounterMigrationSource{Schema: "risk_store", Version: 39}, MFACompletionCounterMigrationSource{Schema: "risk_store", Version: 66}, MFARecoveryCounterMigrationSource{Schema: "risk_store", Version: 67}, issuanceHistory(forward)} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, migration := range history {
			if _, err = tx.Exec(ctx, migration.UpSQL()); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("forward browser dimension migration", err)
			}
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("migration reset populated counter authority", err)
	}
	for _, action := range []string{"identity.mfa.otp-verify", "identity.mfa.enable", "identity.password.change"} {
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO risk_store.counter_windows SELECT tenant_id,$1,'browser-flow',counter_id,value,window_us,started_at,expires_at FROM risk_store.counter_windows WHERE tenant_id='mfa-send-legacy'`, action); err == nil {
			t.Fatal("foreign action adopted browser dimension")
		}
	}
	prepare := func(tenant string, sourceUser, projectedUser identity.UserID) (*kernel.Coordinator, identity.CommandBinding, identity.Command, kernel.CommandPlan) {
		t.Helper()
		feature := &mfaSendCounterFeature{user: sourceUser}
		metadata, _ := protectedCommand(t, tenant).Feature()
		metadata.Operation = feature.FeatureOperations()[0]
		metadata.Binding.OperationID, metadata.Binding.SchemaID = metadata.Operation.OperationID, metadata.Operation.SchemaID
		metadata.Binding.UserID, metadata.Binding.AnonymousFlowID, metadata.Binding.RecordID = "", "bbbbbbbbbbbbbbbbbbbbbg", "AQEBAQEBAQEBAQEBAQEBAQ"
		original, err := identity.NewFeaturePreAuthCommand(metadata, auth.NewBearerCredential(strings.Repeat("A", 43)))
		if err != nil {
			t.Fatal(err)
		}
		command, cp, err := r.PrepareMFALoginSendCommandCounters(original, risk.Subject{User: string(projectedUser), Network: "192.0.2.1"}, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
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
		s, _ := command.Feature()
		b := s.Binding
		builder, _ := audit.NewBuilder(audit.BuilderConfig{})
		seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "factor", ID: b.RecordID}, Context: audit.ContextInput{TenantID: tenant, CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "factor", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := kernel.FeatureAuditBindingDigest(b, s.Operation, "factor", seed)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := coord.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "factor", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: s.Operation}, CommandCounters: &cp, Lifecycle: &kernel.LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if err != nil {
			t.Fatal(err)
		}
		return coord, b, command, plan
	}
	coord, b, command, plan := prepare("mfa-send-foreign", "source-user", "forged-user")
	if _, _, err := coord.ReserveCommand(ctx, b, command, plan); err == nil {
		t.Fatal("caller-selected account bypassed registered source")
	}
	var charges int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.counter_charges WHERE tenant_id='mfa-send-foreign'`).Scan(&charges); err != nil || charges != 0 {
		t.Fatal("foreign source left charge", err)
	}
	for index := 0; index < 6; index++ {
		coord, b, command, plan := prepare("mfa-send-budget", "source-user", "source-user")
		reservation, result, err := coord.ReserveCommand(ctx, b, command, plan)
		if index == 5 {
			var forbidden identity.ForbiddenError
			if !errors.As(err, &forbidden) || result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("new send bypassed original browser/account quota", err, result.Outcome)
			}
			continue
		}
		if err != nil {
			t.Fatal("native MFA send counter reservation", err)
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
			t.Fatal("native counter protected commit", err)
		}
		if _, replay, err := coord.ReserveCommand(ctx, b, command, plan); err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original counter replay diverged", err)
		}
	}
	var browsers, sessions, allowed, snapshots, effects int
	var browserValue string
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FILTER(WHERE dimension='browser-flow'),count(*) FILTER(WHERE dimension='session'),max(value) FILTER(WHERE dimension='browser-flow')::text FROM risk_store.counter_windows WHERE tenant_id='mfa-send-budget'`).Scan(&browsers, &sessions, &browserValue); err != nil || browsers != 1 || sessions != 0 || browserValue != "6" {
		t.Fatal("original browser budget invented a session or reset", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE allowed),(SELECT count(*) FROM risk_store.counter_snapshots s JOIN risk_store.counter_charges c USING(command_id) WHERE c.tenant_id='mfa-send-budget'),(SELECT count(*) FROM public.native_counter_effect WHERE tenant_id='mfa-send-budget') FROM risk_store.counter_charges WHERE tenant_id='mfa-send-budget'`).Scan(&charges, &allowed, &snapshots, &effects); err != nil || charges != 6 || allowed != 5 || snapshots != 24 || effects != 5 {
		t.Fatal("native charge/replay/denial effects diverged", err, charges, allowed, snapshots, effects)
	}
	t.Run("otp-completion-populated-upgrade", func(t *testing.T) {
		const insert = `INSERT INTO risk_store.counter_windows SELECT 'otp-completion-upgrade',$1,$2,counter_id,value,window_us,started_at,expires_at FROM risk_store.counter_windows WHERE tenant_id='mfa-send-legacy'`
		if _, err := pool.Raw().Exec(ctx, insert, "identity.mfa.otp-verify", "capability"); err == nil {
			t.Fatal("OTP completion silently enabled before selection")
		}
		if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&before); err != nil {
			t.Fatal(err)
		}
		history, err := (MFAOTPCompletionCounterMigrationSource{Schema: "risk_store", Version: 69}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, history[0].UpSQL()); err != nil {
			t.Fatal("OTP completion forward migration", err)
		}
		if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&after); err != nil || before != after {
			t.Fatal("upgrade changed original allowances or evidence", err)
		}
		for _, pair := range [][2]string{{"identity.mfa.otp-verify", "browser-flow"}, {"identity.mfa.enable", "capability"}, {"identity.password.change", "capability"}} {
			if _, err := pool.Raw().Exec(ctx, insert, pair[0], pair[1]); err == nil {
				t.Fatal("unrelated lane admitted", pair)
			}
		}
		if _, err := pool.Raw().Exec(ctx, insert, "identity.mfa.otp-verify", "capability"); err != nil {
			t.Fatal("selected original-child completion dimension unavailable", err)
		}
	})
}
