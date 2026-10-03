//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Same-Work SQL effect seams prove native atomicity, not production audit/outbox
// adapter interoperability. Neither seam substitutes for native risk custody.
type issuanceAudit struct{ fail bool }

func (*issuanceAudit) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1}
}
func (a *issuanceAudit) PersistAudits(ctx context.Context, w identitypostgres.Work) error {
	rows, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, r := range rows {
		b, e := audit.CanonicalJSON(r.Record)
		if e != nil {
			return e
		}
		if _, e = w.Exec(ctx, `INSERT INTO public.risk_audit(event_id,command_id,record) VALUES($1,$2,$3::jsonb)`, r.Record.ID(), r.Record.Attributes()["command.id"], string(b)); e != nil {
			return e
		}
	}
	if a.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*issuanceAudit) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	return issuanceEffect(ctx, w, "public.risk_audit")
}

type issuanceOutbox struct{ fail bool }

func (*issuanceOutbox) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
}
func (o *issuanceOutbox) PersistLifecycle(ctx context.Context, w identitypostgres.Work) error {
	rows, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, r := range rows {
		if _, err = w.Exec(ctx, `INSERT INTO public.risk_outbox(event_id,command_id,event_type,subject_id,subject_type) VALUES($1,$2,$3,$4,$5)`, r.ID, string(r.CommandID), r.EventType, r.SubjectID, r.SubjectType); err != nil {
			return err
		}
	}
	if o.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*issuanceOutbox) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	return issuanceEffect(ctx, w, "public.risk_outbox")
}
func issuanceEffect(ctx context.Context, w identitypostgres.RecoveryWork, table string) (identitypostgres.RecoveryStatus, error) {
	b, e := w.Scope()
	if e != nil {
		return identitypostgres.RecoveryUnknown, e
	}
	rows, e := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE command_id=$1)`, string(b.CommandID))
	if e != nil {
		return identitypostgres.RecoveryUnknown, e
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return identitypostgres.RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return identitypostgres.RecoveryCommitted, nil
	}
	return identitypostgres.RecoveryNotCommitted, nil
}

type issuanceHistory []migrations.Migration

type issuanceQueryPolicy struct{}

func (issuanceQueryPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
}

func (h issuanceHistory) Load(context.Context) ([]migrations.Migration, error) {
	return append([]migrations.Migration(nil), h...), nil
}

func TestIssuedEvidenceSameWorkIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_RISK_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, s := context.WithTimeout(context.Background(), 3*time.Second)
		defer s()
		if e := admin.Close(c); e != nil {
			t.Error("admin cleanup")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "risk_issue_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, s := context.WithTimeout(context.Background(), 3*time.Second)
		defer s()
		if _, e := admin.Exec(c, "DROP DATABASE "+quoted); e != nil {
			t.Error("database cleanup")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	kernel, err := (identitypostgres.MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	native, err := (IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := migrations.NewRunner(issuanceHistory(append(append([]migrations.Migration(nil), kernel...), native[0])), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = initial.Up(ctx); err != nil {
		t.Fatal("original install", err)
	}
	// Seed an actual old-format encrypted row before the additive migration.
	// Foundation command metadata is deliberately unknown, never invented success.
	legacyIssue, _ := evaluatedIssue(t, risk.PhoneResetInitiation)
	legacyRecord, err := legacyIssue.Materialize(legacyIssue.Prepared().PreparedAt)
	if err != nil {
		t.Fatal(err)
	}
	legacyBinding := issueBinding(legacyIssue.Prepared())
	legacyBinding.RecordID = "rei1_1_" + base64.RawURLEncoding.EncodeToString(legacyRecord.IntentDigest[:])
	legacyCipher, err := newRecordCipher(map[string][]byte{"wrapping_v1": wrappingKey(1)}, "wrapping_v1")
	if err != nil {
		t.Fatal(err)
	}
	legacyEnvelope, err := legacyCipher.seal(ctx, legacyBinding, legacyRecord)
	if err != nil {
		t.Fatal(err)
	}
	legacyID, _ := base64.RawURLEncoding.DecodeString(string(legacyBinding.CommandID))
	legacyDigest := bindingDigest(legacyBinding)
	if _, err = db.ExecContext(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, legacyID, string(legacyBinding.TenantID), legacyBinding.OperationID, legacyDigest[:], []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, legacyID, string(legacyBinding.TenantID), legacyBinding.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO risk_store.issued_evidence VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11,$12,$13,$14,'issued',$15)`, string(legacyBinding.TenantID), legacyID, legacyBinding.OperationID, legacyBinding.RecordID, string(legacyBinding.UserID), string(legacyIssue.Prepared().Binding.Purpose), strconv.FormatUint(legacyBinding.PolicyVersion, 10), int64(legacyRecord.KeyVersion), legacyDigest[:], legacyRecord.IntentDigest[:], legacyRecord.ProofDigest[:], legacyRecord.EvidenceDigest[:], legacyRecord.IssuedAt, legacyRecord.ExpiresAt, legacyEnvelope); err != nil {
		t.Fatal(err)
	}
	var legacyBefore, legacyAfter string
	if err = db.QueryRowContext(ctx, `SELECT row_to_json(e)::text FROM risk_store.issued_evidence e WHERE record_id=$1`, legacyBinding.RecordID).Scan(&legacyBefore); err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(issuanceHistory(append(kernel, native...)), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("native migrations", err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("populated upgrade replay", err)
	}
	if err = db.QueryRowContext(ctx, `SELECT row_to_json(e)::text FROM risk_store.issued_evidence e WHERE record_id=$1`, legacyBinding.RecordID).Scan(&legacyAfter); err != nil || legacyBefore != legacyAfter {
		t.Fatal("legacy custody rewritten", err)
	}
	legacyMetadata := legacyRecord
	legacyMetadata.Reference = risk.RiskEvidenceRef{}
	if restored, e := legacyCipher.open(ctx, legacyBinding, legacyMetadata, legacyEnvelope); e != nil || restored != legacyRecord {
		t.Fatal("legacy response lost", e)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant','subject','active',1);CREATE TABLE public.risk_audit(event_id text PRIMARY KEY,command_id text NOT NULL,record jsonb);CREATE TABLE public.risk_outbox(event_id text PRIMARY KEY,command_id text NOT NULL,event_type text NOT NULL,subject_id text NOT NULL,subject_type text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, s := context.WithTimeout(context.Background(), 3*time.Second)
		defer s()
		if e := pool.Close(c); e != nil {
			t.Error("pool cleanup")
		}
	}()
	_, key := evaluatedIssue(t, risk.PhoneResetInitiation)
	repo, err := NewRepository(Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1"})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditing, outbox := &issuanceAudit{}, &issuanceOutbox{}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{domain, auditing, outbox, repo})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceQueryPolicy{}}})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(t *testing.T, phase risk.IssuancePhase, at time.Time) (identity.CommandBinding, identity.Command, identitypostgres.CommandPlan, risk.EvidenceIssue) {
		t.Helper()
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		issue, _ := evaluatedIssueAt(t, phase, at, string(id))
		cmd, e := MapIssue(issue, issueBinding(issue.Prepared()))
		if e != nil {
			t.Fatal(e)
		}
		spec, _ := cmd.Feature()
		b := spec.Binding
		builder, e := audit.NewBuilder(audit.BuilderConfig{})
		if e != nil {
			t.Fatal(e)
		}
		seed, e := builder.Build(audit.RecordInput{OccurredAt: at, Action: "identity.risk.decide", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "risk_evidence", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "risk_evidence", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
		if e != nil {
			t.Fatal(e)
		}
		digest, e := identitypostgres.FeatureAuditBindingDigest(b, IssueOperation(), "risk_evidence", seed)
		if e != nil {
			t.Fatal(e)
		}
		plan, e := coordinator.PrepareCommandPlan(b, cmd, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "risk_evidence", Feature: &identitypostgres.FeatureRegistration{Contributor: repo.Descriptor(), Operation: IssueOperation()}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "risk.evidence_issued.v1", AfterVersion: 1}, Audits: []identitypostgres.AuditPlan{{EventType: "identity.risk.decide", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if e != nil {
			t.Fatal("prepare", e)
		}
		return b, cmd, plan, issue
	}
	counts := func(t *testing.T, b identity.CommandBinding, wantIssued, wantSuccess, wantOutbox int) {
		t.Helper()
		raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var i, a, o int
		err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM risk_store.issued_evidence WHERE command_id=$1),(SELECT count(*) FROM public.risk_audit WHERE command_id=$2 AND record->>'outcome'='1'),(SELECT count(*) FROM public.risk_outbox WHERE command_id=$2)`, raw, string(b.CommandID)).Scan(&i, &a, &o)
		if err != nil || i != wantIssued || a != wantSuccess || o != wantOutbox {
			t.Fatalf("atomic state %d/%d/%d: %v", i, a, o, err)
		}
	}
	for _, phase := range []risk.IssuancePhase{risk.PhoneResetInitiation, risk.PhoneResetCompletion} {
		t.Run(string(phase), func(t *testing.T) {
			b, cmd, plan, issue := prepare(t, phase, time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second))
			r, res, e := coordinator.ReserveCommand(ctx, b, cmd, plan)
			if e != nil || res.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("reserve", e)
			}
			w, e := coordinator.Begin(ctx, r)
			if e != nil {
				t.Fatal(e)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			if _, e := repo.ApplyFeature(ctx, w, cmd); e == nil {
				t.Fatal("pre-invocation handle admitted")
			}
			result, e := coordinator.ApplyFeature(ctx, w, cmd)
			if e != nil {
				t.Fatal("apply", e)
			}
			counts(t, b, 0, 0, 0)
			result, e = coordinator.Commit(w, result)
			if e != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("commit", e)
			}
			counts(t, b, 1, 1, 1)
			var lifecycleID, lifecycleType string
			if e = db.QueryRowContext(ctx, `SELECT subject_id,subject_type FROM public.risk_outbox WHERE command_id=$1`, string(b.CommandID)).Scan(&lifecycleID, &lifecycleType); e != nil || lifecycleID != string(b.CommandID) || lifecycleType != "risk_evidence" {
				t.Fatal("lifecycle exposed native digest", e)
			}
			var issued, expiry time.Time
			var ciphertext []byte
			var purpose string
			if e = db.QueryRowContext(ctx, `SELECT issued_at,expires_at,response_envelope,purpose FROM risk_store.issued_evidence WHERE tenant_id=$1 AND record_id=$2`, string(b.TenantID), b.RecordID).Scan(&issued, &expiry, &ciphertext, &purpose); e != nil {
				t.Fatal(e)
			}
			if issued.Before(issue.Prepared().PreparedAt) || !expiry.Equal(issue.Prepared().ExpiresAt) || purpose != string(issue.Prepared().Binding.Purpose) {
				t.Fatal("database time/original expiry/purpose changed")
			}
			record, e := issue.Materialize(issued.UTC())
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(ciphertext, []byte(record.Reference.Reveal())) {
				t.Fatal("plaintext reference stored")
			}
			metadata := record
			metadata.Reference = risk.RiskEvidenceRef{}
			decoded, e := repo.cipher.open(ctx, b, metadata, ciphertext)
			if e != nil || decoded != record {
				t.Fatal("original reference custody", e)
			}
			if _, e = runner.Up(ctx); e != nil {
				t.Fatal("populated migration replay", e)
			}
			_, replay, e := coordinator.ReserveCommand(ctx, b, cmd, plan)
			if e != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != result.AuditEventID {
				t.Fatal("exact replay", e)
			}
			counts(t, b, 1, 1, 1)
		})
	}
	for _, mode := range []string{"audit failure", "outbox failure", "expired", "future"} {
		t.Run(mode, func(t *testing.T) {
			at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
			if mode == "expired" {
				at = at.Add(-time.Hour)
			}
			if mode == "future" {
				at = at.Add(time.Hour)
			}
			b, cmd, plan, _ := prepare(t, risk.PhoneResetInitiation, at)
			auditing.fail, outbox.fail = mode == "audit failure", mode == "outbox failure"
			defer func() { auditing.fail, outbox.fail = false, false }()
			r, _, e := coordinator.ReserveCommand(ctx, b, cmd, plan)
			if e != nil {
				t.Fatal(e)
			}
			w, e := coordinator.Begin(ctx, r)
			if e != nil {
				t.Fatal(e)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			result, e := coordinator.ApplyFeature(ctx, w, cmd)
			if e == nil {
				result, e = coordinator.Commit(w, result)
			} else {
				result, e = coordinator.Abort(w, e)
			}
			if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("failed issuance committed")
			}
			counts(t, b, 0, 0, 0)
		})
	}
	for _, mode := range []string{"live pending", "expired absent", "positive native", "foreign native"} {
		t.Run("recovery "+mode, func(t *testing.T) {
			b, cmd, plan, issue := prepare(t, risk.PhoneResetInitiation, time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second))
			if _, _, e := coordinator.ReserveCommand(ctx, b, cmd, plan); e != nil {
				t.Fatal(e)
			}
			q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if mode != "live pending" {
				if _, e := db.ExecContext(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "positive native" || mode == "foreign native" {
				// Deliberate inconsistent historical fixture: native effect exists but
				// no terminal receipt. It must prevent unanimous rollback proof.
				record, e := issue.Materialize(time.Now().UTC().Truncate(time.Microsecond))
				if e != nil {
					t.Fatal(e)
				}
				envelope, e := repo.cipher.seal(ctx, b, record)
				if e != nil {
					t.Fatal(e)
				}
				digest := bindingDigest(b)
				if mode == "foreign native" {
					digest[0] ^= 1
				}
				if _, e = db.ExecContext(ctx, `INSERT INTO risk_store.issued_evidence VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11,$12,$13,$14,'issued',$15)`, string(b.TenantID), raw, b.OperationID, b.RecordID, string(b.UserID), string(issue.Prepared().Binding.Purpose), strconv.FormatUint(b.PolicyVersion, 10), int64(record.KeyVersion), digest[:], record.IntentDigest[:], record.ProofDigest[:], record.EvidenceDigest[:], record.IssuedAt, record.ExpiresAt, envelope); e != nil {
					t.Fatal(e)
				}
			}
			observed, e := coordinator.RecoverCommand(ctx, q, caller)
			if mode == "expired absent" {
				if e == nil || observed.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("negative recovery", e)
				}
				counts(t, b, 0, 0, 0)
			} else {
				if observed.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("unproved rollback", e)
				}
				var state string
				if err := db.QueryRowContext(ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, raw).Scan(&state); err != nil || state != "pending" {
					t.Fatal("positive/unknown effect released", err)
				}
			}
		})
	}
}
