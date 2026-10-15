//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
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

type issuanceDenyPolicy struct{}

func (issuanceDenyPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
}

type foreignIssuanceAudit struct{ issuanceAudit }

func (*foreignIssuanceAudit) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "foreign/postgres", ContractID: "identity.audit", Version: 1}
}

type auditDescriptorVariant struct {
	*auditpostgres.IdentityContributor
	descriptor identitypostgres.ContributorDescriptor
}

func (a auditDescriptorVariant) Descriptor() identitypostgres.ContributorDescriptor {
	return a.descriptor
}

type lifecycleDescriptorVariant struct {
	*identityoutbox.Contributor
	descriptor identitypostgres.ContributorDescriptor
}

func (l lifecycleDescriptorVariant) Descriptor() identitypostgres.ContributorDescriptor {
	return l.descriptor
}

// Test-only interleaving boundary: both public issuers finish independent
// evaluations before invoking the real executor. No durable outcome is faked.
type concurrentIssuance struct {
	delegate *Executor
	arrivals atomic.Int32
	ready    chan struct{}
}

func (c *concurrentIssuance) Resolve(ctx context.Context, i risk.EvidenceIntent) (risk.EvidenceExecution, error) {
	return c.delegate.Resolve(ctx, i)
}
func (c *concurrentIssuance) Execute(ctx context.Context, i risk.EvidenceIssue) (risk.EvidenceExecution, error) {
	if c.arrivals.Add(1) == 2 {
		close(c.ready)
	}
	select {
	case <-c.ready:
		return c.delegate.Execute(ctx, i)
	case <-ctx.Done():
		return risk.EvidenceExecution{}, ctx.Err()
	}
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
	ownedAuditRoles := false
	defer func() {
		c, s := context.WithTimeout(context.Background(), 3*time.Second)
		defer s()
		if _, e := admin.Exec(c, "DROP DATABASE "+quoted); e != nil {
			t.Error("database cleanup")
		}
		if ownedAuditRoles {
			if _, e := admin.Exec(c, "DROP ROLE audit_writer,audit_reader,audit_retention"); e != nil {
				t.Error("owned audit role cleanup")
			}
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
	executorConfig := func(native *Repository, policy authorization.Service) ExecutorConfig {
		read := &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: policy}
		return ExecutorConfig{Pool: pool, Repository: native, Audit: auditing, Lifecycle: outbox, Coordinator: identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: read, AdmissionPolicy: read}, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "phone-service"}, Tenant: "tenant", Action: "identity.risk.evaluate", Resource: authorization.Resource{Type: "identity.user", ID: "subject"}}}, PolicyID: "risk-policy", RetentionPolicyVersion: 1}
	}
	newExecutor := func(t *testing.T, native *Repository, policy authorization.Service) *Executor {
		t.Helper()
		e, err := NewExecutor(executorConfig(native, policy))
		if err != nil {
			t.Fatal("official executor construction", err)
		}
		return e
	}
	t.Run("official-executor-invalid-composition", func(t *testing.T) {
		for _, change := range []func(*ExecutorConfig){
			func(c *ExecutorConfig) { c.Audit = &foreignIssuanceAudit{} },
			func(c *ExecutorConfig) { c.Audit = nil },
			func(c *ExecutorConfig) { c.Lifecycle = nil },
			func(c *ExecutorConfig) { c.Repository = &Repository{} },
			func(c *ExecutorConfig) { c.Coordinator.AdmissionPolicy = nil },
			func(c *ExecutorConfig) { c.Coordinator.QueryPolicy = nil },
			func(c *ExecutorConfig) { c.Coordinator.MaximumDuration = 0 },
			func(c *ExecutorConfig) { c.Caller.PolicyRevision = 2 },
			func(c *ExecutorConfig) { c.Caller.Request.Subject.Kind = authorization.SubjectGroup },
			func(c *ExecutorConfig) { c.Caller.Request.Action = "identity.user.create" },
			func(c *ExecutorConfig) { c.RetentionPolicyVersion = 0 },
			func(c *ExecutorConfig) { c.PolicyID = "invalid policy" },
		} {
			c := executorConfig(repo, issuanceQueryPolicy{})
			change(&c)
			if _, err := NewExecutor(c); !errors.Is(err, risk.ErrInvalidPolicy) {
				t.Fatal("incomplete or foreign composition admitted", err)
			}
		}
	})
	t.Run("official-executor-production-effects", func(t *testing.T) {
		productionAudit, productionOutbox := productionRiskEffects(t, ctx, db, &ownedAuditRoles)
		c := executorConfig(repo, issuanceQueryPolicy{})
		c.Audit, c.Lifecycle = productionAudit, productionOutbox
		executor, err := NewExecutor(c)
		if err != nil {
			t.Fatal("production adapters rejected", err)
		}
		for _, mutate := range []func(*identitypostgres.ContributorDescriptor){
			func(d *identitypostgres.ContributorDescriptor) { d.Owner = "foreign/postgres" },
			func(d *identitypostgres.ContributorDescriptor) { d.ContractID = "foreign.contract" },
			func(d *identitypostgres.ContributorDescriptor) { d.Version = 2 },
		} {
			for _, isAudit := range []bool{true, false} {
				bad := c
				if isAudit {
					d := productionAudit.Descriptor()
					mutate(&d)
					bad.Audit = auditDescriptorVariant{productionAudit, d}
				} else {
					d := productionOutbox.Descriptor()
					mutate(&d)
					bad.Lifecycle = lifecycleDescriptorVariant{productionOutbox, d}
				}
				if _, err := NewExecutor(bad); !errors.Is(err, risk.ErrInvalidPolicy) {
					t.Fatal("foreign production descriptor admitted", err)
				}
			}
		}
		for _, phase := range []risk.IssuancePhase{risk.PhoneResetInitiation, risk.PhoneResetCompletion} {
			for _, lostAck := range []bool{false, true} {
				id, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := base64.RawURLEncoding.DecodeString(string(id))
				active := executor
				var fault *commitAckFault
				if lostAck {
					faultConfig := c
					faultConfig.Pool, fault = newCommitAckPool(t, ctx, dsn, name, raw)
					active, err = NewExecutor(faultConfig)
					if err != nil {
						t.Fatal(err)
					}
				}
				at := time.Now().UTC().Truncate(time.Microsecond).Add(-100 * time.Millisecond)
				issuer, request, _ := issuanceFixture(t, phase, at, string(id), active, false, nil)
				first, err := issuer.Evaluate(ctx, request)
				if lostAck {
					if err != nil || fault.hits.Load() != 1 || first.Outcome != risk.EvidenceUnknown || first.Evidence != (risk.RiskEvidence{}) {
						t.Fatal("production uncertain commit disclosed", err)
					}
				} else if err != nil || first.Outcome != risk.EvidenceCommitted || first.Evidence.Reference.Reveal() == "" {
					t.Fatal("production issuance", err)
				}
				var nativeCount, auditCount, auditBindings, outboxCount, outboxBindings int
				assertEffects := func() {
					t.Helper()
					err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM risk_store.issued_evidence WHERE command_id=$1),(SELECT count(*) FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$2 AND topic='risk.evidence_issued.v1'),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, raw, string(id)).Scan(&nativeCount, &auditCount, &auditBindings, &outboxCount, &outboxBindings)
					if err != nil || nativeCount != 1 || auditCount != 1 || auditBindings != 1 || outboxCount != 1 || outboxBindings != 1 {
						t.Fatalf("production effect cardinality %d/%d/%d/%d/%d: %v", nativeCount, auditCount, auditBindings, outboxCount, outboxBindings, err)
					}
				}
				assertEffects()
				var action, retention, subjectType, subjectID string
				var outcome int16
				if err = db.QueryRowContext(ctx, `SELECT r.action,r.outcome,convert_from(r.canonical_record,'UTF8')::jsonb->'attributes'->>'retention.class',convert_from(o.payload,'UTF8')::jsonb->>'subject_type',convert_from(o.payload,'UTF8')::jsonb->>'subject_id' FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id JOIN public.outbox_messages o ON o.metadata->>'identity.command_id'=$2 WHERE b.command_id=$1`, raw, string(id)).Scan(&action, &outcome, &retention, &subjectType, &subjectID); err != nil || action != "identity.risk.decide" || outcome != 1 || retention != "protected" || subjectType != "risk_evidence" || subjectID != string(id) {
					t.Fatal("production effect projection", err)
				}
				fresh, err := NewExecutor(c)
				if err != nil {
					t.Fatal(err)
				}
				replay, original, _ := issuanceFixture(t, phase, at.Add(time.Minute), string(id), fresh, true, nil)
				recovered, err := replay.Recover(ctx, original)
				if lostAck {
					first = recovered
				}
				if err != nil || recovered.Outcome != risk.EvidenceCommitted || recovered.Evidence.Reference.Reveal() == "" || recovered != first {
					t.Fatal("production recovery", err)
				}
				var issued, expires time.Time
				var state, purpose string
				if err = db.QueryRowContext(ctx, `SELECT c.state,e.purpose,e.issued_at,e.expires_at FROM identity.commands c JOIN risk_store.issued_evidence e USING(command_id,tenant_id) WHERE c.command_id=$1`, raw).Scan(&state, &purpose, &issued, &expires); err != nil || state != "committed" || purpose != string(recovered.Evidence.Purpose) || !issued.Equal(recovered.Evidence.IssuedAt) || !expires.Equal(recovered.Evidence.ExpiresAt) {
					t.Fatal("production custody changed", err)
				}
				again, err := replay.Evaluate(ctx, original)
				if err != nil || again != first {
					t.Fatal("production replay", err)
				}
				changed := original
				if phase == risk.PhoneResetInitiation {
					changed.Recovery.Phase = risk.PhoneResetCompletion
					changed.Recovery.Binding.RecoveryOperation = "identity.phone.password-reset-complete"
				} else {
					changed.Recovery.Phase = risk.PhoneResetInitiation
					changed.Recovery.Binding.RecoveryOperation = "identity.phone.password-reset-request"
				}
				crossed, _ := replay.Evaluate(ctx, changed)
				if crossed.Outcome == risk.EvidenceCommitted || crossed.Outcome == risk.EvidenceMissing || crossed.Evidence != (risk.RiskEvidence{}) {
					t.Fatal("production cross-purpose replay disclosed")
				}
				assertEffects()
			}
		}
		noSuccessfulEffects := func(t *testing.T, id identity.CommandID) {
			t.Helper()
			raw, _ := base64.RawURLEncoding.DecodeString(string(id))
			var native, audits, messages, bindings int
			err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM risk_store.issued_evidence WHERE command_id=$1),(SELECT count(*) FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.command_id=$1 AND r.outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, raw, string(id)).Scan(&native, &audits, &messages, &bindings)
			if err != nil || native != 0 || audits != 0 || messages != 0 || bindings != 0 {
				t.Fatalf("production rollback retained success %d/%d/%d/%d: %v", native, audits, messages, bindings, err)
			}
		}
		for _, table := range []string{"audit.records", "public.outbox_messages"} {
			t.Run("rollback-"+table, func(t *testing.T) {
				if _, err := db.ExecContext(ctx, `CREATE FUNCTION public.risk_reject_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='fixture effect rejected'; END $$; CREATE TRIGGER risk_reject_effect BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION public.risk_reject_effect()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := db.ExecContext(ctx, `DROP TRIGGER risk_reject_effect ON `+table+`; DROP FUNCTION public.risk_reject_effect()`); err != nil {
						t.Error("effect fault cleanup", err)
					}
				}()
				id, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				issuer, request, _ := issuanceFixture(t, risk.PhoneResetInitiation, time.Now().UTC().Truncate(time.Microsecond).Add(-100*time.Millisecond), string(id), executor, false, nil)
				got, _ := issuer.Evaluate(ctx, request)
				if got.Outcome == risk.EvidenceCommitted || got.Outcome == risk.EvidenceMissing || got.Evidence != (risk.RiskEvidence{}) {
					t.Fatal("production failure disclosed")
				}
				noSuccessfulEffects(t, id)
			})
		}
		t.Run("abandoned-production-reservation", func(t *testing.T) {
			at := time.Now().UTC().Truncate(time.Microsecond).Add(-100 * time.Millisecond)
			b, cmd, _, _ := prepare(t, risk.PhoneResetInitiation, at)
			plan, err := executor.plan(b, cmd, at)
			if err != nil {
				t.Fatal(err)
			}
			_, result, err := executor.coordinator.ReserveCommand(ctx, b, cmd, plan)
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("production reservation", err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if _, err = db.ExecContext(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
			issuer, request, _ := issuanceFixture(t, risk.PhoneResetInitiation, at, string(b.CommandID), executor, true, nil)
			got, err := issuer.Recover(ctx, request)
			if err != nil || got.Outcome != risk.EvidenceFailed || got.Evidence != (risk.RiskEvidence{}) {
				t.Fatal("production noncommit recovery", err)
			}
			noSuccessfulEffects(t, b.CommandID)
		})
	})
	t.Run("official-executor-original-replay", func(t *testing.T) {
		for _, phase := range []risk.IssuancePhase{risk.PhoneResetInitiation, risk.PhoneResetCompletion} {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			at := time.Now().UTC().Truncate(time.Microsecond).Add(-100 * time.Millisecond)
			executor := newExecutor(t, repo, issuanceQueryPolicy{})
			issuer, request, _ := issuanceFixture(t, phase, at, string(id), executor, false, nil)
			first, err := issuer.Evaluate(ctx, request)
			if err != nil || first.Outcome != risk.EvidenceCommitted || first.Evidence.Reference.Reveal() == "" || first.Evidence.MaxUses != 1 || first.Evidence.IssuedAt.Before(at) || !first.Evidence.ExpiresAt.Equal(at.Add(30*time.Second)) {
				t.Fatal("official issuance failed", err)
			}
			counts(t, identity.CommandBinding{CommandID: id}, 1, 1, 1)
			replay, original, _ := issuanceFixture(t, phase, at.Add(time.Minute), string(id), newExecutor(t, repo, issuanceQueryPolicy{}), true, nil)
			second, err := replay.Evaluate(ctx, original)
			if err != nil || second != first {
				t.Fatal("original expired replay altered or renewed", err)
			}
			// Pre-evaluation admission is not protected-response disclosure. The
			// two deliberately independent policies must both govern committed replay.
			disclosureDenied := executorConfig(repo, issuanceQueryPolicy{})
			disclosureDenied.Coordinator.QueryPolicy = &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceDenyPolicy{}}
			deniedExecutor, err := NewExecutor(disclosureDenied)
			if err != nil {
				t.Fatal(err)
			}
			deniedIssuer, deniedRequest, _ := issuanceFixture(t, phase, at.Add(time.Minute), string(id), deniedExecutor, true, nil)
			deniedResult, err := deniedIssuer.Evaluate(ctx, deniedRequest)
			if err != nil || deniedResult.Outcome != risk.EvidenceDenied || deniedResult.Evidence != (risk.RiskEvidence{}) {
				t.Fatal("admission permission bypassed response disclosure policy", err)
			}
			deniedResult, err = deniedIssuer.Recover(ctx, deniedRequest)
			if err != nil || deniedResult.Outcome != risk.EvidenceDenied || deniedResult.Evidence != (risk.RiskEvidence{}) {
				t.Fatal("recovery bypassed response disclosure policy", err)
			}
			newKey, keyErr := risk.NewEvidenceKey(2, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			rotated, err := NewRepository(Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key, newKey}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1), "wrapping_v2": wrappingKey(2)}, CurrentEnvelopeKey: "wrapping_v2"})
			if err != nil {
				t.Fatal(err)
			}
			rotatedIssuer, rotatedRequest, _ := issuanceFixture(t, phase, at.Add(time.Minute), string(id), newExecutor(t, rotated, issuanceQueryPolicy{}), true, []risk.EvidenceKey{key, newKey})
			rotatedResult, err := rotatedIssuer.Evaluate(ctx, rotatedRequest)
			if err != nil || rotatedResult != first {
				t.Fatal("rotation lost original encrypted response", err)
			}
			for _, change := range []func(*risk.PhoneEvidenceRequest){
				func(r *risk.PhoneEvidenceRequest) { r.Actor = "other" },
				func(r *risk.PhoneEvidenceRequest) { r.Recovery.Binding.Tenant = "other" },
				func(r *risk.PhoneEvidenceRequest) { r.Recovery.Binding.Subject = "other" },
				func(r *risk.PhoneEvidenceRequest) { r.Recovery.Binding.CanonicalNumber = "+358401234568" },
				func(r *risk.PhoneEvidenceRequest) { r.Recovery.Binding.PreAuthTransaction = "different-preauth" },
				func(r *risk.PhoneEvidenceRequest) { r.Recovery.Binding.Attempt = "different-attempt" },
				func(r *risk.PhoneEvidenceRequest) { r.Subject.Device = "different-device" },
				func(r *risk.PhoneEvidenceRequest) { r.Subject.Network = "2001:db8::2" },
			} {
				changed := original
				change(&changed)
				got, _ := replay.Evaluate(ctx, changed)
				if got.Outcome == risk.EvidenceCommitted || got.Outcome == risk.EvidenceMissing || got.Evidence != (risk.RiskEvidence{}) {
					t.Fatal("changed intent disclosed or reevaluated")
				}
			}
			counts(t, identity.CommandBinding{CommandID: id}, 1, 1, 1)
			var encrypted []byte
			if err = db.QueryRowContext(ctx, `SELECT response_envelope FROM risk_store.issued_evidence WHERE record_id=$1`, string(id)).Scan(&encrypted); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encrypted, []byte(first.Evidence.Reference.Reveal())) {
				t.Fatal("response stored in plaintext")
			}
			bad := bytes.Clone(encrypted)
			bad[len(bad)-1] ^= 1
			if _, err = db.ExecContext(ctx, `UPDATE risk_store.issued_evidence SET response_envelope=$2 WHERE record_id=$1`, string(id), bad); err != nil {
				t.Fatal(err)
			}
			corrupt, err := replay.Evaluate(ctx, original)
			if err == nil || corrupt.Outcome != risk.EvidenceUnknown || corrupt.Evidence != (risk.RiskEvidence{}) {
				t.Fatal("corrupt original disclosed or evaluated", err)
			}
			if _, err = db.ExecContext(ctx, `UPDATE risk_store.issued_evidence SET response_envelope=$2 WHERE record_id=$1`, string(id), encrypted); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("official-executor-concurrent-exact-command", func(t *testing.T) {
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Truncate(time.Microsecond).Add(-100 * time.Millisecond)
		executor := newExecutor(t, repo, issuanceQueryPolicy{})
		barrier := &concurrentIssuance{delegate: executor, ready: make(chan struct{})}
		issuer, request, _ := issuanceFixture(t, risk.PhoneResetInitiation, at, string(id), barrier, false, nil)
		type response struct {
			result risk.PhoneEvidenceResult
			err    error
		}
		// The parent owns/drains this two-result channel. Each bounded worker sends
		// once and exits; no goroutine or channel ownership escapes this subtest.
		responses := make(chan response, 2)
		for range 2 {
			go func() { result, err := issuer.Evaluate(ctx, request); responses <- response{result, err} }()
		}
		var first risk.PhoneEvidenceResult
		for range 2 {
			r := <-responses
			if r.result.Outcome != risk.EvidenceCommitted && r.result.Outcome != risk.EvidenceUnknown {
				t.Fatal("concurrent exact submission lost safe classification", r.err)
			}
			if r.result.Outcome == risk.EvidenceCommitted {
				if first.Outcome != 0 && r.result != first {
					t.Fatal("multiple committed references")
				}
				first = r.result
			}
		}
		if first.Outcome != risk.EvidenceCommitted {
			t.Fatal("no original committed winner")
		}
		counts(t, identity.CommandBinding{CommandID: id}, 1, 1, 1)
		replay, original, _ := issuanceFixture(t, risk.PhoneResetInitiation, at.Add(time.Minute), string(id), executor, true, nil)
		for range 2 {
			recovered, err := replay.Recover(ctx, original)
			if err != nil || recovered != first {
				t.Fatal("exact retries did not converge to original", err)
			}
		}
		counts(t, identity.CommandBinding{CommandID: id}, 1, 1, 1)
	})
	t.Run("official-executor-lost-successful-commit-ack", func(t *testing.T) {
		for _, phase := range []risk.IssuancePhase{risk.PhoneResetInitiation, risk.PhoneResetCompletion} {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(id))
			faultPool, fault := newCommitAckPool(t, ctx, dsn, name, raw)
			func() {
				c := executorConfig(repo, issuanceQueryPolicy{})
				c.Pool = faultPool
				executor, err := NewExecutor(c)
				if err != nil {
					t.Fatal(err)
				}
				at := time.Now().UTC().Truncate(time.Microsecond).Add(-100 * time.Millisecond)
				issuer, request, _ := issuanceFixture(t, phase, at, string(id), executor, false, nil)
				uncertain, err := issuer.Evaluate(ctx, request)
				if fault.hits.Load() != 1 || err != nil || uncertain.Outcome != risk.EvidenceUnknown || uncertain.Evidence != (risk.RiskEvidence{}) {
					t.Fatal("lost successful acknowledgement disclosed or guessed outcome", err)
				}
				counts(t, identity.CommandBinding{CommandID: id}, 1, 1, 1)
				var state string
				var issued, expires time.Time
				if err = db.QueryRowContext(ctx, `SELECT c.state,e.issued_at,e.expires_at FROM identity.commands c JOIN risk_store.issued_evidence e USING(command_id,tenant_id) WHERE c.command_id=$1`, raw).Scan(&state, &issued, &expires); err != nil || state != "committed" {
					t.Fatal("commit not durable", err)
				}
				// New non-faulted primary executor, with provider/counter work forbidden.
				replay, original, _ := issuanceFixture(t, phase, at.Add(time.Minute), string(id), newExecutor(t, repo, issuanceQueryPolicy{}), true, nil)
				recovered, err := replay.Recover(ctx, original)
				if err != nil || recovered.Outcome != risk.EvidenceCommitted || recovered.Evidence.Reference.Reveal() == "" || !recovered.Evidence.IssuedAt.Equal(issued) || !recovered.Evidence.ExpiresAt.Equal(expires) {
					t.Fatal("committed original not recovered", err)
				}
				for range 2 {
					again, err := replay.Recover(ctx, original)
					if err != nil || again != recovered {
						t.Fatal("recovery replaced original", err)
					}
				}
				again, err := replay.Evaluate(ctx, original)
				if err != nil || again != recovered {
					t.Fatal("matching evaluation replaced original", err)
				}
				counts(t, identity.CommandBinding{CommandID: id}, 1, 1, 1)
			}()
		}
	})
	t.Run("official-executor-denial-before-providers", func(t *testing.T) {
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		issuer, request, _ := issuanceFixture(t, risk.PhoneResetInitiation, time.Now().UTC(), string(id), newExecutor(t, repo, issuanceDenyPolicy{}), true, nil)
		got, err := issuer.Evaluate(ctx, request)
		if err != nil || got.Outcome != risk.EvidenceDenied || got.Evidence != (risk.RiskEvidence{}) {
			t.Fatal("denied caller evaluated or disclosed", err)
		}
		counts(t, identity.CommandBinding{CommandID: id}, 0, 0, 0)
	})
	t.Run("official-executor-pending-and-proved-failure-never-evaluate", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Microsecond).Add(-100 * time.Millisecond)
		b, cmd, plan, _ := prepare(t, risk.PhoneResetInitiation, at)
		_, result, err := coordinator.ReserveCommand(ctx, b, cmd, plan)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("reserve pending history", err)
		}
		issuer, request, _ := issuanceFixture(t, risk.PhoneResetInitiation, at, string(b.CommandID), newExecutor(t, repo, issuanceQueryPolicy{}), true, nil)
		got, err := issuer.Evaluate(ctx, request)
		if err != nil || got.Outcome != risk.EvidenceUnknown || got.Evidence != (risk.RiskEvidence{}) {
			t.Fatal("pending allowed reevaluation", err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, err = db.ExecContext(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
			t.Fatal(err)
		}
		got, err = issuer.Evaluate(ctx, request)
		if err != nil || got.Outcome != risk.EvidenceFailed || got.Evidence != (risk.RiskEvidence{}) {
			t.Fatal("proved failure permitted reevaluation", err)
		}
		counts(t, b, 0, 0, 0)
	})
	t.Run("official-executor-effect-failure-rolls-back", func(t *testing.T) {
		for _, failAudit := range []bool{true, false} {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			executor := newExecutor(t, repo, issuanceQueryPolicy{})
			issuer, request, _ := issuanceFixture(t, risk.PhoneResetInitiation, time.Now().UTC().Truncate(time.Microsecond).Add(-100*time.Millisecond), string(id), executor, false, nil)
			auditing.fail, outbox.fail = failAudit, !failAudit
			got, err := issuer.Evaluate(ctx, request)
			auditing.fail, outbox.fail = false, false
			if got.Evidence != (risk.RiskEvidence{}) || got.Outcome == risk.EvidenceCommitted || got.Outcome == risk.EvidenceMissing {
				t.Fatal("effect failure disclosed evidence", err)
			}
			counts(t, identity.CommandBinding{CommandID: id}, 0, 0, 0)
		}
	})
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
	t.Run("official-risk-reservation", func(t *testing.T) {
		history, err := (ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}, Version: 22}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := migrations.NewRunner(issuanceHistory(append(append([]migrations.Migration(nil), kernel...), history...)), backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal(err)
		}
		testNativeRiskReservation(t, ctx, pool, repo, newExecutor(t, repo, issuanceQueryPolicy{}))
		t.Run("protected counters", func(t *testing.T) { testNativeProtectedCounters(t, ctx, pool) })
	})
	t.Run("native-captcha", func(t *testing.T) {
		history, err := (CaptchaMigrationSource{Schema: "risk_store", Version: 40}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, history[0].UpSQL()); err != nil {
			t.Fatal("native CAPTCHA schema", err)
		}
		scopeHistory, err := (CaptchaScopeMigrationSource{Schema: "risk_store", Version: 41}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, scopeHistory[0].UpSQL()); err != nil {
			t.Fatal("native CAPTCHA scope upgrade", err)
		}
		useHistory, err := (CaptchaUseMigrationSource{Schema: "risk_store", Version: 42}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, useHistory[0].UpSQL()); err != nil {
			t.Fatal("native CAPTCHA consuming upgrade", err)
		}
		testNativeCaptchaReplay(t, ctx, pool)
		t.Run("public-executor", func(t *testing.T) { testPublicCaptchaExecutor(t, ctx, pool, dsn, name) })
		t.Run("public-production-effects", func(t *testing.T) {
			a, o := productionRiskEffects(t, ctx, db, &ownedAuditRoles)
			testPublicCaptchaExecutor(t, ctx, pool, dsn, name, captchaProductionEffects{audit: a, lifecycle: o})
		})
	})
}
