//go:build integration

package postgres

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	policyStore "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// These explicit same-Work SQL seams test native mutation atomicity. They do
// not substitute for the separately required production audit/outbox gate.
type revokeAudit struct{ fail bool }

func (*revokeAudit) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1}
}
func (p *revokeAudit) PersistAudits(ctx context.Context, w identitypostgres.Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, r := range records {
		data, err := audit.CanonicalJSON(r.Record)
		if err != nil {
			return err
		}
		if _, err = w.Exec(ctx, `INSERT INTO public.revoke_audit(event_id,command_id,outcome,record) VALUES($1,$2,$3,$4::jsonb)`, r.Record.ID(), r.Record.Attributes()["command.id"], int64(r.Record.Outcome()), string(data)); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*revokeAudit) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	return revokeEffectEvidence(ctx, w, "public.revoke_audit")
}

type revokeOutbox struct{ fail bool }

func (*revokeOutbox) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
}
func (p *revokeOutbox) PersistLifecycle(ctx context.Context, w identitypostgres.Work) error {
	records, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err = w.Exec(ctx, `INSERT INTO public.revoke_outbox(event_id,command_id,event_type,subject_type,subject_id,before_version,after_version) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.ID, string(r.CommandID), r.EventType, r.SubjectType, r.SubjectID, strconv.FormatUint(r.BeforeVersion, 10), strconv.FormatUint(r.AfterVersion, 10)); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*revokeOutbox) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	return revokeEffectEvidence(ctx, w, "public.revoke_outbox")
}
func revokeEffectEvidence(ctx context.Context, w identitypostgres.RecoveryWork, table string) (identitypostgres.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
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

type revokeQueryPolicy struct{}

func (revokeQueryPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
}

func TestNativeFamilyRevocationIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_SESSION_POSTGRES_TEST_DSN")
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
		if err := admin.Close(c); err != nil {
			t.Error("admin cleanup")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "session_revoke_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, s := context.WithTimeout(context.Background(), 3*time.Second)
		defer s()
		if _, err := admin.Exec(c, "DROP DATABASE "+quoted); err != nil {
			t.Error("fixture cleanup")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	kernel, err := (identitypostgres.MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := (MigrationSource{Schema: "session_store", Version: 10}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	migrate := func(history []migrations.Migration) {
		t.Helper()
		runner, e := migrations.NewRunner(fixtureSource(history), backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("native migration", e)
		}
	}
	history := append(kernel, initial...)
	migrate(history)
	if _, err = db.ExecContext(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1),('tenant-b','user-a','active',1),('tenant-a','user-b','active',1);CREATE TABLE public.revoke_audit(event_id text PRIMARY KEY,command_id text NOT NULL,outcome bigint,record jsonb);CREATE TABLE public.revoke_outbox(event_id text PRIMARY KEY,command_id text NOT NULL,event_type text,subject_type text,subject_id text,before_version text,after_version text)`); err != nil {
		t.Fatal(err)
	}
	seed := func(tenant, user, family, id string, persistent bool) {
		t.Helper()
		s, _ := testSession(t).Bindings()
		s.TenantID, s.UserID, s.FamilyID, s.SessionID = identity.TenantID(tenant), identity.UserID(user), family, id
		s.FamilyVersion = 7
		a, _ := s.Authority.Bindings()
		a.SessionFamily.ScopeKey = "session_family:" + tenant + ":" + family
		a.SessionFamily.Version = 7
		a.Session.ScopeKey = "session:" + tenant + ":" + id
		s.Authority, err = session.NewAuthoritySnapshot(a)
		if err != nil {
			t.Fatal(err)
		}
		s.Authentication.Proof.Tenant, s.Authentication.Proof.Subject = tenant, user
		if persistent {
			p, _ := s.Remember.Bindings()
			p.Choice = session.PersistentSession
			s.Remember, err = session.NewRememberPolicy(p)
			if err != nil {
				t.Fatal(err)
			}
		}
		s.Lookup.Sum[1] = byte(len(id))
		s.Lookup.Sum[2] = id[len(id)-1]
		record, e := session.NewSession(s)
		if e != nil {
			t.Fatal(e)
		}
		payload, expiry, e := encodeRecord(record)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, `INSERT INTO session_store.families VALUES($1,$2,$3,7,'active',$4) ON CONFLICT DO NOTHING`, tenant, family, user, s.IssuedAt.UTC().Format(storedTimeLayout)); e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, `INSERT INTO session_store.sessions VALUES($1,$2,$3,$4,$5,7,'active',$6,$7,$8,$9)`, tenant, id, user, family, strconv.FormatUint(s.Version, 10), int64(s.Lookup.KeyVersion), s.Lookup.Sum[:], expiry, payload); e != nil {
			t.Fatal(e)
		}
	}
	seed("tenant-a", "user-a", "family-a", "session-1", false)
	seed("tenant-a", "user-a", "family-a", "session-2", true)
	seed("tenant-a", "user-a", "family-other", "session-3", false)
	seed("tenant-b", "user-a", "family-a", "session-4", false)
	seed("tenant-a", "user-b", "family-b", "session-5", false)
	seed("tenant-a", "user-a", "family-old-revoked", "session-old", false)
	if _, err := db.ExecContext(ctx, `UPDATE session_store.families SET state='revoked',version=8 WHERE family_id='family-old-revoked'`); err != nil {
		t.Fatal(err)
	}
	var original string
	if err = db.QueryRowContext(ctx, `SELECT jsonb_agg(record ORDER BY tenant_id,session_id)::text FROM session_store.sessions`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	upgraded, err := (RevocationMigrationSource{Base: MigrationSource{Schema: "session_store", Version: 10}, Version: 11}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	migrate(append(kernel, upgraded...))
	migrate(append(kernel, upgraded...))
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, s := context.WithTimeout(context.Background(), 3*time.Second)
		defer s()
		if err := pool.Close(c); err != nil {
			t.Error("pool cleanup")
		}
	}()
	repo, err := NewRepository(pool, Config{Schema: "session_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditing, outbox := &revokeAudit{}, &revokeOutbox{}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{domain, auditing, outbox, repo})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: revokeQueryPolicy{}}})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(t *testing.T, family string, version uint64) (identity.CommandBinding, identity.Command, identitypostgres.CommandPlan) {
		t.Helper()
		b := revokeBinding()
		b.RecordID = family
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		native, e := session.NewRevokeFamilyCommand(b, version)
		if e != nil {
			t.Fatal(e)
		}
		cmd, e := MapCommand(native)
		if e != nil {
			t.Fatal(e)
		}
		builder, e := audit.NewBuilder(audit.BuilderConfig{})
		if e != nil {
			t.Fatal(e)
		}
		seed, e := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "identity.session.revoke", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session_family", ID: family}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session_family", "aggregate.id": family, "aggregate.before_version": strconv.FormatUint(version, 10), "aggregate.after_version": strconv.FormatUint(version+1, 10), "retention.class": "standard"}})
		if e != nil {
			t.Fatal(e)
		}
		digest, e := identitypostgres.FeatureAuditBindingDigest(b, session.RevokeFamilyOperation(), "session_family", seed)
		if e != nil {
			t.Fatal(e)
		}
		p, e := coordinator.PrepareCommandPlan(b, cmd, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session_family", Feature: &identitypostgres.FeatureRegistration{Contributor: repo.Descriptor(), Operation: session.RevokeFamilyOperation()}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "session_family.revoked.v1", BeforeVersion: version, AfterVersion: version + 1}, Audits: []identitypostgres.AuditPlan{{EventType: "identity.session.revoke", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "standard", BindingDigest: digest}}})
		if e != nil {
			t.Fatal(e)
		}
		return b, cmd, p
	}
	familyState := func(t *testing.T, family string, wantState, wantVersion string) {
		t.Helper()
		var state, version string
		if e := db.QueryRowContext(ctx, `SELECT state,version::text FROM session_store.families WHERE tenant_id='tenant-a' AND family_id=$1`, family).Scan(&state, &version); e != nil || state != wantState || version != wantVersion {
			t.Fatal("family transition", state, version, e)
		}
	}
	execute := func(t *testing.T, b identity.CommandBinding, cmd identity.Command, p identitypostgres.CommandPlan) (identity.CommandResult, error) {
		t.Helper()
		r, result, e := coordinator.ReserveCommand(ctx, b, cmd, p)
		if e != nil || result.Outcome != identity.CommitOutcomeInProgress {
			return result, e
		}
		w, e := coordinator.Begin(ctx, r)
		if e != nil {
			return identity.CommandResult{}, e
		}
		defer coordinator.Abort(w, identity.UnavailableError{})
		result, e = coordinator.ApplyFeature(ctx, w, cmd)
		if e != nil {
			return coordinator.Abort(w, e)
		}
		return coordinator.Commit(w, result)
	}
	t.Run("same commit isolation original vector and replay", func(t *testing.T) {
		b, cmd, p := prepare(t, "family-a", 7)
		r, _, e := coordinator.ReserveCommand(ctx, b, cmd, p)
		if e != nil {
			t.Fatal(e)
		}
		w, e := coordinator.Begin(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		defer coordinator.Abort(w, identity.UnavailableError{})
		native, _ := session.NewRevokeFamilyCommand(b, 7)
		if _, e := repo.Apply(ctx, w, native); e == nil {
			t.Fatal("adapter accepted pre-invocation Work")
		}
		result, e := coordinator.ApplyFeature(ctx, w, cmd)
		if e != nil {
			t.Fatal(e)
		}
		familyState(t, "family-a", "active", "7")
		if _, e := repo.Apply(ctx, w, native); e == nil {
			t.Fatal("adapter accepted returned invocation")
		}
		result, e = coordinator.Commit(w, result)
		if e != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil || result.Feature.BeforeVersion != 7 || result.Feature.AfterVersion != 8 {
			t.Fatal("native commit", e)
		}
		familyState(t, "family-a", "revoked", "8")
		familyState(t, "family-other", "active", "7")
		var unchanged string
		if e := db.QueryRowContext(ctx, `SELECT jsonb_agg(record ORDER BY tenant_id,session_id)::text FROM session_store.sessions`).Scan(&unchanged); e != nil || unchanged != original {
			t.Fatal("original snapshots rewritten", e)
		}
		for _, id := range []string{"session-1", "session-2"} {
			got, e := repo.Get(ctx, "tenant-a", id)
			if e != nil || !got.FamilyRevoked || got.CurrentFamilyVersion != 8 {
				t.Fatal("native consumer revocation", e)
			}
			s, _ := got.Session.Bindings()
			if s.FamilyVersion != 7 {
				t.Fatal("stored family authority renewed")
			}
			if got, e = repo.Lookup(ctx, "tenant-a", s.Lookup); e != nil || !got.FamilyRevoked {
				t.Fatal("digest consumer lost revocation", e)
			}
		}
		var count int
		if e := db.QueryRowContext(ctx, `SELECT count(*) FROM session_store.families WHERE (tenant_id='tenant-b' OR user_id='user-b') AND state='active' AND version=7`).Scan(&count); e != nil || count != 2 {
			t.Fatal("foreign family changed", e)
		}
		replay, e := execute(t, b, cmd, p)
		if e != nil || replay.AuditEventID != result.AuditEventID || replay.Feature == nil || *replay.Feature != *result.Feature {
			t.Fatal("exact replay changed", e)
		}
		q, caller := revokeRecoveryInput(b)
		observed, e := coordinator.RecoverCommand(ctx, q, caller)
		if e != nil || observed.Outcome != identity.CommitOutcomeCommitted || observed.Binding != b || observed.Feature == nil || *observed.Feature != result.Feature.Operation {
			t.Fatal("original committed observation not recovered", e)
		}
		var audits, outboxes, effects int
		if e := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.revoke_audit WHERE command_id=$1),(SELECT count(*) FROM public.revoke_outbox WHERE command_id=$1),(SELECT count(*) FROM session_store.family_revocations WHERE command_id=$2)`, string(b.CommandID), mustCommandBytes(t, b.CommandID)).Scan(&audits, &outboxes, &effects); e != nil || audits != 1 || outboxes != 1 || effects != 1 {
			t.Fatal("duplicate/missing durable effects", e)
		}
		var action, event, kind, subject, retention, actor, before, after string
		if e := db.QueryRowContext(ctx, `SELECT record->>'action',record->'attributes'->>'retention.class',record->'actor'->>'id' FROM public.revoke_audit WHERE command_id=$1`, string(b.CommandID)).Scan(&action, &retention, &actor); e != nil || action != "identity.session.revoke" || retention != "standard" || actor != "user-a" {
			t.Fatal("audit declaration lost", e)
		}
		if e := db.QueryRowContext(ctx, `SELECT event_type,subject_type,subject_id,before_version,after_version FROM public.revoke_outbox WHERE command_id=$1`, string(b.CommandID)).Scan(&event, &kind, &subject, &before, &after); e != nil || event != "session_family.revoked.v1" || kind != "session_family" || subject != "family-a" || before != "7" || after != "8" {
			t.Fatal("lifecycle scope lost", e)
		}
		changedNative, _ := session.NewRevokeFamilyCommand(b, 6)
		changed, _ := MapCommand(changedNative)
		if _, _, e := coordinator.ReserveCommand(ctx, b, changed, p); e == nil {
			t.Fatal("changed intent replay admitted")
		}
	})
	t.Run("stale absent revoked and foreign ownership", func(t *testing.T) {
		for _, item := range []struct {
			family  string
			version uint64
		}{{"family-a", 8}, {"family-other", 6}, {"family-other", 8}, {"absent", 7}, {"family-b", 7}} {
			b, cmd, p := prepare(t, item.family, item.version)
			result, e := execute(t, b, cmd, p)
			var conflict identity.ConflictError
			if !errors.As(e, &conflict) || result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("unsafe precondition outcome", e, result.Outcome)
			}
		}
		familyState(t, "family-other", "active", "7")
		familyState(t, "family-b", "active", "7")
	})
	t.Run("audit and outbox failure roll back native effect", func(t *testing.T) {
		for _, auditFailure := range []bool{true, false} {
			auditing.fail, outbox.fail = auditFailure, !auditFailure
			b, cmd, p := prepare(t, "family-other", 7)
			result, e := execute(t, b, cmd, p)
			auditing.fail, outbox.fail = false, false
			if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("participant failure committed")
			}
			familyState(t, "family-other", "active", "7")
			var n int
			if e := db.QueryRowContext(ctx, `SELECT count(*) FROM session_store.family_revocations WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&n); e != nil || n != 0 {
				t.Fatal("rolled back mutation binding retained", e)
			}
		}
	})
	t.Run("abandoned claim primary noncommit recovery", func(t *testing.T) {
		b, cmd, p := prepare(t, "family-other", 7)
		if _, _, e := coordinator.ReserveCommand(ctx, b, cmd, p); e != nil {
			t.Fatal(e)
		}
		if _, e := db.ExecContext(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)); e != nil {
			t.Fatal(e)
		}
		q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
		caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
		result, e := coordinator.RecoverCommand(ctx, q, caller)
		var unavailable identity.UnavailableError
		if !errors.As(e, &unavailable) || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("native negative recovery", e, result.Outcome)
		}
		familyState(t, "family-other", "active", "7")
	})
	t.Run("racing independent commands cannot increment twice", func(t *testing.T) {
		b1, c1, p1 := prepare(t, "family-other", 7)
		b2, c2, p2 := prepare(t, "family-other", 7)
		start := make(chan struct{})
		results := make(chan identity.CommandResult, 2)
		failures := make(chan error, 2)
		var done sync.WaitGroup
		for _, input := range []struct {
			b identity.CommandBinding
			c identity.Command
			p identitypostgres.CommandPlan
		}{{b1, c1, p1}, {b2, c2, p2}} {
			done.Add(1)
			go func() {
				defer done.Done()
				<-start
				r, e := execute(t, input.b, input.c, input.p)
				results <- r
				failures <- e
			}()
		}
		close(start)
		done.Wait()
		close(results)
		close(failures)
		committed, aborted, conflicts := 0, 0, 0
		for result := range results {
			switch result.Outcome {
			case identity.CommitOutcomeCommitted:
				committed++
			case identity.CommitOutcomeNotCommitted:
				aborted++
			default:
				t.Fatal("unexpected raced outcome", result.Outcome)
			}
		}
		for e := range failures {
			if e != nil {
				var conflict identity.ConflictError
				if !errors.As(e, &conflict) {
					t.Fatal("raced failure", e)
				}
				conflicts++
			}
		}
		if committed != 1 || aborted != 1 || conflicts != 1 {
			t.Fatal("racing revoke lost exclusion")
		}
		familyState(t, "family-other", "revoked", "8")
	})
	t.Run("cancellation before commit discards provisional revocation", func(t *testing.T) {
		seed("tenant-a", "user-a", "family-cancelled", "session-7", false)
		b, cmd, p := prepare(t, "family-cancelled", 7)
		r, _, e := coordinator.ReserveCommand(ctx, b, cmd, p)
		if e != nil {
			t.Fatal(e)
		}
		call, stop := context.WithCancel(ctx)
		defer stop()
		w, e := coordinator.Begin(call, r)
		if e != nil {
			t.Fatal(e)
		}
		defer coordinator.Abort(w, identity.UnavailableError{})
		result, e := coordinator.ApplyFeature(call, w, cmd)
		if e != nil {
			t.Fatal(e)
		}
		stop()
		result, e = coordinator.Commit(w, result)
		if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("cancelled provisional mutation committed")
		}
		familyState(t, "family-cancelled", "active", "7")
		var n int
		if e := db.QueryRowContext(ctx, `SELECT count(*) FROM session_store.family_revocations WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&n); e != nil || n != 0 {
			t.Fatal("cancelled mutation evidence survived", e)
		}
	})
	t.Run("conflicting retained native evidence cannot prove noncommit", func(t *testing.T) {
		b, cmd, p := prepare(t, "family-b", 7)
		if _, _, e := coordinator.ReserveCommand(ctx, b, cmd, p); e != nil {
			t.Fatal(e)
		}
		if _, e := db.ExecContext(ctx, `INSERT INTO session_store.family_revocations(tenant_id,command_id,purpose,user_id,family_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,$4,$5,7,8,$6)`, string(b.TenantID), mustCommandBytes(t, b.CommandID), b.OperationID, string(b.UserID), b.RecordID, make([]byte, 32)); e != nil {
			t.Fatal(e)
		}
		if _, e := db.ExecContext(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)); e != nil {
			t.Fatal(e)
		}
		q, caller := revokeRecoveryInput(b)
		observed, e := coordinator.RecoverCommand(ctx, q, caller)
		if e == nil || observed.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("corrupt native binding terminalized", e, observed.Outcome)
		}
		var state string
		if e := db.QueryRowContext(ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&state); e != nil || state != "pending" {
			t.Fatal("unknown native evidence erased", e)
		}
	})
	t.Run("deferred database rejection is unknown until primary recovery", func(t *testing.T) {
		seed("tenant-a", "user-a", "family-ambiguous", "session-6", false)
		// Fail only at Commit after native/audit/outbox/terminal staging. This proves
		// the noncommitted ambiguity path, not a lost successful acknowledgement.
		if _, e := db.ExecContext(ctx, `CREATE FUNCTION public.reject_revoke_commit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION USING ERRCODE=''23514'',MESSAGE=''test rejection'';END';CREATE CONSTRAINT TRIGGER reject_revoke_commit AFTER INSERT ON session_store.family_revocations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_revoke_commit()`); e != nil {
			t.Fatal(e)
		}
		b, cmd, p := prepare(t, "family-ambiguous", 7)
		result, e := execute(t, b, cmd, p)
		if e == nil || result.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("commit rejection incorrectly proves rollback", e, result.Outcome)
		}
		familyState(t, "family-ambiguous", "active", "7")
		if _, e := db.ExecContext(ctx, `DROP TRIGGER reject_revoke_commit ON session_store.family_revocations;DROP FUNCTION public.reject_revoke_commit()`); e != nil {
			t.Fatal(e)
		}
		if _, e := db.ExecContext(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)); e != nil {
			t.Fatal(e)
		}
		q, caller := revokeRecoveryInput(b)
		recovered, e := coordinator.RecoverCommand(ctx, q, caller)
		var unavailable identity.UnavailableError
		if !errors.As(e, &unavailable) || recovered.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("ambiguous noncommit was not recovered", e, recovered.Outcome)
		}
		familyState(t, "family-ambiguous", "active", "7")
	})
	t.Run("authenticated issuance", func(t *testing.T) {
		proofHistory, e := (identitypostgres.SignInProofUseMigrationSource{Base: identitypostgres.MigrationSource{}, Version: 12}).Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		sessionHistory, e := (IssueMigrationSource{Base: RevocationMigrationSource{Base: MigrationSource{Schema: "session_store", Version: 10}, Version: 11}, Version: 13}).Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		policySQL, e := policyStore.AuthoritySchemaMigration(14)
		if e != nil {
			t.Fatal(e)
		}
		policyMigration, e := migrations.NewMigration(14, policySQL.Name, migrations.TransactionModeDefault, policySQL.Up, policySQL.Down)
		if e != nil {
			t.Fatal(e)
		}
		combined := append(proofHistory, sessionHistory...)
		combined = append(combined, policyMigration)
		slices.SortFunc(combined, func(a, b migrations.Migration) int { return cmp.Compare(a.Version(), b.Version()) })
		directory := identitypostgres.DirectoryAuthorityMigrationSource{Base: fixtureSource(combined), Version: 15, GlobalAuthorityID: "deployment-issue", TenantIDs: []identity.TenantID{"issue"}}
		credential := identitypostgres.CredentialMigrationSource{Base: directory, Version: 16}
		status := identitypostgres.StatusMigrationSource{Base: credential, Version: 17}
		runner, e := migrations.NewRunner(status, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal(e)
		}
		oldHistory, e := status.Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		oneHistory, e := (RevokeOneMigrationSource{Base: RevocationMigrationSource{Base: MigrationSource{Schema: "session_store", Version: 10}, Version: 11}, Version: 18}).Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		var beforeMigration string
		if e = db.QueryRowContext(ctx, `SELECT jsonb_agg(record ORDER BY tenant_id,session_id)::text FROM session_store.sessions`).Scan(&beforeMigration); e != nil {
			t.Fatal(e)
		}
		listHistory, e := (ListMigrationSource{Schema: "session_store", Version: 19}).Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		complete := append(oldHistory, oneHistory[len(oneHistory)-1])
		complete = append(complete, listHistory...)
		setHistory, e := (RevokeSetMigrationSource{Schema: "session_store", Version: 20}).Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		complete = append(complete, setHistory...)
		rotationHistory, e := (RotationMigrationSource{Schema: "session_store", Version: 21}).Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		complete = append(complete, rotationHistory...)
		cleanupHistory, e := (CleanupMigrationSource{Schema: "session_store", Version: 22}).Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		complete = append(complete, cleanupHistory...)
		migrate(complete)
		migrate(complete)
		// Populated active/revoked records and all older migration checksums
		// survive the additive single-session installation byte-for-byte.
		var afterMigration string
		if e = db.QueryRowContext(ctx, `SELECT jsonb_agg(record ORDER BY tenant_id,session_id)::text FROM session_store.sessions`).Scan(&afterMigration); e != nil || afterMigration != beforeMigration {
			t.Fatal("populated snapshot changed", e)
		}
		testNativeIssueIntegration(t, ctx, pool)
		t.Run("native session authentication", func(t *testing.T) { testNativeSessionAuthentication(t, ctx, pool) })
	})
}

func revokeRecoveryInput(b identity.CommandBinding) (identity.RecoveryQuery, authorization.DecisionContext) {
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
	return q, caller
}

func mustCommandBytes(t *testing.T, id identity.CommandID) []byte {
	t.Helper()
	b, e := base64.RawURLEncoding.DecodeString(string(id))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
