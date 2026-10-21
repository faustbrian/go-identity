//go:build integration

package anonymouspostgres_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// These declared audit/outbox sinks exercise sole-Work rollback. They do not
// stand in for production provider qualification or a complete signin service.
type lifecycleAudit struct{ fail bool }

func (*lifecycleAudit) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1}
}
func (p *lifecycleAudit) PersistAudits(ctx context.Context, w kernel.Work) error {
	items, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, item := range items {
		if _, err := w.Exec(ctx, `INSERT INTO public.anonymous_audits(command_id,event_id,succeeded) VALUES($1,$2,$3)`, item.Record.Attributes()["command.id"], item.Record.ID(), item.Record.Outcome() == audit.OutcomeSucceeded); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*lifecycleAudit) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

type lifecycleOutbox struct{ fail bool }

func (*lifecycleOutbox) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
}
func (p *lifecycleOutbox) PersistLifecycle(ctx context.Context, w kernel.Work) error {
	items, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, item := range items {
		if _, err := w.Exec(ctx, `INSERT INTO public.anonymous_outbox(command_id,event_id) VALUES($1,$2)`, string(item.CommandID), item.ID); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*lifecycleOutbox) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

type creationPhase struct {
	repository *anonymouspg.Repository
	domain     *kernel.AnonymousCreationDomain
	effect     *sessionpg.AnonymousSigninEffect
	intent     kernel.AnonymousCreationIntent
	original   identity.Command
	authority  kernel.AnonymousAuthorityRecord
	mode       string
	staged     bool
}

func (*creationPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
}
func (p *creationPhase) FeatureOperations() []identity.FeatureOperation {
	f, _ := p.original.Feature()
	return []identity.FeatureOperation{f.Operation}
}
func (p *creationPhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.original {
		return identity.ForbiddenError{}
	}
	_, err := anonymouspg.CreationSubject(c)
	return err
}
func (p *creationPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	u, err := p.domain.Apply(ctx, w, p, c, p.intent)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.authority = kernel.AnonymousAuthorityRecord{User: u, Placeholder: p.intent.Placeholder, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}
	if p.mode != "missing-lifecycle" {
		if err := p.repository.StageCreation(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.mode == "duplicate-lifecycle" {
		if err := p.repository.StageCreation(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if _, err := policy.InitializeAuthority(ctx, w, policy.AuthorityScope{TenantID: authorization.TenantID(u.TenantID), SubjectID: authorization.SubjectID(u.ID), PolicyNamespace: "guests"}, time.Second); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.effect.Apply(ctx, w, p, c, p.authority)
	p.staged = err == nil
	if err == nil && p.mode == "rollback" {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return receipt, err
}
func (p *creationPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.mode == "final-denial" {
		return identity.ForbiddenError{}
	}
	if err := p.repository.RequireCreation(ctx, w, p, c); err != nil {
		return err
	}
	return p.effect.Check(ctx, w, p, c, p.authority)
}
func (p *creationPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.repository.RecoverCreation(ctx, w, p)
}

func nativeFixture(t *testing.T) (context.Context, *database.Pool, *kernel.Repository) {
	t.Helper()
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit owned loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := admin.Close(bounded); err != nil {
			t.Error("admin cleanup")
		}
	})
	id, _ := identity.NewSubjectID()
	name := "anonymous_native_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(bounded, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup")
		}
	})
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = name
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(bounded); err != nil {
			t.Error("pool cleanup")
		}
	})
	var selected string
	if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&selected); err != nil || selected != name {
		t.Fatal("wrong isolated database")
	}
	kernelHistory := kernel.AnonymousDisposalMigrationSource{Base: kernel.DirectoryAuthorityMigrationSource{Base: kernel.AnonymousIdentityMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: "anonymous-deployment", TenantIDs: []identity.TenantID{"tenant-a", "AAAAAAAAAAAAAAAAAAAAAQ"}}, Version: 16}
	sessionHistory := sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "session_store", Version: 20}, Version: 21}, Version: 22}
	for _, source := range []migrations.Source{kernelHistory, sessionHistory, sessionpg.AnonymousSigninMigrationSource{Schema: "session_store", Version: 23, Predecessor: sessionpg.AnonymousAfterBaseIssuance}, sessionpg.AnonymousDisposalMigrationSource{Schema: "session_store", Version: 24}, anonymouspg.MigrationSource{Schema: "anonymous_store", Version: 25}, anonymouspg.DisposalMigrationSource{Schema: "anonymous_store", Version: 27}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("owner migration", err)
			}
		}
	}
	policyHistory, err := policy.AuthoritySchemaMigration(26)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, policyHistory.Up); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.anonymous_audits(command_id text NOT NULL,event_id text PRIMARY KEY,succeeded boolean NOT NULL);CREATE TABLE public.anonymous_outbox(command_id text NOT NULL,event_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	repository, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, repository
}

func TestNativeAnonymousLifecycleAndSession(t *testing.T) {
	ctx, pool, kernelRepository := nativeFixture(t)
	repository, err := anonymouspg.NewRepository(pool, anonymouspg.Config{Schema: "anonymous_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewAnonymousCreationDomain(kernelRepository)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := sessionpg.NewAnonymousSigninEffect(sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, sessionpg.AnonymousAdmissionConfig{GlobalAuthorityID: "anonymous-deployment", PolicyNamespace: "guests", Audience: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-lifecycle", "duplicate-lifecycle", "expired", "rollback", "audit-failure", "outbox-failure", "final-denial"} {
		t.Run(mode, func(t *testing.T) {
			spec, subject := creationFixture(t)
			data, _ := subject.Record()
			now := time.Now().UTC().Truncate(time.Microsecond)
			data.CreatedAt, data.ExpiresAt = now, now.Add(24*time.Hour)
			if mode == "expired" {
				data.CreatedAt, data.ExpiresAt = now.Add(-25*time.Hour), now.Add(-time.Hour)
			}
			subject, err = anonymous.NewAnonymousSubject(data)
			if err != nil {
				t.Fatal(err)
			}
			spec.Fields, err = anonymouspg.CreationFields(subject)
			if err != nil {
				t.Fatal(err)
			}
			b := spec.Binding
			creation := b
			creation.UserID, creation.AnonymousFlowID, creation.OperationID, creation.SchemaID = data.UserID, "", "identity.user.create", "guest-profile"
			intent := kernel.AnonymousCreationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Placeholder: identity.Identifier{ID: identity.IdentifierID(data.ID), UserID: data.UserID, Kind: identity.IdentifierAnonymousPlaceholder, CanonicalValue: string(data.ID) + "@anonymous.invalid", Version: 1}}
			fields, err := kernel.AnonymousCreationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			spec.Fields = append(spec.Fields, fields...)
			remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: 15 * time.Minute, FreshFor: 15 * time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "anonymous-deployment", TenantID: data.TenantID}, data.UserID)
			family, idSession := "family-"+string(data.ID), "session-"+string(data.ID)
			sk, _ := sessionpg.SessionAuthorityKeys(data.TenantID, data.UserID, family, idSession)
			pk, _ := (policy.AuthorityScope{TenantID: authorization.TenantID(data.TenantID), PolicyNamespace: "guests", SubjectID: authorization.SubjectID(data.UserID)}).Key()
			a := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
			vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), SessionFamily: a(sk.Family), Session: a(sk.Session), Authorization: a(pk)})
			if err != nil {
				t.Fatal(err)
			}
			token, _ := session.NewToken(32)
			key, _ := session.NewDigestKey(1, make([]byte, 32))
			digest, err := token.Digest(key, string(data.TenantID))
			if err != nil {
				t.Fatal(err)
			}
			record, err := session.NewSession(session.SessionSpec{SessionID: idSession, FamilyID: family, TenantID: data.TenantID, UserID: data.UserID, Audience: "service-a", Version: 1, FamilyVersion: 1, Lookup: digest, Authority: vector, Remember: remember, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: data.CreatedAt}, IssuedAt: data.CreatedAt, LastActivityAt: data.CreatedAt})
			if err != nil {
				t.Fatal(err)
			}
			sessionFields, err := sessionpg.AnonymousSigninSessionFields(record)
			if err != nil {
				t.Fatal(err)
			}
			spec.Fields = append(spec.Fields, sessionFields...)
			command, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			phase := &creationPhase{repository: repository, domain: domain, effect: effect, intent: intent, original: command, mode: mode}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{kernelRepository, &lifecycleAudit{fail: mode == "audit-failure"}, &lifecycleOutbox{fail: mode == "outbox-failure"}, phase})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: "identity.anonymous.create", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "anonymous_flow", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "anonymous_flow", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "standard"}})
			if err != nil {
				t.Fatal(err)
			}
			auditDigest, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, "anonymous_flow", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "anonymous_flow", Feature: &kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: spec.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "anonymous.created.v1"}, Audits: []kernel.AuditPlan{{EventType: "identity.anonymous.create", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "standard", BindingDigest: auditDigest}}})
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			result, applyErr := coordinator.ApplyFeature(ctx, work, command)
			if applyErr != nil {
				result, _ = coordinator.Abort(work, applyErr)
			} else {
				result, err = coordinator.Commit(work, result)
			}
			success := mode == "commit"
			if success && (applyErr != nil || err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("native anonymous composition failed", applyErr, err, result.Outcome)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid anonymous composition committed")
			}
			if (mode == "rollback" || mode == "audit-failure" || mode == "outbox-failure" || mode == "final-denial") && !phase.staged {
				t.Fatal("rollback oracle did not reach actual session persistence")
			}
			var users, subjects, sessions, credentials, outbox, audits int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM anonymous_store.subjects WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.anonymous_outbox WHERE command_id=$3),(SELECT count(*) FROM public.anonymous_audits WHERE command_id=$3 AND succeeded)`, string(data.TenantID), string(data.UserID), string(b.CommandID)).Scan(&users, &subjects, &sessions, &credentials, &outbox, &audits); err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if users != want || subjects != want || sessions != want || credentials != 0 || outbox != want || audits != want {
				t.Fatal("native owners lost atomicity", users, subjects, sessions, credentials, outbox, audits)
			}
			if success {
				stored, err := repository.Read(ctx, anonymous.SubjectQuery{TenantID: data.TenantID, UserID: data.UserID})
				if err != nil {
					t.Fatal(err)
				}
				got, _ := stored.Record()
				if got != data {
					t.Fatal("actual lifecycle state changed")
				}
				if _, err := repository.Read(ctx, anonymous.SubjectQuery{TenantID: "tenant-b", UserID: data.UserID}); err != anonymous.ErrSubjectAbsent {
					t.Fatal("anonymous read crossed tenant", err)
				}
				testAnonymousSessionRecognition(t, ctx, pool, data, token, key)
				_, replay, err := coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("original creation replay lost", err)
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE anonymous_store.subjects SET state=$3,version=2 WHERE tenant_id=$1 AND user_id=$2`, string(data.TenantID), string(data.UserID), int16(anonymous.StateDeleted)); err != nil {
					t.Fatal(err)
				}
				stored, err = repository.Read(ctx, anonymous.SubjectQuery{TenantID: data.TenantID, UserID: data.UserID})
				if err != nil {
					t.Fatal(err)
				}
				got, _ = stored.Record()
				if got.State != anonymous.StateDeleted || got.Version != 2 || stored.RequireActive(data.TenantID, now) == nil {
					t.Fatal("terminal lifecycle was revived")
				}
			}
		})
	}
}
