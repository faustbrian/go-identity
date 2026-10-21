//go:build integration

package postgres

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
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// This declared native component seam proves actual kernel/session ownership
// and atomicity, not risk admission, the anonymous lifecycle or public signin.
type anonymousSessionFeature struct {
	domain   *kernel.AnonymousCreationDomain
	effect   *AnonymousSigninEffect
	intent   kernel.AnonymousCreationIntent
	original identity.Command
	expected kernel.AnonymousAuthorityRecord
	mode     string
	applied  bool
}

func (*anonymousSessionFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
}
func (*anonymousSessionFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{anonymousSessionOperation()}
}
func (p *anonymousSessionFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.original {
		return identity.ForbiddenError{}
	}
	_, err := AnonymousSigninSession(c)
	return err
}
func (p *anonymousSessionFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.mode != "missing-creation" {
		user, err := p.domain.Apply(ctx, w, p, c, p.intent)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.expected = kernel.AnonymousAuthorityRecord{User: user, Placeholder: p.intent.Placeholder, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}
	}
	if p.mode != "missing-policy" {
		scope := policy.AuthorityScope{TenantID: authorization.TenantID(p.intent.Creation.Binding.TenantID), PolicyNamespace: "guests", SubjectID: authorization.SubjectID(p.intent.Creation.Binding.UserID)}
		if _, err := policy.InitializeAuthority(ctx, w, scope, time.Second); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.mode == "changed-epoch" {
		p.expected.CredentialAuthorityVersion++
	}
	if p.mode == "foreign-command" {
		spec, _ := c.Feature()
		c, _ = identity.NewFeatureCommand(spec)
	}
	r, err := p.effect.Apply(ctx, w, p, c, p.expected)
	p.applied = err == nil
	if err == nil && p.mode == "rollback" {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return r, err
}
func (p *anonymousSessionFeature) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.mode == "final-denial" {
		return identity.ForbiddenError{}
	}
	return p.effect.Check(ctx, w, p, c, p.expected)
}
func (p *anonymousSessionFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

func anonymousSessionDatabase(t *testing.T) (context.Context, *database.Pool, *kernel.Repository) {
	t.Helper()
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
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
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "anonymous_sessions_" + string(id)
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
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
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
	var actual string
	if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&actual); err != nil || actual != name {
		t.Fatal("wrong isolated database")
	}
	kernelSource := kernel.DirectoryAuthorityMigrationSource{Base: kernel.AnonymousIdentityMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: "guest-deployment", TenantIDs: []identity.TenantID{"guest-tenant"}}
	sessionSource := IssueMigrationSource{Base: RevocationMigrationSource{Base: MigrationSource{Schema: "session_store", Version: 20}, Version: 21}, Version: 22}
	for _, source := range []migrations.Source{kernelSource, sessionSource, AnonymousSigninMigrationSource{Schema: "session_store", Version: 23, Predecessor: AnonymousAfterBaseIssuance}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("native history", err)
			}
		}
	}
	policyMigration, err := policy.AuthoritySchemaMigration(24)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, policyMigration.Up); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.revoke_audit(event_id text PRIMARY KEY,command_id text NOT NULL,outcome bigint,record jsonb);
CREATE TABLE public.revoke_outbox(event_id text PRIMARY KEY,command_id text NOT NULL,event_type text,subject_type text,subject_id text,before_version text,after_version text)`); err != nil {
		t.Fatal(err)
	}
	repository, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, repository
}

func TestAnonymousSessionAtomicNativePersistence(t *testing.T) {
	ctx, pool, repository := anonymousSessionDatabase(t)
	domain, err := kernel.NewAnonymousCreationDomain(repository)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := NewAnonymousSigninEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, AnonymousAdmissionConfig{GlobalAuthorityID: "guest-deployment", PolicyNamespace: "guests", Audience: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-creation", "missing-policy", "changed-epoch", "foreign-command", "rollback", "audit-failure", "outbox-failure", "final-denial"} {
		t.Run(mode, func(t *testing.T) {
			spec, original := anonymousSessionMappingFixture(t)
			b := spec.Binding
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.AnonymousFlowID = "guest-tenant", string(b.CommandID)
			id, _ := identity.NewSubjectID()
			creation := b
			creation.UserID, creation.AnonymousFlowID, creation.OperationID, creation.SchemaID = identity.UserID(id), "", "identity.user.create", "guest-profile"
			intent := kernel.AnonymousCreationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Placeholder: identity.Identifier{ID: identity.IdentifierID(id), UserID: identity.UserID(id), Kind: identity.IdentifierAnonymousPlaceholder, CanonicalValue: string(id) + "@anonymous.invalid", Version: 1}}
			s, _ := original.Bindings()
			s.TenantID, s.UserID, s.SessionID, s.FamilyID = b.TenantID, identity.UserID(id), "guest-session-"+mode, "guest-family-"+mode
			now := time.Now().UTC().Truncate(time.Microsecond)
			s.IssuedAt, s.LastActivityAt, s.Authentication.AnonymousAt = now, now, now
			s.Lookup = session.TokenDigest{KeyVersion: 1, Sum: [32]byte{byte(len(mode)), 1}}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "guest-deployment", TenantID: b.TenantID}, s.UserID)
			sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
			pk, _ := (policy.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: "guests", SubjectID: authorization.SubjectID(s.UserID)}).Key()
			a := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
			s.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), Session: a(sk.Session), SessionFamily: a(sk.Family), Authorization: a(pk)})
			if err != nil {
				t.Fatal(err)
			}
			record, err := session.NewSession(s)
			if err != nil {
				t.Fatal(err)
			}
			spec.Binding = b
			spec.Fields, err = AnonymousSigninSessionFields(record)
			if err != nil {
				t.Fatal(err)
			}
			creationFields, err := kernel.AnonymousCreationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			spec.Fields = append(spec.Fields, creationFields...)
			command, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			feature := &anonymousSessionFeature{domain: domain, effect: effect, intent: intent, original: command, mode: mode}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repository, &revokeAudit{fail: mode == "audit-failure"}, &revokeOutbox{fail: mode == "outbox-failure"}, feature})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "anonymous_flow", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "anonymous_flow", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, "anonymous_flow", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "anonymous_flow", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: spec.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "anonymous.created.v1"}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
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
				t.Fatal("native anonymous session failed", applyErr, err, result.Outcome)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid anonymous session committed")
			}
			if (mode == "rollback" || mode == "audit-failure" || mode == "outbox-failure" || mode == "final-denial") && !feature.applied {
				t.Fatal("rollback oracle never reached staged session")
			}
			var users, credentials, sessions, families, issuances int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$1 AND user_id=$2)`, string(b.TenantID), string(s.UserID)).Scan(&users, &credentials, &sessions, &families, &issuances); err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if users != want || sessions != want || families != want || issuances != want || credentials != 0 {
				t.Fatal("anonymous atomicity or no-credential invariant failed", users, credentials, sessions, families, issuances)
			}
			if success {
				_, replay, err := coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("anonymous session replay failed", err)
				}
				got, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{EventType: "anonymous.created.v1"}, anonymousIssuanceDigest)
				if err != nil || status != kernel.RecoveryCommitted || got.UserID != s.UserID || got.SessionID != s.SessionID || got.FamilyID != s.FamilyID {
					t.Fatal("retained original anonymous issuance lost", err)
				}
				if _, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{EventType: "anonymous.created.v1"}, passwordSignupIssuanceDigest); err != nil || status != kernel.RecoveryUnknown {
					t.Fatal("anonymous issuance borrowed password evidence", err)
				}
			}
		})
	}
}
