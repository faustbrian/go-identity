//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// This declared native seam tests actual kernel writes and sole-transaction
// ownership, not risk policy, anonymous lifecycle storage or session issuance.
type anonymousCreationPhase struct {
	domain   *AnonymousCreationDomain
	expected identity.Command
	intent   AnonymousCreationIntent
	mode     string
}

type anonymousCreationAuditPhase struct {
	recoveryAuditPhase
	successAttempted bool
}

func (p *anonymousCreationAuditPhase) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, record := range records {
		succeeded := record.Record.Outcome() == audit.OutcomeSucceeded
		p.successAttempted = p.successAttempted || succeeded
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_audits(event_id,command_id,succeeded) VALUES($1,$2,$3)`, record.Record.ID(), string(w.state.binding.CommandID), succeeded); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}

func (*anonymousCreationPhase) Descriptor() ContributorDescriptor {
	return anonymousCreationDescriptor()
}
func (*anonymousCreationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{anonymousCreationOperation()}
}
func (p *anonymousCreationPhase) ValidateFeatureCommand(c identity.Command, _ CommandPlan) error {
	if c != p.expected {
		return invalidAnonymousCreation()
	}
	return nil
}
func (p *anonymousCreationPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	if p.mode != "missing-kernel" {
		candidate := command
		if p.mode == "reconstructed-command" {
			spec, _ := command.Feature()
			candidate, _ = identity.NewFeatureCommand(spec)
		}
		user, err := p.domain.Apply(ctx, w, p, candidate, p.intent)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		observed, placeholder, err := w.AnonymousCreation(p)
		if err != nil || user != observed || placeholder != p.intent.Placeholder {
			return identity.FeatureReceipt{}, invalidAnonymousCreation()
		}
		admission := AnonymousAuthorityRecord{User: user, Placeholder: placeholder, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}
		if p.mode == "wrong-anonymous-epoch" {
			admission.CredentialAuthorityVersion = 2
		}
		if err := w.RequireAnonymousAuthority(ctx, p, admission); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if p.mode == "duplicate-kernel" {
			// Ignoring the duplicate's error must not erase Work failure.
			_, _ = p.domain.Apply(ctx, w, p, command, p.intent)
		}
	}
	if p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	spec, _ := command.Feature()
	_, err := w.Exec(ctx, `INSERT INTO public.identity_test_anonymous_effect(command_id,user_id) VALUES($1,$2)`, string(spec.Binding.CommandID), string(p.intent.Creation.Binding.UserID))
	return identity.FeatureReceipt{Operation: spec.Operation}, err
}
func (*anonymousCreationPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_anonymous_effect")
}
func (p *anonymousCreationPhase) CheckFeatureCommit(ctx context.Context, w Work, command identity.Command) error {
	if command != p.expected || p.mode == "final-check-failure" {
		return identity.ForbiddenError{}
	}
	// Creation custody is Apply-local, not a renewable commit-time capability.
	if _, _, err := w.AnonymousCreation(p); err == nil {
		return invalidAnonymousCreation()
	}
	return ctx.Err()
}

func anonymousKernelDatabase(t *testing.T) (context.Context, *database.Pool, *Repository) {
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
		t.Fatal("disposable cluster unavailable")
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
	name := "identity_anonymous_" + string(id)
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
	var selected string
	if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&selected); err != nil || selected != name {
		t.Fatal("wrong isolated database")
	}
	history, err := (AnonymousDisposalMigrationSource{Base: AnonymousIdentityMigrationSource{Base: IdentifierNormalizationMigrationSource{Base: IdentifierMutationMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal("anonymous history", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE,succeeded bool NOT NULL);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_anonymous_effect(command_id text PRIMARY KEY,user_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	repository, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{storageSchema()}})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, repository
}

func TestAnonymousCreationPostgres(t *testing.T) {
	ctx, pool, repository := anonymousKernelDatabase(t)
	domain, err := NewAnonymousCreationDomain(repository)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-kernel", "duplicate-kernel", "reconstructed-command", "changed-subject", "changed-attributes", "changed-actor", "changed-tenant", "unknown-field", "retired-placeholder", "wrong-anonymous-epoch", "native-failure", "audit-failure", "outbox-failure", "final-check-failure"} {
		t.Run(mode, func(t *testing.T) {
			intent := anonymousCreationIntentFixture()
			b := intent.Creation.Binding
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			intent.Creation.Binding.CommandID = b.CommandID
			intent.Creation.Binding.UserID = identity.UserID(id)
			intent.Creation.Attributes[0].Value.Scalar.String = "Guest"
			intent.Placeholder.ID, intent.Placeholder.UserID, intent.Placeholder.CanonicalValue = identity.IdentifierID(id), identity.UserID(id), string(id)+"@anonymous.invalid"
			if mode == "retired-placeholder" {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'retired-guest','deleted',1)`, string(b.TenantID)); err != nil {
					t.Fatal(err)
				}
				digest := [32]byte{1}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifier_retirements(tenant_id,user_id,identifier_id,kind,record_version,verification_version,removed,command_id,key_version,value_digest,retired_at,reuse_until) VALUES($1,'retired-guest',$2,'anonymous-placeholder',1,1,true,$3,1,$4,clock_timestamp(),clock_timestamp()+interval '1 day')`, string(b.TenantID), string(intent.Placeholder.ID), string(b.CommandID), digest[:]); err != nil {
					t.Fatal(err)
				}
			}
			fields, err := AnonymousCreationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			op := anonymousCreationOperation()
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			b.UserID, b.AnonymousFlowID = "", string(b.CommandID)
			if mode == "unknown-field" {
				fields = append(fields, identity.FeatureField{Name: "anonymous.creation.extra", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "unexpected"}})
			}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			if err != nil {
				t.Fatal("anonymous command", err)
			}
			phase := &anonymousCreationPhase{domain: domain, expected: command, intent: intent, mode: mode}
			switch mode {
			case "changed-subject":
				phase.intent.Creation.Binding.UserID = "AAAAAAAAAAAAAAAAAAAAAQ"
				phase.intent.Placeholder.UserID = phase.intent.Creation.Binding.UserID
				phase.intent.Placeholder.CanonicalValue = string(phase.intent.Creation.Binding.UserID) + "@anonymous.invalid"
			case "changed-attributes":
				phase.intent.Creation.Attributes = storageValues()
			case "changed-actor":
				phase.intent.Creation.Binding.ActorID = "another-actor"
			case "changed-tenant":
				phase.intent.Creation.Binding.TenantID = "another-tenant"
			}
			auditing := &anonymousCreationAuditPhase{recoveryAuditPhase: recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}}
			outbox := &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}
			registry, err := NewContributorRegistry([]Contributor{repository, auditing, outbox, phase})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.Feature, plan.SubjectType = registry.Descriptors(), &FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, "anonymous_flow"
			plan.Lifecycle = &LifecyclePlan{EventType: "anonymous.created.v1"}
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = op.OperationID, "protected"
			seed, err := securityMutationAudit(ctx, b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", op.OperationID, plan.SubjectType, b.AnonymousFlowID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal("anonymous plan", err)
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
			if success && (err != nil || applyErr != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("anonymous kernel did not commit", err, applyErr, result.Outcome)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid anonymous creation committed")
			}
			for _, table := range []string{"identity.users", "identity.identifiers", "identity.user_attributes"} {
				var count int
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(id)).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if success && count != 1 || !success && count != 0 {
					t.Fatalf("%s did not conserve atomic creation: %d", table, count)
				}
			}
			var refs, bindings, native, audit, lifecycle int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),
(SELECT count(*) FROM identity.anonymous_creation_bindings WHERE tenant_id=$1 AND user_id=$2),
(SELECT count(*) FROM public.identity_test_anonymous_effect WHERE command_id=$3),
(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3 AND succeeded),
(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3)`, string(b.TenantID), string(id), string(b.CommandID)).Scan(&refs, &bindings, &native, &audit, &lifecycle); err != nil {
				t.Fatal(err)
			}
			if refs != 0 || success && (bindings != 1 || native != 1 || audit != 1 || lifecycle != 1) || !success && (bindings != 0 || native != 0 || audit != 0 || lifecycle != 0) {
				t.Fatal("anonymous creation lost transaction boundary or invented credential authority", refs, bindings, native, audit, lifecycle)
			}
			if (mode == "outbox-failure" || mode == "final-check-failure") && !auditing.successAttempted {
				t.Fatal("rollback control never reached provisional successful audit")
			}
			if success {
				replayed, receipt, err := coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil || replayed.state != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("original anonymous creation replay lost", err)
				}
				query := identity.UserStatusQuery{TenantID: b.TenantID, UserID: identity.UserID(id)}
				authority, err := repository.GetAnonymousAuthority(ctx, query)
				if err != nil || authority.User.ID != query.UserID || authority.User.Status != identity.StatusActive || authority.UserAuthorityVersion != 1 || authority.IdentifierAuthorityVersion != 1 || authority.CredentialAuthorityVersion != 1 || authority.Placeholder != intent.Placeholder {
					t.Fatal("actual anonymous kernel authority unavailable", err)
				}
				foreign := query
				foreign.TenantID = "another-tenant"
				if got, err := repository.GetAnonymousAuthority(ctx, foreign); err == nil || got != (AnonymousAuthorityRecord{}) {
					t.Fatal("anonymous authority crossed tenant")
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=2,credential_version=3 WHERE tenant_id=$1 AND user_id=$2`, string(query.TenantID), string(query.UserID)); err != nil {
					t.Fatal(err)
				}
				authority, err = repository.GetAnonymousAuthority(ctx, query)
				if err != nil || authority.UserAuthorityVersion != 2 || authority.CredentialAuthorityVersion != 3 {
					t.Fatal("anonymous read invented default epochs", err)
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned',version=2,authority_version=3 WHERE tenant_id=$1 AND user_id=$2`, string(query.TenantID), string(query.UserID)); err != nil {
					t.Fatal(err)
				}
				authority, err = repository.GetAnonymousAuthority(ctx, query)
				if err != nil || authority.User.Status != identity.StatusBanned || authority.User.Version != 2 || authority.UserAuthorityVersion != 3 {
					t.Fatal("anonymous primary read erased blocking", err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'permanent-password',1,'identity/password',1,true)`, string(query.TenantID), string(query.UserID)); err != nil {
					t.Fatal(err)
				}
				if got, err := repository.GetAnonymousAuthority(ctx, query); err == nil || got != (AnonymousAuthorityRecord{}) {
					t.Fatal("permanent credential retained anonymous authority")
				}
			}
		})
	}
}
