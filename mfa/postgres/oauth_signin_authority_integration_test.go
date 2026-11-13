//go:build integration

package mfapostgres

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The controlled participant tests the real coordinator and factor/account rows,
// not provider authentication or complete session issuance.
type oauthSigninFactorInvocation struct {
	op                       identity.FeatureOperation
	pool                     *database.Pool
	mode                     string
	applied, final, lockHeld bool
	retained                 kernel.Work
	command                  identity.Command
	original                 identity.Command
	declaration              kernel.CommandPlan
}

func (*oauthSigninFactorInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.signin", Version: 1}
}
func (p *oauthSigninFactorInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*oauthSigninFactorInvocation) ValidateFeatureCommand(identity.Command, kernel.CommandPlan) error {
	return nil
}
func (*oauthSigninFactorInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

// The immutable output/admission below is a controlled preparation double, not
// an authenticated provider/risk envelope. The real kernel still owns journal,
// generation, original command custody and transaction scheduling.
type oauthSigninFactorAdmission struct{}

func (oauthSigninFactorAdmission) Check(ctx context.Context) error { return ctx.Err() }
func (a oauthSigninFactorAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	if generation == 0 {
		return nil, identity.InvalidInputError{Field: "test_preparation"}
	}
	return binary.BigEndian.AppendUint64(nil, generation), nil
}

func (p *oauthSigninFactorInvocation) ValidateFeaturePreparation(command identity.Command, _ kernel.CommandPlan) error {
	if command != p.original {
		return identity.InvalidInputError{Field: "test_preparation"}
	}
	return nil
}
func (p *oauthSigninFactorInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	f, ok := command.Feature()
	b, registration, _, err := w.FeatureScope(p)
	if err != nil || !ok || command != p.original || b != f.Binding || registration.Operation != p.op {
		return identity.InvalidInputError{Field: "test_preparation"}
	}
	return ctx.Err()
}
func (p *oauthSigninFactorInvocation) GenerateFeaturePreparation(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	if err := p.ValidateFeaturePreparation(command, p.declaration); err != nil {
		return nil, err
	}
	return (oauthSigninFactorAdmission{}).Generate(ctx, generation)
}
func (p *oauthSigninFactorInvocation) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if ctx.Err() != nil || command != p.original || generation == 0 || len(wire) != 8 || binary.BigEndian.Uint64(wire) != generation {
		return identity.Command{}, kernel.CommandPlan{}, identity.InvalidInputError{Field: "test_preparation"}
	}
	return command, p.declaration, nil
}
func (p *oauthSigninFactorInvocation) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeaturePreparation(command, p.declaration); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return oauthSigninFactorAdmission{}, nil
}
func (p *oauthSigninFactorInvocation) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, command, generation, wire); err != nil {
		return nil, err
	}
	return oauthSigninFactorAdmission{}, nil
}

func (p *oauthSigninFactorInvocation) check(ctx context.Context, w kernel.Work, command identity.Command) error {
	owner := p
	if p.mode == "foreign-owner" {
		copy := *p
		owner = &copy
	}
	version := uint64(1)
	if p.mode == "zero-version" {
		version = 0
	}
	if p.mode == "reconstructed-command" {
		spec, _ := command.Feature()
		cookie, _ := command.PreAuthCookie()
		var err error
		command, err = identity.NewFeaturePreAuthCommand(spec, cookie)
		if err != nil {
			return err
		}
	}
	state, err := RequireOAuthSigninFactors(ctx, w, owner, command, version)
	if err == nil && (state.Version() != 1 || state.RequireEmailRecovery("tenant-a", "user-a") != nil) {
		return identity.ForbiddenError{}
	}
	return err
}

func (p *oauthSigninFactorInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.retained, p.command = w, command
	f, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO oauth_signin_factor_probe VALUES($1)`, string(f.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.check(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	if p.mode == "current" {
		other, err := p.pool.Raw().Begin(ctx)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		_, lockErr := other.Exec(ctx, `SELECT version FROM identity_mfa.factor_authorities WHERE tenant_id='tenant-a' AND user_id='user-a' FOR UPDATE NOWAIT`)
		_ = other.Rollback(ctx)
		var locked *pgconn.PgError
		p.lockHeld = errors.As(lockErr, &locked) && locked.Code == "55P03"
		if !p.lockHeld {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
	}
	if p.mode == "late-enrolled" {
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.op}, nil
}
func (p *oauthSigninFactorInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if err := p.check(ctx, w, command); err != nil {
		return err
	}
	p.final = true
	return nil
}

func newOAuthSigninFactorStore(t *testing.T) (context.Context, *database.Pool, *kernel.Repository) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	dsn, directory := os.Getenv("IDENTITY_MFA_TEST_DSN"), os.Getenv("IDENTITY_POSTGRES_TEST_DATA_DIRECTORY")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" || !filepath.IsAbs(directory) {
		t.Fatal("explicit owned loopback identity_test cluster required")
	}
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("owned cluster unavailable")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	var actual string
	if err := admin.QueryRow(ctx, "SHOW data_directory").Scan(&actual); err != nil || actual != directory {
		t.Fatal("not the exact task-owned cluster")
	}
	id, _ := identity.NewSubjectID()
	name := "oauth_signin_factors_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup", err)
		}
	})
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("owned pool cleanup", err)
		}
	})
	accounts := kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	history, err := (kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: accounts, Version: 13}, Version: 14}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range history {
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("actual account history", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, authoritySQL+`
CREATE TABLE oauth_signin_factor_probe(command_id text PRIMARY KEY);
CREATE TABLE signup_factor_audits(id text PRIMARY KEY,command_id text NOT NULL,succeeded bool NOT NULL);
CREATE TABLE signup_factor_events(id text PRIMARY KEY,command_id text NOT NULL,kind text NOT NULL);
INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup');
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a','user-a','provider-ref',3,'identity/oauth',1,true);
WITH a AS (SELECT 'oidc'::text AS provider,'https://issuer.example'::text AS issuer,'opaque-subject'::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT 'tenant-a','user-a','provider-account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a;
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant-a','user-a','provider-ref','provider-account');`); err != nil {
		t.Fatal("native factor/account rows", err)
	}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, repo
}

func TestOAuthSigninFactorsPostgres(t *testing.T) {
	ctx, pool, repository := newOAuthSigninFactorStore(t)
	account, err := repository.GetProviderSigninAccount(ctx, kernel.ProviderSigninAccountQuery{TenantID: "tenant-a", Provider: "oidc", Issuer: "https://issuer.example", Subject: "opaque-subject"})
	if err != nil {
		t.Fatal("original existing provider account", err)
	}
	fields, err := kernel.OAuthSigninAccountFields(account)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if observed, err := ReadOAuthSigninFactors(cancelled, pool, "tenant-a", "user-a", time.Second); !errors.Is(err, context.Canceled) || observed.Version() != 0 {
		t.Fatal("cancelled primary read supplied factor metadata", err)
	}
	for _, mode := range []string{"current", "missing", "enrolled", "stale", "foreign-owner", "zero-version", "reconstructed-command", "late-enrolled"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities; INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','user-a',1,0,decode(repeat('01',16),'hex'),'identity.password.signup')`); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing":
				_, err = pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities`)
			case "enrolled":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1`)
			case "stale":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2`)
			}
			if err != nil {
				t.Fatal(err)
			}
			observed, readErr := ReadOAuthSigninFactors(ctx, pool, "tenant-a", "user-a", time.Second)
			if (readErr != nil) != (mode == "missing" || mode == "enrolled") || readErr != nil && observed.Version() != 0 {
				t.Fatal("known-empty primary metadata", readErr)
			}
			if mode == "stale" && observed.Version() != 2 {
				t.Fatal("primary read invented original generation")
			}
			id, _ := identity.NewCommandID()
			op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			binding := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", ActorID: "social-login", ActorKind: authorization.SubjectServiceAccount, AnonymousFlowID: "original-flow", OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "social-signin", PolicyVersion: 1, CorrelationID: string(id)}
			command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			owner := &oauthSigninFactorInvocation{op: op, pool: pool, mode: mode}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repository, &signupFactorAudit{}, &signupFactorOutbox{}, owner})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "oauth_signin", ID: string(binding.AnonymousFlowID)}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "oauth_signin", "aggregate.id": string(binding.AnonymousFlowID), "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(binding, op, "oauth_signin", seed)
			if err != nil {
				t.Fatal(err)
			}
			declaration := kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "oauth_signin", Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "oauth.signin.v1"}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			owner.original, owner.declaration = command, declaration
			plan, err := coordinator.PrepareFeaturePreparationPlan(command, declaration)
			if err != nil {
				t.Fatal("prepare original callback", err)
			}
			result, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
			if owner.command != command {
				t.Fatal("factor check did not receive the unchanged original callback", err)
			}
			success := mode == "current"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || !owner.applied || !owner.final || !owner.lockHeld) {
				t.Fatal("current known-empty callback fenced incorrectly", result.Outcome, "entered", owner.command != (identity.Command{}), "applied", owner.applied, "final", owner.final, "locked", owner.lockHeld, err)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("denied factor authority committed")
			}
			if mode == "late-enrolled" && (!owner.applied || owner.final) {
				t.Fatal("final check did not reject intervening enrollment")
			}
			if _, err := RequireOAuthSigninFactors(ctx, owner.retained, owner, owner.command, 1); err == nil {
				t.Fatal("returned Work retained MFA authority")
			}
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM oauth_signin_factor_probe WHERE command_id=$1`, string(id)).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if count != want {
				t.Fatal("denied or late-enrolled effects survived", count, want)
			}
		})
	}
}
