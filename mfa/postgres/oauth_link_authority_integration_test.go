//go:build integration

package mfapostgres

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// This controlled owner exercises real coordinator phases and the actual MFA
// table. It does not implement OAuth exchange, session authentication or linking.
// Prepared callback-state grants use the real capability issuer and checkpoint.
type oauthLinkFactorInvocation struct {
	op                                 identity.FeatureOperation
	descriptor                         kernel.ContributorDescriptor
	plan                               kernel.CommandPlan
	issuer                             *identitycapability.Issuer
	checkpoint                         *identitycapability.IssuancePreparationCodec
	issuance                           kernel.CapabilityIssuancePlan
	prepared                           identitycapability.PreparedIssuance
	pool                               *database.Pool
	mode                               string
	admitted, applied, final, lockHeld bool
	retained                           kernel.Work
	command                            identity.Command
}

func (p *oauthLinkFactorInvocation) Descriptor() kernel.ContributorDescriptor { return p.descriptor }
func (p *oauthLinkFactorInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*oauthLinkFactorInvocation) ValidateFeatureCommand(identity.Command, kernel.CommandPlan) error {
	return nil
}
func (*oauthLinkFactorInvocation) ValidateFeaturePreparation(identity.Command, kernel.CommandPlan) error {
	return nil
}
func (*oauthLinkFactorInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func (p *oauthLinkFactorInvocation) check(ctx context.Context, w kernel.Work, c identity.Command) error {
	owner := p
	if p.mode == "foreign-owner" {
		copy := *p
		owner = &copy
	}
	version := uint64(1)
	if p.mode == "zero-version" {
		version = 0
	}
	state, err := RequireOAuthLinkStartFactors(ctx, w, owner, c, version)
	if err == nil && (state.Version() != 1 || state.RequireEmailRecovery("tenant-a", "user-a") != nil) {
		return identity.ForbiddenError{}
	}
	return err
}

func (p *oauthLinkFactorInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.check(ctx, w, c); err != nil {
		return err
	}
	p.admitted = true
	return nil
}
func (p *oauthLinkFactorInvocation) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	b := mustOAuthFactorBinding(c)
	now := time.Now().UTC().Truncate(time.Second)
	state := capability.Payload{
		Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"identity"},
		Subject: string(b.UserID), Tenant: string(b.TenantID), Resource: b.RecordID,
		Operation: "identity.oauth.callback", CorrelationID: b.CorrelationID,
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1,
	}
	prepared, err := p.issuer.Prepare(ctx, b, []capability.Payload{state})
	if err != nil {
		return nil, err
	}
	p.issuance, err = prepared.Plan()
	if err != nil {
		return nil, err
	}
	return p.checkpoint.CheckpointPreparation(ctx, prepared, generation, nil)
}
func (p *oauthLinkFactorInvocation) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	prepared, err := p.checkpoint.RestorePreparation(ctx, mustOAuthFactorBinding(c), generation, p.issuance, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.prepared = prepared
	final := p.plan
	final.Contributors = append([]kernel.ContributorDescriptor(nil), final.Contributors...)
	final.Contributors = append(final.Contributors, p.issuer.Descriptor())
	final.CapabilityIssuance = &p.issuance
	return c, final, nil
}
func (p *oauthLinkFactorInvocation) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.retained, p.command = w, c
	if _, err := w.Exec(ctx, `INSERT INTO oauth_factor_probe VALUES($1)`, string(mustOAuthFactorBinding(c).CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.check(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.issuer != nil {
		if err := p.issuer.Stage(ctx, w, p.prepared); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	p.applied = true
	if p.mode == "known-empty" {
		blocked, stop := context.WithTimeout(ctx, 30*time.Millisecond)
		defer stop()
		_, err := p.pool.Raw().Exec(blocked, `UPDATE identity_mfa.factor_authorities SET version=2 WHERE tenant_id='tenant-a' AND user_id='user-a'`)
		p.lockHeld = err != nil && blocked.Err() != nil
		if !p.lockHeld {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
	}
	if p.mode == "late-enrolled" {
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.op, AfterVersion: 1}, nil
}
func (p *oauthLinkFactorInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.check(ctx, w, c); err != nil {
		return err
	}
	p.final = true
	return nil
}
func mustOAuthFactorBinding(c identity.Command) identity.CommandBinding {
	s, _ := c.Feature()
	return s.Binding
}

func oauthLinkFactorIssuer(t *testing.T) (*identitycapability.Issuer, *identitycapability.IssuancePreparationCodec) {
	t.Helper()
	signing := bytes.Repeat([]byte{9}, 32)
	signer, err := capability.NewHMACSHA256Signer("signing-v1", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "signing-v1", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := identitycapability.NewIssuer(identitycapability.IssuerConfig{
		Crypto: capability.ServiceConfig{
			Issuer: "https://identity.example.test", Signer: signer, Resolver: keys,
			Clock: time.Now, Limits: capability.DefaultLimits(),
		},
		Audience: "identity", CurrentReplayKeyVersion: 1,
		RetainedReplayKeys: map[uint32][32]byte{1: {6}}, PreparationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := identitycapability.NewIssuancePreparationCodec(issuer, identitycapability.IssuancePreparationConfig{
		Deployment: "oauth-factor-test", ActiveEnvelopeKey: "checkpoint",
		EnvelopeKeys: map[string][]byte{"checkpoint": bytes.Repeat([]byte{7}, 32)},
		VerificationKeys: []identitycapability.PreparationVerificationKey{{ID: "signing-v1", HMAC: signing}},
		Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issuer, checkpoint
}

func TestOAuthLinkFactorsPostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_MFA_TEST_DSN")
	c, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || c.Host != "127.0.0.1" || c.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test cluster required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal("owned cluster unavailable")
	}
	defer admin.Close(context.Background())
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "oauth_link_factors_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup failed")
		}
	}()
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("owned pool cleanup failed")
		}
	}()
	preparation := kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 100}
	admission := kernel.AdmissionPreparationMigrationSource{Base: preparation, Version: 101}
	counters := kernel.CounterPreparationMigrationSource{Base: admission, Version: 102}
	history, err := (kernel.OAuthRPPreparationErasureMigrationSource{Base: counters, Version: 103}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range history {
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	source := identitycapability.Migrations()
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		contents, err := fs.ReadFile(source, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
			t.Fatal("capability install", entry.Name(), err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, authoritySQL+`
ALTER TABLE identity_mfa.factor_authorities DROP CONSTRAINT factor_authorities_active_factors_check;
CREATE TABLE oauth_factor_probe(command_id text PRIMARY KEY);
CREATE TABLE signup_factor_audits(id text PRIMARY KEY,command_id text NOT NULL,succeeded bool NOT NULL);
CREATE TABLE signup_factor_events(id text PRIMARY KEY,command_id text NOT NULL,kind text NOT NULL);
INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup');`); err != nil {
		t.Fatal(err)
	}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	issuer, checkpoint := oauthLinkFactorIssuer(t)
	for _, mode := range []string{"known-empty", "enrolled", "stale", "missing", "corrupt", "foreign-owner", "zero-version", "foreign-schema", "foreign-lifecycle", "foreign-user", "late-enrolled", "preparation", "preparation-enrolled", "preparation-missing"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities; INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','user-a',1,0,decode(repeat('01',16),'hex'),'identity.password.signup')`); err != nil {
				t.Fatal(err)
			}
			s, registration, life := oauthLinkStartFactorFixture(t)
			p := &oauthLinkFactorInvocation{op: s.Operation, descriptor: registration.Contributor, mode: mode, pool: pool}
			preparing := strings.HasPrefix(mode, "preparation")
			switch mode {
			case "enrolled", "preparation-enrolled":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1`)
			case "stale":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2`)
			case "missing", "preparation-missing":
				_, err = pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities`)
			case "corrupt":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=65`)
			case "foreign-schema":
				p.op.SchemaID += ".alias"
				s.Operation = p.op
				s.Binding.SchemaID = p.op.SchemaID
			case "foreign-lifecycle":
				life.EventType = "session.created.v1"
			case "foreign-user":
				s.Binding.ActorID, s.Binding.UserID = "other-user", "other-user"
			}
			if err != nil {
				t.Fatal(err)
			}
			state, readErr := ReadOAuthLinkFactors(ctx, pool, "tenant-a", "user-a", time.Second)
			readDenies := mode == "enrolled" || mode == "missing" || mode == "corrupt" || mode == "preparation-enrolled" || mode == "preparation-missing"
			if (readErr != nil) != readDenies || readErr != nil && state.Version() != 0 {
				t.Fatal("primary no-factor observation", readErr)
			}
			if mode == "stale" && state.Version() != 2 {
				t.Fatal("primary observation must retain actual current generation")
			}
			command, err := identity.NewFeatureCommand(s)
			if err != nil {
				t.Fatal(err)
			}
			contributors := []kernel.Contributor{repo, &signupFactorAudit{}, &signupFactorOutbox{}, p}
			subjectType := "oauth_rp"
			if preparing {
				p.issuer, p.checkpoint = issuer, checkpoint
				contributors = append(contributors, issuer)
				subjectType = "oauth_transaction"
			}
			registry, err := kernel.NewContributorRegistry(contributors)
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: s.Operation.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(s.Binding.ActorID)}, Subject: audit.SubjectInput{Type: subjectType, ID: s.Binding.RecordID}, Context: audit.ContextInput{TenantID: string(s.Binding.TenantID), CorrelationID: s.Binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: s.Binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(s.Binding.CommandID), "aggregate.type": subjectType, "aggregate.id": s.Binding.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(s.Binding, s.Operation, subjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			originalContributors := registry.Descriptors()
			if preparing {
				// The closed RP profile adds its issuer only after original preparation.
				originalContributors = originalContributors[:len(originalContributors)-1]
			}
			declaration := kernel.CommandPlan{Contributors: originalContributors, SubjectType: subjectType, Feature: &kernel.FeatureRegistration{Contributor: p.descriptor, Operation: p.op}, Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: s.Operation.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			var result identity.CommandResult
			if preparing {
				p.plan = declaration
				plan, err := coordinator.PrepareFeaturePreparationPlan(command, declaration)
				if err != nil {
					t.Fatal("prepare original", err)
				}
				result, err = coordinator.ExecutePreparedFeature(ctx, command, plan)
			} else {
				plan, planErr := coordinator.PrepareCommandPlan(s.Binding, command, declaration)
				if planErr != nil {
					t.Fatal("prepare", planErr)
				}
				reservation, _, reserveErr := coordinator.ReserveCommand(ctx, s.Binding, command, plan)
				if reserveErr != nil {
					t.Fatal("reserve", reserveErr)
				}
				work, beginErr := coordinator.Begin(ctx, reservation)
				if beginErr != nil {
					t.Fatal("begin", beginErr)
				}
				var applyErr error
				result, applyErr = coordinator.ApplyFeature(ctx, work, command)
				if applyErr != nil {
					result, err = coordinator.Abort(work, applyErr)
				} else {
					result, err = coordinator.Commit(work, result)
				}
			}
			success := mode == "known-empty" || mode == "preparation"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || !p.applied || !p.final) {
				t.Fatalf("known-empty phases failed: result=%v applied=%v final=%v err=%v", result.Outcome, p.applied, p.final, err)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("denied authority committed")
			}
			if mode == "known-empty" && !p.lockHeld {
				t.Fatal("factor writer was not fenced until Work closed")
			}
			if mode == "preparation" && !p.admitted {
				t.Fatal("preparation admission did not fence original factors")
			}
			if mode == "late-enrolled" && (!p.applied || p.final) {
				t.Fatal("final admission did not reject intervening enrollment")
			}
			if _, err := RequireOAuthLinkStartFactors(ctx, p.retained, p, p.command, 1); err == nil {
				t.Fatal("returned invocation retained authority")
			}
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM oauth_factor_probe WHERE command_id=$1`, string(s.Binding.CommandID)).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if count != want {
				t.Fatalf("provisional effects=%d want=%d", count, want)
			}
			if preparing {
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$1`, string(s.Binding.CommandID)).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != want {
					t.Fatalf("original state grants=%d want=%d", count, want)
				}
			}
		})
	}
}
