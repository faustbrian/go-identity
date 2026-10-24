//go:build integration

package mfapostgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// Kernel/MFA are real. These native, audit and outbox seams isolate factor
// initialization; they do not establish WebAuthn verification or session signup.
type passkeySignupFactorPhase struct {
	domain             *kernel.PasskeyRegistrationDomain
	command            identity.Command
	intent             kernel.PasskeyRegistrationIntent
	mode               string
	initialized        bool
	provenanceReplaced bool
}

func (*passkeySignupFactorPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*passkeySignupFactorPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "passkey", OperationID: "identity.passkey.register-verify", SchemaID: "identity.passkey.register-verify.signup-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}}
}
func (p *passkeySignupFactorPhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *passkeySignupFactorPhase) PasskeyRegistration(c identity.Command) (kernel.PasskeyRegistrationIntent, error) {
	if c != p.command {
		return kernel.PasskeyRegistrationIntent{}, identity.ForbiddenError{}
	}
	return p.intent, nil
}
func (*passkeySignupFactorPhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}
func (p *passkeySignupFactorPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.mode == "before-creation" {
		if err := InitializePasskeySignup(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if _, err := p.domain.Apply(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.mode != "missing-initialization" {
		owner, command := kernel.PasskeyRegistrationContributor(p), c
		if p.mode == "foreign-owner" {
			owner = &passkeySignupFactorPhase{}
		}
		if p.mode == "reconstructed-command" {
			s, _ := c.Feature()
			command, _ = identity.NewFeatureCommand(s)
		}
		if err := InitializePasskeySignup(ctx, w, owner, command); err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.initialized = true
		if p.mode == "duplicate" {
			_ = InitializePasskeySignup(ctx, w, p, c)
		}
	}
	if p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	state, err := RequirePasskeySignupFactors(ctx, w, p, c)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if state.Version() != 1 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], AfterVersion: 1}, nil
}
func (p *passkeySignupFactorPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.mode == "late-command-change" {
		// A failed earlier reservation is a real foreign command, but has no
		// factor row. Keep the row present and known-empty while replacing only
		// its original custody; FK/uniqueness checks must not cause this denial.
		n, err := w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET initialized_command_id=(SELECT c.command_id FROM identity.commands c WHERE c.tenant_id=$1 AND c.purpose='identity.passkey.register-verify' AND NOT EXISTS(SELECT 1 FROM identity_mfa.factor_authorities f WHERE f.tenant_id=c.tenant_id AND f.initialized_purpose=c.purpose AND f.initialized_command_id=c.command_id) ORDER BY c.command_id LIMIT 1) WHERE tenant_id=$1 AND user_id=$2`, string(p.intent.Credential.TenantID), string(p.intent.Credential.UserID))
		if err != nil || n != 1 {
			return identity.UnavailableError{}
		}
		p.provenanceReplaced = true
	}
	if p.mode == "late-enrollment" {
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id=$1 AND user_id=$2`, string(p.intent.Credential.TenantID), string(p.intent.Credential.UserID)); err != nil {
			return err
		}
	}
	if p.mode == "late-origin-change" {
		if _, err := w.Exec(ctx, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(p.intent.Credential.TenantID), string(p.intent.Credential.UserID)); err != nil {
			return err
		}
	}
	if p.mode == "late-cancellation" {
		cancelled, stop := context.WithCancel(ctx)
		stop()
		_, err := RequirePasskeySignupFactors(cancelled, w, p, c)
		if err == nil {
			return identity.ForbiddenError{}
		}
		// Ignoring cancellation cannot erase the kernel's poisoned Work.
		return nil
	}
	_, err := RequirePasskeySignupFactors(ctx, w, p, c)
	return err
}

type signupFactorAudit struct{}

func (*signupFactorAudit) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}
}
func (*signupFactorAudit) PersistAudits(ctx context.Context, w kernel.Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	b, err := w.Scope()
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := w.Exec(ctx, `INSERT INTO signup_factor_audits VALUES($1,$2,$3)`, record.Record.ID(), string(b.CommandID), record.Record.Outcome() == audit.OutcomeSucceeded); err != nil {
			return err
		}
	}
	return nil
}
func (*signupFactorAudit) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

type signupFactorOutbox struct{ fail bool }

func (*signupFactorOutbox) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
}
func (p *signupFactorOutbox) PersistLifecycle(ctx context.Context, w kernel.Work) error {
	events, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, event := range events {
		if _, err := w.Exec(ctx, `INSERT INTO signup_factor_events VALUES($1,$2,$3)`, event.ID, string(event.CommandID), event.EventType); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (p *signupFactorOutbox) PersistPasskeyRegistration(ctx context.Context, w kernel.Work) error {
	if err := p.PersistLifecycle(ctx, w); err != nil {
		return err
	}
	event, err := w.StagedPasskeyRegistrationLifecycle()
	if err != nil {
		return err
	}
	_, err = w.Exec(ctx, `INSERT INTO signup_factor_events VALUES($1,$2,$3)`, event.ID, string(event.CommandID), event.EventType)
	return err
}
func (*signupFactorOutbox) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func TestPasskeySignupFactorInitializationPostgres(t *testing.T) {
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
	name := "passkey_signup_factors_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup failed", err)
		}
	}()
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
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
	history, err := (kernel.PasskeyRegistrationMigrationSource{Base: kernel.PasswordSignupAcceptanceMigrationSource{Base: kernel.PasswordRegistrationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	factors, err := (PasskeySignupMigrationSource{Base: UsernameSignupMigrationSource{Base: MagicLinkSignupMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}, Version: 3}, Version: 4}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range factors {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE signup_factor_audits(id text PRIMARY KEY,command_id text NOT NULL,succeeded bool NOT NULL);CREATE TABLE signup_factor_events(id text PRIMARY KEY,command_id text NOT NULL,kind text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewPasskeyRegistrationDomain(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "before-creation", "missing-initialization", "foreign-owner", "reconstructed-command", "duplicate", "native-failure", "outbox-failure", "late-enrollment", "late-origin-change", "late-cancellation", "late-command-change"} {
		t.Run(mode, func(t *testing.T) {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			p := &passkeySignupFactorPhase{domain: domain, mode: mode}
			op := p.FeatureOperations()[0]
			b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", AnonymousFlowID: "signup-flow-" + mode, ActorID: "signup-service", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, RecordID: "passkey-" + mode, PolicyID: "signup-policy", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "signup-correlation"}
			creation := b
			creation.OperationID, creation.UserID, creation.AnonymousFlowID, creation.RecordID, creation.SchemaID = "identity.user.create", identity.UserID("created-"+mode), "", "", "fields"
			p.intent = kernel.PasskeyRegistrationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Credential: identity.CredentialRef{ID: identity.CredentialID(b.RecordID), TenantID: b.TenantID, UserID: creation.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}}
			fields, err := kernel.PasskeyRegistrationFields(p.intent)
			if err != nil {
				t.Fatal(err)
			}
			p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.PasskeyRegistrationDigest(p.intent)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &signupFactorAudit{}, &signupFactorOutbox{fail: mode == "outbox-failure"}, p})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: "identity.passkey.create_credential", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "credential", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "credential", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			auditDigest, err := kernel.FeatureAuditBindingDigest(b, op, "credential", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "credential", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "identity.passkey.create_credential", AfterVersion: 1}, PasskeyRegistration: &kernel.PasskeyRegistrationPlan{UserID: creation.UserID, CredentialID: p.intent.Credential.ID, CreationDigest: digest, CreationEventIndex: 1}, Audits: []kernel.AuditPlan{{EventType: "identity.passkey.create_credential", SchemaVersion: 1, BindingDigest: auditDigest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}})
			if err != nil {
				t.Fatal("prepare", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, p.command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			result, applyErr := coordinator.ApplyFeature(ctx, work, p.command)
			if applyErr != nil {
				result, err = coordinator.Abort(work, applyErr)
			} else {
				result, err = coordinator.Commit(work, result)
			}
			success := mode == "commit"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("known-empty signup authority did not commit", err, applyErr)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("ineligible factor initialization committed")
			}
			var users, factorRows, knownEmpty, audits, events int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 AND version=1 AND active_factors=0 AND initialized_purpose='identity.passkey.register-verify'),(SELECT count(*) FROM signup_factor_audits WHERE command_id=$3 AND succeeded),(SELECT count(*) FROM signup_factor_events WHERE command_id=$3)`, string(b.TenantID), string(creation.UserID), string(id)).Scan(&users, &factorRows, &knownEmpty, &audits, &events); err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if users != want || factorRows != want || knownEmpty != want || audits != want || events != 2*want {
				t.Fatal("factor creation split from kernel/effects", users, factorRows, knownEmpty, audits, events)
			}
			if success {
				_, retry, err := coordinator.ReserveCommand(ctx, b, p.command, plan)
				if err != nil || retry.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("retry lost original initialization metadata", err)
				}
			}
			if (mode == "native-failure" || mode == "outbox-failure" || mode == "late-enrollment" || mode == "late-origin-change" || mode == "duplicate") && !p.initialized {
				t.Fatal("rollback control never reached actual initialization", applyErr)
			}
			if mode == "late-command-change" && !p.provenanceReplaced {
				t.Fatal("foreign provenance control did not replace a valid known-empty row", applyErr, err)
			}
		})
	}
}
