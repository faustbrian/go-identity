//go:build integration

package mfapostgres

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// The controlled feature supplies only an invocation seam. Factor authority is
// the real MFA owner/table, and Work comes from the genuine coordinator. This
// is not proof of WebAuthn authentication or a complete passkey consumer.
type passkeyFactorInvocation struct {
	op         identity.FeatureOperation
	descriptor kernel.ContributorDescriptor
	record     session.Session
	foreign    bool
	admitted   bool
	mfa        bool
}

func (p *passkeyFactorInvocation) Descriptor() kernel.ContributorDescriptor { return p.descriptor }
func (p *passkeyFactorInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*passkeyFactorInvocation) ValidateFeatureCommand(identity.Command, kernel.CommandPlan) error {
	return nil
}
func (*passkeyFactorInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, identity.UnavailableError{}
}
func (p *passkeyFactorInvocation) ApplyFeature(ctx context.Context, w kernel.Work, _ identity.Command) (identity.FeatureReceipt, error) {
	if _, err := w.Exec(ctx, `INSERT INTO passkey_factor_probe VALUES(1)`); err != nil {
		return identity.FeatureReceipt{}, err
	}
	owner := p
	if p.foreign {
		copy := *p
		owner = &copy
	}
	var err error
	if p.mfa {
		err = RequireMFAPasskeySessionFactors(ctx, w, owner, p.record)
	} else {
		err = RequirePasskeySessionFactors(ctx, w, owner, p.record)
	}
	p.admitted = err == nil
	// Always abort after the guard: this unit owns no protocol/session mutation.
	// The probe verifies earlier writes cannot survive the denied/aborted Work.
	if err == nil {
		err = identity.UnavailableError{}
	}
	return identity.FeatureReceipt{}, err
}

func TestPasskeySessionFactorAuthorityPostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_MFA_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test cluster required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("owned cluster unavailable")
	}
	defer admin.Close(context.Background())
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "passkey_factors_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup failed")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(kernel.MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
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
	if _, err = pool.Raw().Exec(ctx, authoritySQL+`CREATE TABLE passkey_factor_probe(value integer);
INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','user-a',1,0,decode(repeat('01',16),'hex'),'identity.password.signup')`); err != nil {
		t.Fatal(err)
	}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := identityoutbox.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("MFA-primary", func(t *testing.T) { testPasskeyMFAChallengeFactorAuthority(t, ctx, pool, repo) })
	t.Run("MFA-continuation-migration", func(t *testing.T) { testPasskeyContinuationMigrationPostgres(t, ctx, pool) })
	t.Run("MFA-continuation-recovery", func(t *testing.T) { testPasskeyContinuationRecoveryPostgres(t, ctx, pool) })
	// Selected guard tests may skip MFA-primary, which normally creates this
	// native table. Install it only when absent; never substitute a factor store.
	var factorTable *string
	if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity_mfa.totp_factors')::text`).Scan(&factorTable); err != nil {
		t.Fatal(err)
	}
	if factorTable == nil {
		if _, err := pool.Raw().Exec(ctx, totpFactorSQL); err != nil {
			t.Fatal(err)
		}
	}
	factorID, _ := identity.NewCommandID()
	rawFactorID := mustContinuationCommandBytes(string(factorID))
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a','identity.mfa.enable',decode(repeat('01',32),'hex'),1,decode('01','hex'))`, rawFactorID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a','identity.mfa.enable')`, rawFactorID); err != nil {
		t.Fatal(err)
	}
	modes := []string{"known-empty", "missing", "enrolled", "stale", "foreign-owner", "foreign-user", "foreign-tenant", "foreign-schema", "foreign-lifecycle", "foreign-record", "foreign-factor-key", "password-record", "revoke-target", "revoke-source", "update-options", "update-assertion", "update-options-lifecycle", "update-assertion-lifecycle", "update-assertion-version", "update-assertion-stale", "update-assertion-enrolled", "update-assertion-schema", "update-assertion-owner"}
	for _, stage := range []string{"MFA-update-options", "MFA-update-assertion", "MFA-enroll-assertion-options", "MFA-enroll-registration-options", "MFA-enroll-register"} {
		for _, suffix := range []string{"", "-stale", "-enrollment", "-pending", "-empty", "-blocked", "-foreign-factor", "-foreign-user", "-foreign-tenant", "-owner", "-descriptor", "-schema", "-lifecycle", "-version", "-ordinary", "-factor-key", "-otp", "-recovery-code", "-record", "-event-index"} {
			modes = append(modes, stage+suffix)
		}
	}
	for _, stage := range []string{"enroll-assertion-options", "enroll-registration-options", "enroll-register"} {
		for _, suffix := range []string{"", "-lifecycle", "-version", "-stale", "-enrolled", "-schema", "-owner"} {
			modes = append(modes, stage+suffix)
		}
	}
	for _, stage := range []string{"delete-options", "delete-assertion"} {
		for _, suffix := range []string{"", "-lifecycle", "-version", "-stale", "-enrolled", "-schema", "-owner", "-record"} {
			modes = append(modes, stage+suffix)
		}
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=1,active_factors=0`); err != nil {
				t.Fatal(err)
			}
			record := passkeyFactorSession(t)
			spec, _ := record.Bindings()
			commandID, _ := identity.NewCommandID()
			op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.signin-verify", SchemaID: "identity.passkey.signin-verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			descriptor := kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
			life := kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}
			b := identity.CommandBinding{CommandID: commandID, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, RecordID: spec.SessionID, PolicyID: "policy", PolicyVersion: 1, CorrelationID: "correlation"}
			completedMFA := strings.HasPrefix(mode, "MFA-")
			if completedMFA {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES('tenant-a','user-a',$1,2,1,1,'SHA1',6,30,0,'Example',decode('01','hex'),$2,'identity.mfa.enable',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '4 minutes',clock_timestamp())`, string(factorID), rawFactorID); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.totp_factors WHERE factor_id=$1`, string(factorID)); err != nil {
						t.Error(err)
					}
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active'; UPDATE identity_mfa.factor_authorities SET version=1,active_factors=0`); err != nil {
						t.Error(err)
					}
				}()
				record = completedPasskeyFactorSession(t, string(factorID))
				spec, _ = record.Bindings()
				op.OperationID, op.SchemaID = "identity.passkey.update", "identity.passkey.update.options-v1"
				life = kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}
				b.RecordID = "original-ceremony"
				if strings.HasPrefix(mode, "MFA-update-assertion") {
					op.SchemaID = "identity.passkey.update.assertion-v1"
					life = kernel.LifecyclePlan{EventType: "identity.passkey.rename_credential", BeforeVersion: 4, AfterVersion: 5}
					b.RecordID = "another-passkey"
				}
				if strings.HasPrefix(mode, "MFA-enroll-") {
					op.OperationID, op.SchemaID = "identity.passkey.register-options", "identity.passkey.register-options.session-assertion-options-v1"
					b.RecordID = string(commandID)
					if strings.HasPrefix(mode, "MFA-enroll-registration-options") {
						op.SchemaID, life.EventType = "identity.passkey.register-options.session-registration-options-v1", "passkey.registration.started.v1"
					} else if strings.HasPrefix(mode, "MFA-enroll-register") {
						op.OperationID, op.SchemaID, life.EventType = "identity.passkey.register-verify", "identity.passkey.register-verify.session-registration-v1", "identity.passkey.create_credential"
					}
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1; UPDATE identity.users SET status='active'; UPDATE identity_mfa.totp_factors SET state=2,confirmed_at=created_at,enrollment_version=1`); err != nil {
					t.Fatal(err)
				}
				switch {
				case strings.HasSuffix(mode, "-ordinary"):
					record = passkeyFactorSession(t)
				case strings.HasSuffix(mode, "-factor-key"), strings.HasSuffix(mode, "-otp"), strings.HasSuffix(mode, "-recovery-code"):
					projection, _ := record.Bindings()
					metadata, _ := record.MFAAuthentication().Bindings()
					if strings.HasSuffix(mode, "-factor-key") {
						vector, _ := projection.Authority.Bindings()
						vector.Factor.Binding.ScopeKey = "foreign-factor"
						projection.Authority, err = session.NewAuthoritySnapshot(vector)
					} else if strings.HasSuffix(mode, "-otp") {
						metadata.Method = "otp"
					} else {
						metadata.Method, metadata.RecoverySetID, metadata.RecoverySetVersion = "recovery-code", "BwcHBwcHBwcHBwcHBwcHBw", 1
					}
					if err != nil {
						t.Fatal(err)
					}
					factor, err := session.NewMFAAuthentication(metadata)
					if err != nil {
						t.Fatal(err)
					}
					record, err = session.NewSessionWithPasskeyMFA(projection, factor)
				case strings.HasSuffix(mode, "-descriptor"):
					descriptor.Version = 2
				case strings.HasSuffix(mode, "-stale"):
					_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2`)
				case strings.HasSuffix(mode, "-enrollment"):
					_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET enrollment_version=2`)
				case strings.HasSuffix(mode, "-pending"):
					_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET state=1,confirmed_at=NULL`)
				case strings.HasSuffix(mode, "-empty"):
					_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=0`)
				case strings.HasSuffix(mode, "-blocked"):
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned'`)
				case strings.HasSuffix(mode, "-foreign-factor"):
					other, _ := identity.NewCommandID()
					record = completedPasskeyFactorSession(t, string(other))
				case strings.HasSuffix(mode, "-foreign-user"):
					b.UserID, b.ActorID = "other-user", "other-user"
				case strings.HasSuffix(mode, "-foreign-tenant"):
					b.TenantID = "other-tenant"
				case strings.HasSuffix(mode, "-schema"):
					op.SchemaID = "identity.passkey.update.native-v1"
				case strings.HasSuffix(mode, "-lifecycle"):
					life.EventType = "session.created.v1"
				case strings.HasSuffix(mode, "-version"):
					life.BeforeVersion, life.AfterVersion = 1, 2
					if strings.HasPrefix(mode, "MFA-update-assertion") {
						life.BeforeVersion, life.AfterVersion = 0, 1
					}
				case strings.HasSuffix(mode, "-record"):
					if strings.HasPrefix(mode, "MFA-enroll-") {
						b.RecordID = "not-original-command"
					} else {
						b.UserID, b.ActorID = "other-user", "other-user"
					}
				case strings.HasSuffix(mode, "-event-index"):
					life.EventIndex = 1
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(mode, "update-options") {
				op.OperationID, op.SchemaID = "identity.passkey.update", "identity.passkey.update.options-v1"
				life = kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}
				b.RecordID = "original-ceremony"
			} else if strings.HasPrefix(mode, "update-assertion") {
				op.OperationID, op.SchemaID = "identity.passkey.update", "identity.passkey.update.assertion-v1"
				life = kernel.LifecyclePlan{EventType: "identity.passkey.rename_credential", BeforeVersion: 4, AfterVersion: 5}
				b.RecordID = "another-passkey"
			}
			enrollment := strings.HasPrefix(mode, "enroll-")
			if enrollment {
				op.OperationID = "identity.passkey.register-options"
				op.SchemaID = "identity.passkey.register-options.session-assertion-options-v1"
				life = kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}
				b.RecordID = string(commandID)
				if strings.HasPrefix(mode, "enroll-registration-options") {
					op.SchemaID = "identity.passkey.register-options.session-registration-options-v1"
					life.EventType = "passkey.registration.started.v1"
				}
				if strings.HasPrefix(mode, "enroll-register") {
					op.OperationID = "identity.passkey.register-verify"
					op.SchemaID = "identity.passkey.register-verify.session-registration-v1"
					life.EventType = "identity.passkey.create_credential"
					b.RecordID = "new-passkey"
				}
				switch {
				case strings.HasSuffix(mode, "-lifecycle"):
					life.EventType = "session.created.v1"
				case strings.HasSuffix(mode, "-version"):
					life.BeforeVersion, life.AfterVersion = 1, 2
				case strings.HasSuffix(mode, "-schema"):
					op.SchemaID = "identity.passkey.register-options.native-v1"
				case strings.HasSuffix(mode, "-stale"):
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2`); err != nil {
						t.Fatal(err)
					}
				case strings.HasSuffix(mode, "-enrolled"):
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1`); err != nil {
						t.Fatal(err)
					}
				}
			}
			deletion := strings.HasPrefix(mode, "delete-")
			if deletion {
				op.OperationID, op.SchemaID = "identity.passkey.delete", "identity.passkey.delete.options-v1"
				life = kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}
				b.RecordID = string(commandID)
				assertion := strings.HasPrefix(mode, "delete-assertion")
				if assertion {
					op.SchemaID = "identity.passkey.delete.assertion-v1"
					life = kernel.LifecyclePlan{EventType: "identity.passkey.remove_credential", BeforeVersion: 4, AfterVersion: 5}
					b.RecordID = "removed-passkey"
				}
				switch {
				case strings.HasSuffix(mode, "-lifecycle"):
					life.EventType = "identity.passkey.rename_credential"
				case strings.HasSuffix(mode, "-version"):
					life.BeforeVersion, life.AfterVersion = 1, 2
					if assertion {
						life.BeforeVersion, life.AfterVersion = 0, 1
					}
				case strings.HasSuffix(mode, "-schema"):
					op.SchemaID = "identity.passkey.delete.native-v1"
				case strings.HasSuffix(mode, "-stale"):
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2`); err != nil {
						t.Fatal(err)
					}
				case strings.HasSuffix(mode, "-enrolled"):
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1`); err != nil {
						t.Fatal(err)
					}
				case strings.HasSuffix(mode, "-record"):
					if assertion {
						b.UserID, b.ActorID = "other-user", "other-user"
					} else {
						b.RecordID = "not-original-command"
					}
				}
			}
			switch mode {
			case "missing":
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','user-a',1,0,decode(repeat('01',16),'hex'),'identity.password.signup')`); err != nil {
						t.Error(err)
					}
				}()
			case "enrolled":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1`); err != nil {
					t.Fatal(err)
				}
			case "stale":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2`); err != nil {
					t.Fatal(err)
				}
			case "foreign-user":
				b.UserID = "other-user"
				b.ActorID = "other-user"
			case "foreign-tenant":
				b.TenantID = "other-tenant"
			case "foreign-schema":
				op.SchemaID = "other-schema"
			case "foreign-lifecycle":
				life.EventType = "passkey.updated.v1"
			case "foreign-record":
				b.RecordID = "other-session"
			case "foreign-factor-key":
				v, _ := spec.Authority.Bindings()
				v.Factor.Binding.ScopeKey = "other-factor"
				spec.Authority, err = session.NewAuthoritySnapshot(v)
				if err != nil {
					t.Fatal(err)
				}
				record, err = session.NewSession(spec)
				if err != nil {
					t.Fatal(err)
				}
			case "password-record":
				spec.Authentication.Proof.Method = "password"
				spec.Authentication.Proof.Assurance = 1
				record, err = session.NewSession(spec)
				if err != nil {
					t.Fatal(err)
				}
			case "revoke-target", "revoke-source":
				op = session.RevokeOneOperation()
				descriptor = kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}
				life = kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: 1, AfterVersion: 2}
				if mode == "revoke-source" {
					b.RecordID = "sibling-target"
				}
			case "update-options-lifecycle", "update-assertion-lifecycle":
				life.EventType = "session.created.v1"
			case "update-assertion-version":
				life.BeforeVersion, life.AfterVersion = 0, 1
			case "update-assertion-stale":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2`); err != nil {
					t.Fatal(err)
				}
			case "update-assertion-enrolled":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1`); err != nil {
					t.Fatal(err)
				}
			case "update-assertion-schema":
				op.SchemaID = "identity.passkey.update.native-v1"
			}
			readErr := ReadPasskeySessionFactors(ctx, pool, record, time.Second)
			readDenies := completedMFA || mode == "missing" || mode == "enrolled" || mode == "stale" || mode == "foreign-factor-key" || mode == "password-record" || mode == "update-assertion-stale" || mode == "update-assertion-enrolled" || (enrollment || deletion) && (strings.HasSuffix(mode, "-stale") || strings.HasSuffix(mode, "-enrolled"))
			if (readErr != nil) != readDenies {
				t.Fatal("original primary factor read", readErr)
			}
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "factor-test", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: mode}}}})
			if err != nil {
				t.Fatal(err)
			}
			feature := &passkeyFactorInvocation{op: op, descriptor: descriptor, record: record, mfa: completedMFA, foreign: mode == "foreign-owner" || mode == "update-assertion-owner" || (enrollment || deletion || completedMFA) && strings.HasSuffix(mode, "-owner")}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, auditing, lifecycle, feature})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, e := builder.Build(audit.RecordInput{OccurredAt: spec.IssuedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
			if e != nil {
				t.Fatal(e)
			}
			digest, e := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
			if e != nil {
				t.Fatal(e)
			}
			declaration := kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: descriptor, Operation: op}, Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			plan, err := coordinator.PrepareCommandPlan(b, command, declaration)
			if err != nil {
				t.Fatal("prepare", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal("reserve", err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal("begin", err)
			}
			_, applyErr := coordinator.ApplyFeature(ctx, work, command)
			if applyErr == nil {
				t.Fatal("test seam must abort after guard")
			}
			result, _ := coordinator.Abort(work, applyErr)
			want := mode == "MFA-update-options" || mode == "MFA-update-assertion" || mode == "MFA-enroll-assertion-options" || mode == "MFA-enroll-registration-options" || mode == "MFA-enroll-register" || mode == "known-empty" || mode == "revoke-target" || mode == "revoke-source" || mode == "update-options" || mode == "update-assertion" || mode == "enroll-assertion-options" || mode == "enroll-registration-options" || mode == "enroll-register" || mode == "delete-options" || mode == "delete-assertion"
			if feature.admitted != want {
				t.Fatalf("factor guard admitted=%v want=%v", feature.admitted, want)
			}
			if result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("aborted guard committed")
			}
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM passkey_factor_probe`).Scan(&count); err != nil || count != 0 {
				t.Fatal("provisional write survived aborted Work", count, err)
			}
		})
	}
}
