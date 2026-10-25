//go:build integration

package mfapostgres

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	outbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This controlled owner tests only the stored-factor/Work guard. It supplies no
// WebAuthn verification, usable factor secret, continuation or session.
type passkeyChallengeFactorInvocation struct {
	op                identity.FeatureOperation
	foreign, admitted bool
	version           uint64
}

func (*passkeyChallengeFactorInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (p *passkeyChallengeFactorInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*passkeyChallengeFactorInvocation) ValidateFeatureCommand(identity.Command, kernel.CommandPlan) error {
	return nil
}
func (*passkeyChallengeFactorInvocation) CheckFeatureCommit(context.Context, kernel.Work, identity.Command) error {
	return identity.UnavailableError{}
}
func (*passkeyChallengeFactorInvocation) ValidatePasskeyMFAChallenge(identity.Command, kernel.MFAContinuationPlan) error {
	return identity.UnavailableError{}
}
func (*passkeyChallengeFactorInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, identity.UnavailableError{}
}
func (p *passkeyChallengeFactorInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if _, err := w.Exec(ctx, `INSERT INTO passkey_factor_probe VALUES(1)`); err != nil {
		return identity.FeatureReceipt{}, err
	}
	owner := p
	if p.foreign {
		copy := *p
		owner = &copy
	}
	err := RequirePasskeySigninFactors(ctx, w, owner, command, "user-a", p.version)
	p.admitted = err == nil
	if err == nil {
		err = identity.UnavailableError{}
	}
	return identity.FeatureReceipt{}, err
}

func testPasskeyMFAChallengeFactorAuthority(t *testing.T, ctx context.Context, pool *database.Pool, repo *kernel.Repository) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, totpFactorSQL); err != nil {
		t.Fatal(err)
	}
	factorID, _ := identity.NewCommandID()
	raw := mustContinuationCommandBytes(string(factorID))
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a','identity.mfa.enable',decode(repeat('01',32),'hex'),1,decode('01','hex'));`, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a','identity.mfa.enable')`, raw); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES('tenant-a','user-a',$1,2,1,1,'SHA1',6,30,0,'Example',decode('01','hex'),$2,'identity.mfa.enable',$3,$4,$3)`, string(factorID), raw, now, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.totp_factors WHERE tenant_id='tenant-a' AND factor_id=$1`, string(factorID)); err != nil {
			t.Error(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=1,active_factors=0`); err != nil {
			t.Error(err)
		}
	}()
	for _, mode := range []string{"confirmed", "empty", "zero-version", "stale", "pending", "foreign-stored-user", "foreign-stored-tenant", "foreign-owner", "foreign-schema", "foreign-record", "foreign-lifecycle"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=1,active_factors=1; UPDATE identity_mfa.totp_factors SET state=2,confirmed_at=created_at`); err != nil {
				t.Fatal(err)
			}
			version := uint64(1)
			switch mode {
			case "empty":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=0`); err != nil {
					t.Fatal(err)
				}
			case "zero-version":
				version = 0
			case "stale":
				version = 2
			case "pending":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET state=1,confirmed_at=NULL`); err != nil {
					t.Fatal(err)
				}
			case "foreign-stored-user", "foreign-stored-tenant":
				// The selected subject still has positive authority, but no eligible
				// own TOTP. Only the unrelated subject has confirmed custody.
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET state=1,confirmed_at=NULL`); err != nil {
					t.Fatal(err)
				}
				tenant, user := "tenant-a", "user-b"
				if mode == "foreign-stored-tenant" {
					tenant, user = "tenant-b", "user-a"
				}
				seedForeignPasskeyChallengeFactor(t, ctx, pool, tenant, user, now)
			}
			id, _ := identity.NewCommandID()
			op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.signin-verify", SchemaID: "identity.passkey.signin-verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			if mode == "foreign-schema" {
				op.SchemaID = "identity.passkey.signin-verify.another"
			}
			b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: "correlation", RecordID: string(id)}
			if mode == "foreign-record" {
				b.RecordID = "another-record"
			}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op})
			if err != nil {
				t.Fatal(err)
			}
			owner := &passkeyChallengeFactorInvocation{op: op, version: version, foreign: mode == "foreign-owner"}
			auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
			if err != nil {
				t.Fatal(err)
			}
			lifecycle, err := outbox.NewContributor()
			if err != nil {
				t.Fatal(err)
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, auditing, lifecycle, owner})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			life := kernel.LifecyclePlan{EventType: "mfa.challenge.created.v1", AfterVersion: 1}
			if mode == "foreign-lifecycle" {
				life.EventType = "session.created.v1"
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "authentication_attempt", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, op, "authentication_attempt", seed)
			if err != nil {
				t.Fatal(err)
			}
			declaration := kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "authentication_attempt", Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			plan, err := coordinator.PrepareCommandPlan(b, command, declaration)
			if err != nil {
				t.Fatal("prepare", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			_, applyErr := coordinator.ApplyFeature(ctx, work, command)
			if applyErr == nil {
				t.Fatal("guard test must abort")
			}
			_, _ = coordinator.Abort(work, applyErr)
			if owner.admitted != (mode == "confirmed") {
				t.Fatalf("guard admitted=%v mode=%s", owner.admitted, mode)
			}
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM passkey_factor_probe`).Scan(&count); err != nil || count != 0 {
				t.Fatal("probe survived abort", err)
			}
		})
	}
}

// Declared prior stored state only. No fixture byte is presented as a usable
// TOTP secret or as proof that a real enrollment/authentication took place.
func seedForeignPasskeyChallengeFactor(t *testing.T, ctx context.Context, pool *database.Pool, tenant, user string, now time.Time) {
	t.Helper()
	signup, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []struct {
		id      identity.CommandID
		purpose string
	}{{signup, "identity.password.signup"}, {enrollment, "identity.mfa.enable"}} {
		raw := mustContinuationCommandBytes(string(command.id))
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,decode(repeat('01',32),'hex'),1,decode('01','hex'))`, raw, tenant, command.purpose); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, raw, tenant, command.purpose); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, tenant, user); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities VALUES($1,$2,1,1,$3,'identity.password.signup')`, tenant, user, mustContinuationCommandBytes(string(signup))); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES($1,$2,$3,2,1,1,'SHA1',6,30,0,'Example',decode('01','hex'),$4,'identity.mfa.enable',$5,$6,$5)`, tenant, user, string(enrollment), mustContinuationCommandBytes(string(enrollment)), now, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2`, tenant, string(enrollment)); err != nil {
			t.Error(err)
		}
	})
}
