//go:build integration

package mfapostgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// This fixture stops after real preparation admission. It observes the MFA
// contract without pretending to issue SSO state or perform the kernel's
// mandatory account-link effect. Native SSO journeys own final-effect proof.
type ssoOIDCExplicitLinkFactorInvocation struct {
	ssoOIDCSigninFactorInvocation
	descriptor                kernel.ContributorDescriptor
	entered, admitted, locked bool
}

func (p *ssoOIDCExplicitLinkFactorInvocation) Descriptor() kernel.ContributorDescriptor {
	return p.descriptor
}

func (p *ssoOIDCExplicitLinkFactorInvocation) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command != p.original || plan.Feature == nil || plan.Feature.Operation != p.op || plan.Feature.Contributor != p.descriptor {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *ssoOIDCExplicitLinkFactorInvocation) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(command, plan)
}

func (p *ssoOIDCExplicitLinkFactorInvocation) ValidateSSOOIDCExplicitLinkConsumption(command identity.Command, proof kernel.CapabilityPlan) error {
	return p.ValidateSSOOIDCSigninConsumption(command, proof)
}

func (p *ssoOIDCExplicitLinkFactorInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.entered, p.retained = true, w
	var owner kernel.FeatureExecutionContributor = p
	version := p.expectedVersion
	if p.mode == "foreign-owner" {
		copy := *p
		owner = &copy
	}
	if p.mode == "zero-version" {
		version = 0
	}
	if p.mode == "changed-binding" {
		spec, _ := command.Feature()
		spec.Binding.RecordID = "other-flow"
		token, _ := command.SessionToken()
		var err error
		command, err = identity.NewFeatureSessionCommand(spec, token)
		if err != nil {
			return err
		}
	}
	state, err := RequireSSOOIDCExplicitLinkFactors(ctx, w, owner, command, version)
	if err != nil {
		return err
	}
	if state.Version() != p.expectedVersion || state.RequireEmailRecovery("tenant-a", "user-a") != nil {
		return identity.ForbiddenError{}
	}
	p.admitted = true
	other, err := p.pool.Raw().Begin(ctx)
	if err != nil {
		return err
	}
	_, lockErr := other.Exec(ctx, `SELECT version FROM identity_mfa.factor_authorities WHERE tenant_id='tenant-a' AND user_id='user-a' FOR UPDATE NOWAIT`)
	_ = other.Rollback(ctx)
	var locked *pgconn.PgError
	p.locked = errors.As(lockErr, &locked) && locked.Code == "55P03"
	// End this factor-only observation before generation or any domain effect.
	return identity.ForbiddenError{}
}

func TestSSOOIDCExplicitLinkFactorsPreparationPostgres(t *testing.T) {
	ctx, pool, repository := newOAuthSigninFactorStore(t)
	accounts := kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	preparation := kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: accounts, Version: 13}, Version: 14}
	counter := kernel.CounterPreparationMigrationSource{Base: preparation, Version: 15}
	start := kernel.SSOOIDCPreparationErasureMigrationSource{Base: counter, Version: 16}
	history, err := (kernel.SSOOIDCCallbackPreparationErasureMigrationSource{Base: start, Version: 17}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if step.Version() > 14 {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("native enterprise journal history", err)
			}
		}
	}
	migrations := capabilitypg.Migrations()
	entries, err := fs.ReadDir(migrations, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		contents, err := fs.ReadFile(migrations, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
			t.Fatal("capability history", err)
		}
	}
	for _, callback := range []bool{false, true} {
		profile := "start"
		if callback {
			profile = "callback"
		}
		t.Run(profile, func(t *testing.T) {
			for _, mode := range []string{"current", "missing", "enrolled", "advanced", "foreign-owner", "zero-version", "changed-binding"} {
				t.Run(mode, func(t *testing.T) {
					resetOAuthSessionFactors(t, ctx, pool, "current")
					observed, err := ReadSSOOIDCExplicitLinkFactors(ctx, pool, "tenant-a", "user-a", time.Second)
					if err != nil || observed.Version() != 1 {
						t.Fatal("original known-empty observation", err)
					}
					resetOAuthSessionFactors(t, ctx, pool, mode)
					state, readErr := ReadSSOOIDCExplicitLinkFactors(ctx, pool, "tenant-a", "user-a", time.Second)
					if mode == "missing" || mode == "enrolled" {
						if readErr == nil || state.Version() != 0 {
							t.Fatal("missing or enrolled primary admitted")
						}
					} else if readErr != nil || mode == "advanced" && state.Version() != 2 {
						t.Fatal("primary did not preserve actual generation", readErr)
					}
					spec, registration, life := ssoOIDCExplicitLinkFactorFixture(t, callback)
					command := ssoOIDCExplicitLinkFactorCommand(t, spec)
					owner := &ssoOIDCExplicitLinkFactorInvocation{ssoOIDCSigninFactorInvocation: ssoOIDCSigninFactorInvocation{op: spec.Operation, pool: pool, original: command, mode: mode, expectedVersion: observed.Version()}, descriptor: registration.Contributor}
					contributors := []kernel.Contributor{repository, &signupFactorAudit{}, &signupFactorOutbox{}, owner}
					if callback {
						contributors = append(contributors, capabilitypg.NewParticipant())
					}
					registry, err := kernel.NewContributorRegistry(contributors)
					if err != nil {
						t.Fatal(err)
					}
					coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
					if err != nil {
						t.Fatal(err)
					}
					binding := spec.Binding
					action, retention := spec.Operation.OperationID, "protected"
					if callback {
						action, retention = "identity.account.link", "standard"
					}
					builder, err := audit.NewBuilder(audit.BuilderConfig{})
					if err != nil {
						t.Fatal(err)
					}
					seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "sso_login_transaction", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": "sso_login_transaction", "aggregate.id": binding.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": retention}})
					if err != nil {
						t.Fatal(err)
					}
					digest, err := kernel.FeatureAuditBindingDigest(binding, spec.Operation, "sso_login_transaction", seed)
					if err != nil {
						t.Fatal(err)
					}
					owner.declaration = kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "sso_login_transaction", Feature: &registration, Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, BindingDigest: digest, RetentionClass: retention, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
					if callback {
						proof := kernel.CapabilityPlan{CapabilityID: string(binding.CommandID), Purpose: "identity.sso.oidc-callback", ReplayKeyVersion: 1, ReplayDigest: sha256.Sum256([]byte(binding.CommandID)), ProofFingerprint: [32]byte{9}, ExpiresAt: time.Now().UTC().Add(time.Minute).Truncate(time.Second), MaxUses: 1}
						owner.declaration.Capability = &proof
						if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, string(binding.TenantID), string(proof.Purpose), proof.ReplayKeyVersion, proof.ReplayDigest[:], proof.CapabilityID, proof.ProofFingerprint[:], proof.ExpiresAt, proof.MaxUses); err != nil {
							t.Fatal(err)
						}
					}
					plan, err := coordinator.PrepareFeaturePreparationPlan(command, owner.declaration)
					if err != nil {
						t.Fatal("prepare original member scope", err)
					}
					result, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
					if err == nil || result.Outcome == identity.CommitOutcomeCommitted || !owner.entered {
						t.Fatal("factor-only admission did not stop before effects", result.Outcome, owner.entered, err)
					}
					if mode == "current" {
						if !owner.admitted || !owner.locked || !errors.Is(err, identity.ForbiddenError{}) {
							t.Fatal("known-empty original generation was not locked during admission", owner.admitted, owner.locked, err)
						}
					} else if owner.admitted {
						t.Fatal("foreign, missing, enrolled or stale factor authority admitted")
					}
					if _, err := RequireSSOOIDCExplicitLinkFactors(ctx, owner.retained, owner, command, observed.Version()); err == nil {
						t.Fatal("returned admission Work retained member-link authority")
					}
				})
			}
		})
	}
}
