//go:build integration

package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// This controlled native owner supplies fixed preparation output and external
// admission, not OIDC verification or session issuance. The actual coordinator,
// account and MFA rows, and capability participant own the tested transaction.
type ssoOIDCSigninFactorInvocation struct {
	op                                   identity.FeatureOperation
	pool                                 *database.Pool
	original                             identity.Command
	declaration                          kernel.CommandPlan
	expectedVersion                      uint64
	mode                                 string
	applied, finalEntered, final, locked bool
	retained                             kernel.Work
}

func (*ssoOIDCSigninFactorInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-callback", Version: 1}
}

func (p *ssoOIDCSigninFactorInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}

func (p *ssoOIDCSigninFactorInvocation) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command != p.original || plan.Feature == nil || plan.Feature.Operation != p.op || plan.Feature.Contributor != p.Descriptor() || plan.Capability == nil || p.declaration.Capability == nil || *plan.Capability != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	return nil
}

func (*ssoOIDCSigninFactorInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func (p *ssoOIDCSigninFactorInvocation) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(command, plan)
}

func (p *ssoOIDCSigninFactorInvocation) ValidateSSOOIDCSigninConsumption(command identity.Command, proof kernel.CapabilityPlan) error {
	if command != p.original || p.declaration.Capability == nil || proof != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *ssoOIDCSigninFactorInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	spec, ok := command.Feature()
	binding, feature, _, err := w.FeatureScope(p)
	if err != nil || !ok || command != p.original || binding != spec.Binding || feature.Operation != p.op {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *ssoOIDCSigninFactorInvocation) GenerateFeaturePreparation(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	if err := p.ValidateFeaturePreparation(command, p.declaration); err != nil {
		return nil, err
	}
	return (oauthSigninFactorAdmission{}).Generate(ctx, generation)
}

func (p *ssoOIDCSigninFactorInvocation) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if ctx.Err() != nil || command != p.original || generation == 0 || len(wire) != 8 || binary.BigEndian.Uint64(wire) != generation {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	return command, p.declaration, nil
}

func (p *ssoOIDCSigninFactorInvocation) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeaturePreparation(command, p.declaration); err != nil {
		return nil, err
	}
	return oauthSigninFactorAdmission{}, ctx.Err()
}

func (p *ssoOIDCSigninFactorInvocation) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, command, generation, wire); err != nil {
		return nil, err
	}
	return oauthSigninFactorAdmission{}, nil
}

func (p *ssoOIDCSigninFactorInvocation) check(ctx context.Context, w kernel.Work, command identity.Command) error {
	if command != p.original {
		return identity.ForbiddenError{}
	}
	owner := p
	version := p.expectedVersion
	if p.mode == "foreign-owner" {
		copy := *p
		owner = &copy
	}
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
	state, err := RequireSSOOIDCSigninFactors(ctx, w, owner, command, version)
	if err == nil && (state.Version() != p.expectedVersion || state.RequireEmailRecovery("tenant-a", "user-a") != nil) {
		return identity.ForbiddenError{}
	}
	return err
}

func (p *ssoOIDCSigninFactorInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.retained = w
	consumed, err := w.SSOOIDCSigninConsumption(p)
	spec, ok := command.Feature()
	if err != nil || !ok || command != p.original || consumed.Command != spec.Binding || consumed.Plan != *p.declaration.Capability || consumed.Generation == 0 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if _, err := w.Exec(ctx, `INSERT INTO oauth_signin_factor_probe VALUES($1)`, string(spec.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.check(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	other, err := p.pool.Raw().Begin(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	_, lockErr := other.Exec(ctx, `SELECT version FROM identity_mfa.factor_authorities WHERE tenant_id='tenant-a' AND user_id='user-a' FOR UPDATE NOWAIT`)
	_ = other.Rollback(ctx)
	var locked *pgconn.PgError
	p.locked = errors.As(lockErr, &locked) && locked.Code == "55P03"
	if !p.locked {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if p.mode == "late-enrolled" || p.mode == "late-epoch" {
		active := 0
		if p.mode == "late-enrolled" {
			active = 1
		}
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=$1 WHERE tenant_id='tenant-a' AND user_id='user-a'`, active); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.op, BeforeVersion: 1, AfterVersion: 2}, nil
}

func (p *ssoOIDCSigninFactorInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.finalEntered = true
	if err := p.check(ctx, w, command); err != nil {
		return err
	}
	p.final = true
	return nil
}

func TestRequireSSOOIDCSigninFactorsPreparedPostgres(t *testing.T) {
	ctx, pool, repository := newOAuthSigninFactorStore(t)
	accounts := kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	preparation := kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: accounts, Version: 13}, Version: 14}
	history, err := (kernel.CounterPreparationMigrationSource{Base: preparation, Version: 15}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("native retained callback declaration", err)
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
			t.Fatal("real capability participant history", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET owner='sso' WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
		t.Fatal(err)
	}
	account, err := repository.GetSSOOIDCSigninAccount(ctx, kernel.ProviderSigninAccountQuery{TenantID: "tenant-a", Provider: "oidc", Issuer: "https://issuer.example", Subject: "opaque-subject"})
	if err != nil {
		t.Fatal("real SSO-owned callback account", err)
	}
	fields, err := kernel.SSOOIDCSigninAccountFields(account)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"current", "missing", "enrolled", "stale", "foreign-owner", "zero-version", "reconstructed-command", "late-enrolled", "late-epoch"} {
		t.Run(mode, func(t *testing.T) {
			resetOAuthSessionFactors(t, ctx, pool, "current")
			observed, err := ReadSSOOIDCSigninFactors(ctx, pool, "tenant-a", "user-a", time.Second)
			if err != nil || observed.Version() != 1 {
				t.Fatal("original factor observation", err)
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
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			start, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			op := identity.FeatureOperation{Owner: "sso/oidc", OperationID: "identity.sso.oidc-callback", SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			binding := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", ActorID: "native-sso-service", ActorKind: authorization.SubjectServiceAccount, AnonymousFlowID: "original-enterprise-flow", RecordID: string(start), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "enterprise-signin", PolicyVersion: 1, CorrelationID: string(id)}
			command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			owner := &ssoOIDCSigninFactorInvocation{op: op, pool: pool, original: command, mode: mode, expectedVersion: observed.Version()}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repository, &signupFactorAudit{}, &signupFactorOutbox{}, owner, capabilitypg.NewParticipant()})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: "identity.sso.login", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "sso_login_transaction", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "sso_login_transaction", "aggregate.id": binding.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(binding, op, "sso_login_transaction", seed)
			if err != nil {
				t.Fatal(err)
			}
			proof := kernel.CapabilityPlan{CapabilityID: string(id), Purpose: "identity.sso.oidc-callback", ReplayKeyVersion: 1, ReplayDigest: sha256.Sum256([]byte(id)), ProofFingerprint: [32]byte{9}, ExpiresAt: time.Now().UTC().Add(time.Minute).Truncate(time.Second), MaxUses: 1}
			// This is fixture issuance metadata, not proof verification. Real
			// capability storage owns every reservation/consumption transition.
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, string(binding.TenantID), string(proof.Purpose), proof.ReplayKeyVersion, proof.ReplayDigest[:], proof.CapabilityID, proof.ProofFingerprint[:], proof.ExpiresAt, proof.MaxUses); err != nil {
				t.Fatal(err)
			}
			owner.declaration = kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "sso_login_transaction", Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, Capability: &proof, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2}, Audits: []kernel.AuditPlan{{EventType: "identity.sso.login", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			plan, err := coordinator.PrepareFeaturePreparationPlan(command, owner.declaration)
			if err != nil {
				t.Fatal("prepare original enterprise callback", err)
			}
			result, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
			if owner.retained == (kernel.Work{}) {
				t.Fatal("callback did not reach native Apply after capability consumption", result.Outcome, err)
			}
			success := mode == "current"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || !owner.applied || !owner.final || !owner.locked) {
				t.Fatal("known-empty original callback failed", result.Outcome, owner.applied, owner.finalEntered, owner.final, owner.locked, err)
			}
			if !success && (err == nil || result.Outcome != identity.CommitOutcomeNotCommitted || owner.final) {
				t.Fatal("denied callback did not establish rollback", result.Outcome, owner.applied, owner.finalEntered, owner.final, err)
			}
			if (mode == "late-enrolled" || mode == "late-epoch") && (!owner.applied || !owner.finalEntered) {
				t.Fatal("late change did not reach exact final callback check", err)
			}
			if _, err := RequireSSOOIDCSigninFactors(ctx, owner.retained, owner, command, observed.Version()); err == nil {
				t.Fatal("returned Work retained enterprise callback authority")
			}
			var effects, uses int
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT state,uses,(SELECT count(*) FROM oauth_signin_factor_probe WHERE command_id=$1) FROM public.capability_identity_one_use WHERE capability_id=$1`, string(id)).Scan(&state, &uses, &effects); err != nil {
				t.Fatal(err)
			}
			wantState, wantEffects := "released", 0
			if success {
				wantState, wantEffects = "finalized", 1
			}
			if state != wantState || uses != wantEffects || effects != wantEffects {
				t.Fatal("MFA denial leaked capability use or provisional effects", state, uses, effects)
			}
			if mode == "late-enrolled" || mode == "late-epoch" {
				var version, active int
				if err := pool.Raw().QueryRow(ctx, `SELECT version,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id='tenant-a' AND user_id='user-a'`).Scan(&version, &active); err != nil || version != 1 || active != 0 {
					t.Fatal("late factor mutation escaped rollback", version, active, err)
				}
			}
		})
	}
}
