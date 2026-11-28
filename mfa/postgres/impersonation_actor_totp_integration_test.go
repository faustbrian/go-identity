//go:build integration

package mfapostgres

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// This controlled owner exercises real MFA rows in the original coordinator
// invocation. It does not authenticate an administrator, approve a grant or
// create an impersonation session.
type impersonationActorFactorInvocation struct {
	op         identity.FeatureOperation
	descriptor kernel.ContributorDescriptor
	actor      identity.UserID
	factorID   string
	mode       string
	original   identity.Command
	retained   kernel.Work
	command    identity.Command
	denied     error
	applied    bool
	final      bool
}

func (p *impersonationActorFactorInvocation) Descriptor() kernel.ContributorDescriptor {
	return p.descriptor
}

func (p *impersonationActorFactorInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}

func (*impersonationActorFactorInvocation) ValidateFeatureCommand(identity.Command, kernel.CommandPlan) error {
	return nil
}

func (*impersonationActorFactorInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func (p *impersonationActorFactorInvocation) check(ctx context.Context, w kernel.Work) error {
	owner := p
	if p.mode == "foreign-invocation" {
		copy := *p
		owner = &copy
	}
	err := RequireImpersonationActorTOTPSessionFactor(ctx, w, owner, p.actor, p.factorID, TOTPSessionFactorState{EnrollmentVersion: 1, AuthorityVersion: 1})
	if err != nil {
		p.denied = err
	}
	return err
}

func (p *impersonationActorFactorInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.retained, p.command = w, command
	if command != p.original {
		return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "original_command"}
	}
	f, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO oauth_signin_factor_probe VALUES($1)`, string(f.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.check(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	if p.mode == "late-withdrawn" {
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.totp_factors SET state=3,encrypted_secret=NULL,last_step=NULL WHERE tenant_id='tenant-a' AND user_id='actor-admin'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	_, _, declared, err := w.FeatureScope(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: p.op, BeforeVersion: declared.BeforeVersion, AfterVersion: declared.AfterVersion}, nil
}

func (p *impersonationActorFactorInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, _ identity.Command) error {
	if err := p.check(ctx, w); err != nil {
		return err
	}
	p.final = true
	return nil
}

func TestRequireImpersonationActorTOTPSessionFactorPostgres(t *testing.T) {
	ctx, pool, repository := newOAuthSigninFactorStore(t)
	if _, err := pool.Raw().Exec(ctx, totpFactorSQL); err != nil {
		t.Fatal("native TOTP schema", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	// The shared seed helper also uses this context in its cleanup. A bounded
	// fixture lifetime keeps it usable after testing cancels t.Context().
	seedContext, cancelSeed := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancelSeed)
	seedForeignPasskeyChallengeFactor(t, seedContext, pool, "tenant-a", "actor-admin", now)
	seedForeignPasskeyChallengeFactor(t, seedContext, pool, "tenant-a", "target-user", now)
	var actorFactor, targetFactor string
	if err := pool.Raw().QueryRow(ctx, `SELECT factor_id FROM identity_mfa.totp_factors WHERE tenant_id='tenant-a' AND user_id='actor-admin'`).Scan(&actorFactor); err != nil {
		t.Fatal(err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT factor_id FROM identity_mfa.totp_factors WHERE tenant_id='tenant-a' AND user_id='target-user'`).Scan(&targetFactor); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name, schema string
		before       uint64
	}{{"request", "impersonation-request", 0}, {"approve", "impersonation-approve", 1}, {"start", "impersonation-start", 2}} {
		t.Run(operation.name, func(t *testing.T) {
			for _, mode := range []string{"current-actor", "target-substitution", "target-factor", "foreign-invocation", "foreign-schema", "foreign-contributor", "stale-authority", "stale-enrollment", "withdrawn", "late-withdrawn"} {
				t.Run(mode, func(t *testing.T) {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=1,active_factors=1;
UPDATE identity_mfa.totp_factors SET state=2,enrollment_version=1,encrypted_secret=decode('01','hex'),confirmed_at=created_at`); err != nil {
						t.Fatal(err)
					}
					op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: "identity.impersonation." + operation.name, SchemaID: operation.schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential}
					owner := &impersonationActorFactorInvocation{op: op, descriptor: kernel.ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}, actor: "actor-admin", factorID: actorFactor, mode: mode}
					var mutation string
					switch mode {
					case "target-substitution":
						owner.actor, owner.factorID = "target-user", targetFactor
					case "target-factor":
						owner.factorID = targetFactor
					case "foreign-schema":
						op.SchemaID = "foreign-impersonation"
						owner.op = op
					case "foreign-contributor":
						owner.descriptor.Version = 2
					case "stale-authority":
						mutation = `UPDATE identity_mfa.factor_authorities SET version=2 WHERE user_id='actor-admin'`
					case "stale-enrollment":
						mutation = `UPDATE identity_mfa.totp_factors SET enrollment_version=2 WHERE user_id='actor-admin'`
					case "withdrawn":
						mutation = `UPDATE identity_mfa.totp_factors SET state=3,encrypted_secret=NULL,last_step=NULL WHERE user_id='actor-admin'`
					}
					if mutation != "" {
						if _, err := pool.Raw().Exec(ctx, mutation); err != nil {
							t.Fatal(err)
						}
					}
					id, err := identity.NewCommandID()
					if err != nil {
						t.Fatal(err)
					}
					grantID, err := identity.NewCommandID()
					if err != nil {
						t.Fatal(err)
					}
					binding := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "target-user", ActorID: "actor-admin", ActorKind: authorization.SubjectUser, RecordID: string(grantID), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "impersonation-admin", PolicyVersion: 1, CorrelationID: string(id)}
					command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op})
					if err != nil {
						t.Fatal(err)
					}
					owner.original = command
					registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repository, &signupFactorAudit{}, &signupFactorOutbox{}, owner})
					if err != nil {
						t.Fatal(err)
					}
					coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
					if err != nil {
						t.Fatal(err)
					}
					life := kernel.LifecyclePlan{EventType: "impersonation." + operation.name + ".v1", BeforeVersion: operation.before, AfterVersion: operation.before + 1}
					builder, err := audit.NewBuilder(audit.BuilderConfig{})
					if err != nil {
						t.Fatal(err)
					}
					seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "impersonation", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "impersonation", "aggregate.id": binding.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
					if err != nil {
						t.Fatal(err)
					}
					digest, err := kernel.FeatureAuditBindingDigest(binding, op, "impersonation", seed)
					if err != nil {
						t.Fatal(err)
					}
					declaration := kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "impersonation", Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
					plan, err := coordinator.PrepareCommandPlan(binding, command, declaration)
					if err != nil {
						t.Fatal("prepare original actor/target Work", err)
					}
					reservation, _, err := coordinator.ReserveCommand(ctx, binding, command, plan)
					if err != nil {
						t.Fatal(err)
					}
					work, err := coordinator.Begin(ctx, reservation)
					if err != nil {
						t.Fatal(err)
					}
					defer coordinator.Abort(work, identity.UnavailableError{})
					result, applyErr := coordinator.ApplyFeature(ctx, work, command)
					if applyErr != nil {
						result, err = coordinator.Abort(work, applyErr)
					} else {
						result, err = coordinator.Commit(work, result)
					}
					if owner.command != command {
						t.Fatal("test did not enter the original invocation", applyErr, err)
					}
					success := mode == "current-actor"
					if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || !owner.applied || !owner.final) {
						t.Fatal("current actor factor denied with a distinct target", result.Outcome, applyErr, err)
					}
					if !success {
						var invalid identity.InvalidInputError
						if result.Outcome == identity.CommitOutcomeCommitted || owner.final || !errors.Is(owner.denied, identity.ForbiddenError{}) && !errors.As(owner.denied, &invalid) {
							t.Fatal("foreign or lost actor authority was not denied", result.Outcome, owner.denied, applyErr, err)
						}
					}
					if mode == "late-withdrawn" && !owner.applied {
						t.Fatal("withdrawal control did not reach the final factor fence", applyErr)
					}
					if err := RequireImpersonationActorTOTPSessionFactor(ctx, owner.retained, owner, "actor-admin", actorFactor, TOTPSessionFactorState{EnrollmentVersion: 1, AuthorityVersion: 1}); err == nil {
						t.Fatal("closed Work retained actor factor authority")
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
						t.Fatal("actor factor denial did not roll back provisional effects", count, want)
					}
				})
			}
		})
	}
}
