//go:build integration

package mfapostgres

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func oauthSessionFactorRecord(t testing.TB) session.Session {
	t.Helper()
	spec, err := passkeyFactorSession(t).Bindings()
	if err != nil {
		t.Fatal(err)
	}
	vector, err := spec.Authority.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	vector.Passkey = session.OptionalAuthorityBinding{}
	spec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication.Proof.Method = "oauth"
	spec.Authentication.Proof.Assurance = auth.AssuranceSingleFactor
	spec.Authentication.CredentialID = "provider-account"
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func resetOAuthSessionFactors(t testing.TB, ctx context.Context, pool *database.Pool, mode string) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities;
INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','user-a',1,0,decode(repeat('01',16),'hex'),'identity.password.signup')`); err != nil {
		t.Fatal(err)
	}
	var statement string
	switch mode {
	case "missing":
		statement = `DELETE FROM identity_mfa.factor_authorities`
	case "enrolled":
		statement = `UPDATE identity_mfa.factor_authorities SET active_factors=1`
	case "advanced":
		statement = `UPDATE identity_mfa.factor_authorities SET version=2`
	}
	if statement != "" {
		if _, err := pool.Raw().Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadOAuthSessionFactorsPostgres(t *testing.T) {
	ctx, pool, _ := newOAuthSigninFactorStore(t)
	record := oauthSessionFactorRecord(t)
	for _, mode := range []string{"current", "missing", "enrolled", "advanced"} {
		t.Run(mode, func(t *testing.T) {
			resetOAuthSessionFactors(t, ctx, pool, mode)
			err := ReadOAuthSessionFactors(ctx, pool, record, time.Second)
			if mode == "current" {
				if err != nil {
					t.Fatal("original known-empty session generation denied", err)
				}
			} else if !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("lost original factor authority did not deny", err)
			}
		})
	}
}

// This participant exercises the native Work invocation and authoritative MFA
// row, not session storage, provider verification or complete session revocation.
type oauthSessionFactorInvocation struct {
	op                     identity.FeatureOperation
	record                 session.Session
	pool                   *database.Pool
	mode                   string
	applied, final, locked bool
	retained               kernel.Work
}

func (*oauthSessionFactorInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}
}
func (p *oauthSessionFactorInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*oauthSessionFactorInvocation) ValidateFeatureCommand(identity.Command, kernel.CommandPlan) error {
	return nil
}
func (*oauthSessionFactorInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func (p *oauthSessionFactorInvocation) check(ctx context.Context, w kernel.Work) error {
	owner := p
	if p.mode == "foreign-owner" {
		copy := *p
		owner = &copy
	}
	return RequireOAuthSessionFactors(ctx, w, owner, p.record)
}

func (p *oauthSessionFactorInvocation) factorLocked(ctx context.Context) (bool, error) {
	other, err := p.pool.Raw().Begin(ctx)
	if err != nil {
		return false, err
	}
	defer other.Rollback(ctx)
	_, err = other.Exec(ctx, `SELECT version FROM identity_mfa.factor_authorities WHERE tenant_id='tenant-a' AND user_id='user-a' FOR UPDATE NOWAIT`)
	var locked *pgconn.PgError
	if errors.As(err, &locked) && locked.Code == "55P03" {
		return true, nil
	}
	return false, err
}

func (p *oauthSessionFactorInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.retained = w
	f, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO oauth_signin_factor_probe VALUES($1)`, string(f.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.check(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	var err error
	p.locked, err = p.factorLocked(ctx)
	if err != nil || !p.locked {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if p.mode == "late-enrolled" {
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.op, BeforeVersion: 1, AfterVersion: 2}, nil
}

func (p *oauthSessionFactorInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, _ identity.Command) error {
	if err := p.check(ctx, w); err != nil {
		return err
	}
	locked, err := p.factorLocked(ctx)
	if err != nil || !locked {
		return identity.UnavailableError{}
	}
	p.final = true
	return nil
}

func TestRequireOAuthSessionFactorsPostgres(t *testing.T) {
	ctx, pool, repository := newOAuthSigninFactorStore(t)
	for _, mode := range []string{"current-target", "current-caller", "missing", "enrolled", "advanced", "foreign-owner", "foreign-user", "foreign-schema", "foreign-lifecycle", "original-version", "late-enrolled"} {
		t.Run(mode, func(t *testing.T) {
			resetOAuthSessionFactors(t, ctx, pool, mode)
			record := oauthSessionFactorRecord(t)
			spec, _ := record.Bindings()
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			op := session.RevokeOneOperation()
			life := kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: 1, AfterVersion: 2}
			binding := identity.CommandBinding{CommandID: id, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, RecordID: spec.SessionID, PolicyID: "policy", PolicyVersion: 1, CorrelationID: string(id)}
			switch mode {
			case "current-caller":
				binding.RecordID = "sibling-target"
			case "foreign-user":
				binding.UserID, binding.ActorID = "other-user", "other-user"
			case "foreign-schema":
				op.SchemaID = "other-schema"
			case "foreign-lifecycle":
				life.EventType = "session.created.v1"
			case "original-version":
				life.BeforeVersion, life.AfterVersion = 2, 3
			}
			binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{{Name: "factor-test", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: mode}}}})
			if err != nil {
				t.Fatal(err)
			}
			owner := &oauthSessionFactorInvocation{op: op, record: record, pool: pool, mode: mode}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repository, &signupFactorAudit{}, &signupFactorOutbox{}, owner})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := builder.Build(audit.RecordInput{OccurredAt: spec.IssuedAt, Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "session", "aggregate.id": binding.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(binding, op, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			declaration := kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			plan, err := coordinator.PrepareCommandPlan(binding, command, declaration)
			if err != nil {
				t.Fatal("prepare revoke-one guard", err)
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
				if _, usableErr := work.Exec(ctx, `SELECT 1`); usableErr == nil {
					t.Fatal("denied factor guard left Work usable")
				}
				result, err = coordinator.Abort(work, applyErr)
			} else {
				result, err = coordinator.Commit(work, result)
			}
			success := mode == "current-target" || mode == "current-caller"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || !owner.applied || !owner.final || !owner.locked) {
				t.Fatal("original known-empty revoke guard failed", result.Outcome, applyErr, err)
			}
			if !success && (result.Outcome == identity.CommitOutcomeCommitted || owner.final) {
				t.Fatal("lost or foreign factor authority committed", result.Outcome, err)
			}
			if mode == "late-enrolled" && !owner.applied {
				t.Fatal("late-enrollment control never reached final check", applyErr)
			}
			if err := RequireOAuthSessionFactors(ctx, owner.retained, owner, record); err == nil {
				t.Fatal("closed Work retained original factor authority")
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
				t.Fatal("factor denial did not roll back provisional effects", count, want)
			}
			if mode != "missing" {
				if locked, err := owner.factorLocked(ctx); err != nil || locked {
					t.Fatal("completed Work retained factor row lock", locked, err)
				}
			}
		})
	}
}
