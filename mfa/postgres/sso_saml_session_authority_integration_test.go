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
	"github.com/faustbrian/go-identity/session"
)

func TestReadSSOSAMLSessionFactorsPostgres(t *testing.T) {
	ctx, pool, _ := newOAuthSigninFactorStore(t)
	for _, mode := range []string{"current", "missing", "enrolled", "advanced", "foreign-tenant", "foreign-user"} {
		t.Run(mode, func(t *testing.T) {
			resetOAuthSessionFactors(t, ctx, pool, mode)
			record := ssoSAMLFactorSession(t)
			tenant, user := identity.TenantID("tenant-a"), identity.UserID("user-a")
			if mode == "foreign-tenant" || mode == "foreign-user" {
				if mode == "foreign-tenant" {
					tenant = "foreign-tenant"
				} else {
					user = "foreign-user"
				}
				spec, _ := record.Bindings()
				vector, _ := spec.Authority.Bindings()
				spec.TenantID, spec.UserID = tenant, user
				spec.Authentication.Proof.Tenant, spec.Authentication.Proof.Subject = string(tenant), string(user)
				vector.Organization.Binding.ScopeKey = "organization:" + string(tenant) + ":organization-a"
				var err error
				vector.Factor.Binding.ScopeKey, err = FactorAuthorityKey(tenant, user)
				if err != nil {
					t.Fatal(err)
				}
				spec.Authority, err = session.NewAuthoritySnapshot(vector)
				if err != nil {
					t.Fatal(err)
				}
				record, err = session.NewSession(spec)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := ReadSSOSAMLSessionFactors(ctx, pool, record, time.Second)
			if mode == "current" {
				if err != nil {
					t.Fatal("original enterprise generation denied", err)
				}
			} else if !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("lost enterprise factor generation admitted", err)
			}
		})
	}
}

// This narrow native participant observes the real coordinator and MFA row.
// Session ownership, organization membership and SAML verification stay with
// their separate owners; this fixture does not claim complete logout proof.
type ssoSAMLSessionFactorInvocation struct{ oauthSessionFactorInvocation }

func (p *ssoSAMLSessionFactorInvocation) checkSSO(ctx context.Context, w kernel.Work) error {
	owner := p
	if p.mode == "foreign-owner" {
		copy := *p
		owner = &copy
	}
	return RequireSSOSAMLSessionFactors(ctx, w, owner, p.record)
}

func (p *ssoSAMLSessionFactorInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.retained = w
	f, _ := command.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO oauth_signin_factor_probe VALUES($1)`, string(f.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkSSO(ctx, w); err != nil {
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

func (p *ssoSAMLSessionFactorInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, _ identity.Command) error {
	if err := p.checkSSO(ctx, w); err != nil {
		return err
	}
	p.final = true
	return nil
}

func TestRequireSSOSAMLSessionFactorsPostgres(t *testing.T) {
	ctx, pool, repository := newOAuthSigninFactorStore(t)
	for _, mode := range []string{"current-target", "current-caller", "missing", "enrolled", "advanced", "foreign-owner", "foreign-user", "foreign-tenant", "foreign-schema", "foreign-lifecycle", "original-version", "late-enrolled", "oidc-record", "oauth2-record", "social-record"} {
		t.Run(mode, func(t *testing.T) {
			resetOAuthSessionFactors(t, ctx, pool, mode)
			record := ssoSAMLFactorSession(t)
			if mode == "oidc-record" {
				record = ssoOIDCFactorSession(t)
			}
			if mode == "oauth2-record" {
				record = ssoOAuth2FactorSession(t)
			}
			if mode == "social-record" {
				record = oauthSessionFactorRecord(t)
			}
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
			case "foreign-tenant":
				binding.TenantID = "other-tenant"
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
			owner := &ssoSAMLSessionFactorInvocation{oauthSessionFactorInvocation{op: op, record: record, pool: pool, mode: mode}}
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
				t.Fatal("prepare exact revoke-one", err)
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
			success := mode == "current-target" || mode == "current-caller"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || !owner.applied || !owner.final || !owner.locked) {
				t.Fatal("original enterprise factor fence failed", result.Outcome, applyErr, err)
			}
			if !success && (result.Outcome == identity.CommitOutcomeCommitted || owner.final) {
				t.Fatal("lost or foreign authority committed", result.Outcome, err)
			}
			if mode == "late-enrolled" && !owner.applied {
				t.Fatal("late-enrollment control never reached final check", applyErr)
			}
			if err := RequireSSOSAMLSessionFactors(ctx, owner.retained, owner, record); err == nil {
				t.Fatal("returned Work retained enterprise factor authority")
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
				t.Fatal("denied enterprise factor effects survived", count, want)
			}
			if mode != "missing" {
				if locked, err := owner.factorLocked(ctx); err != nil || locked {
					t.Fatal("completed Work retained enterprise factor row lock", locked, err)
				}
			}
		})
	}
}
