//go:build integration

package passwordintegration_test

import (
	"context"
	"encoding/base64"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

func TestNativeActionPrimaryIntegration(t *testing.T) {
	testPrimaryPasswordCredentialIntegration(t, "identity_action_primary_test", "", "action-primary")
}

// This fixture proves the password owner's authentic proof, immutable native
// command restoration and atomic protected consumption. Its deliberately
// test-owned effect table is not username or organization implementation proof.
func testNativeActionPrimary(t *testing.T, ctx context.Context, pool *database.Pool, config passwordpg.ReauthenticationConfig, verification passwordpg.ReauthenticationRequest) {
	t.Helper()
	rows, err := (passwordpg.ActionReauthenticationMigrationSource{Base: passwordpg.MigrationSource{}, Version: 9}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, rows[len(rows)-1].UpSQL()); err != nil {
		t.Fatal("action migration", err)
	}
	if _, err = pool.Raw().Exec(ctx, `CREATE SCHEMA action_primary_fixture;
CREATE TABLE action_primary_fixture.effects(command_id text PRIMARY KEY,operation text NOT NULL);
INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','target-owner','active',1);`); err != nil {
		t.Fatal("isolated effect fixture", err)
	}
	for _, action := range []string{"identity.username.update", "identity.organization.owner-transfer"} {
		t.Run(action, func(t *testing.T) {
			target := passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: action, Audience: "action-audience"}
			selected := config
			selected.Targets = append(append([]passwordpg.ReauthenticationTarget(nil), config.Targets...), target)
			source, err := passwordpg.NewReauthenticationService(pool, selected)
			if err != nil {
				t.Fatal("actual proof owner", err)
			}
			verification.Target = target
			issued, err := source.Verify(ctx, verification)
			if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("actual password proof", err)
			}
			primary, err := passwordpg.NewActionPrimarySource(source, passwordpg.ActionPrimaryConfig{Action: action, Audience: target.Audience, MaximumAge: 15 * time.Minute, Transport: session.CredentialBearer})
			if err != nil || !primary.Matches(action, target.Audience) || primary.Matches(action, "foreign") {
				t.Fatal("exact startup target", err)
			}
			for _, denied := range []passwordpg.ActionPrimaryConfig{
				{Action: "identity.password.change", Audience: target.Audience, MaximumAge: time.Minute, Transport: session.CredentialBearer},
				{Action: action, Audience: "unregistered", MaximumAge: time.Minute, Transport: session.CredentialBearer},
				{Action: action, Audience: target.Audience, MaximumAge: 15*time.Minute + time.Nanosecond, Transport: session.CredentialBearer},
			} {
				if _, err := passwordpg.NewActionPrimarySource(source, denied); err == nil {
					t.Fatal("foreign or over-age startup selection enabled")
				}
			}
			request := passwordpg.ActionPrimaryRequest{TenantID: verification.TenantID, RecordID: "01K7TZ4JZH6K5PMFDSVJ5JV0RW", Session: verification.Session, Proof: issued.Proof, Caller: verification.Caller}
			if action == "identity.organization.owner-transfer" {
				request.TargetSubjectID = "target-owner"
			}
			request.CommandID, _ = identity.NewCommandID()
			for _, mutate := range []func(*passwordpg.ActionPrimaryRequest){
				func(r *passwordpg.ActionPrimaryRequest) { r.Proof.Action = "identity.password.change" },
				func(r *passwordpg.ActionPrimaryRequest) { r.Proof.Proof.Audience = "foreign" },
				func(r *passwordpg.ActionPrimaryRequest) { r.Proof.SessionVersion++ },
				func(r *passwordpg.ActionPrimaryRequest) { r.Proof.Proof.Subject = "foreign" },
				func(r *passwordpg.ActionPrimaryRequest) {
					r.Proof.Proof.IssuedAt = r.Proof.Proof.IssuedAt.Add(-time.Hour)
				},
			} {
				wrong := request
				mutate(&wrong)
				if _, err := primary.Prepare(ctx, wrong); err == nil {
					t.Fatal("foreign or modified proof became authority")
				}
			}
			run := func(rollback bool) (identity.CommandResult, error) {
				request.CommandID, _ = identity.NewCommandID()
				admission, err := primary.Prepare(ctx, request)
				if err != nil {
					return identity.CommandResult{}, err
				}
				original, err := admission.Original()
				if err != nil {
					t.Fatal(err)
				}
				originalSpec, err := original.Bindings()
				if err != nil {
					t.Fatal(err)
				}
				deadline, err := admission.Deadline()
				if err != nil || !deadline.Equal(issued.Proof.Proof.ExpiresAt) {
					t.Fatal("original proof freshness changed", err)
				}
				op := identity.FeatureOperation{Owner: "identity/username", OperationID: action, SchemaID: action + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
				descriptor := kernel.ContributorDescriptor{Owner: "identity/username/postgres", ContractID: "identity.username", Version: 1}
				user := originalSpec.UserID
				if request.TargetSubjectID != "" {
					op.Owner, op.SchemaID = "organization", "organization-membership"
					descriptor = kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.membership", Version: 1}
					user = request.TargetSubjectID
				}
				binding := identity.CommandBinding{CommandID: request.CommandID, TenantID: request.TenantID, UserID: user, ActorID: identity.ActorID(originalSpec.UserID), ActorKind: authorization.SubjectUser, RecordID: request.RecordID, OperationID: action, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "action-primary", PolicyVersion: 9, CorrelationID: string(request.CommandID)}
				command, err := admission.Command(binding, nil)
				if err != nil {
					t.Fatal("action command", err)
				}
				before, _ := command.Feature()
				for _, extra := range []identity.FeatureField{
					{Name: "password.action-primary.unknown", Value: identity.FeatureValue{Kind: identity.FeatureBool}},
					{Name: "other.oversize", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: make([]byte, 8193)}},
					{Name: "other.inactive", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Text: "inactive"}},
				} {
					if _, err := primary.Restore(ctx, request, append(slices.Clone(before.Fields), extra)); err == nil {
						t.Fatal("malformed or unknown source custody restored")
					}
				}
				direct, err := primary.Restore(ctx, request, before.Fields)
				if err != nil {
					t.Fatal("direct original restore", err)
				}
				for _, field := range before.Fields {
					if len(field.Value.Bytes) != 0 {
						field.Value.Bytes[0] ^= 1
					}
				}
				unchanged, err := direct.Command(binding, nil)
				want, _ := command.Feature()
				got, _ := unchanged.Feature()
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("Restore retained caller-owned mutable provenance", err)
				}
				// A new immutable native contributor reconstructs custody from the
				// original command; no request-generated state map is available.
				restored, err := primary.RestoreCommand(ctx, command, verification.Caller, session.CSRFToken{})
				if err != nil {
					t.Fatal("restart restore", err)
				}
				until, err := restored.Deadline()
				if err != nil || !until.Equal(deadline) {
					t.Fatal("restore renewed freshness", err)
				}
				phase := &actionPrimaryFixturePhase{source: primary, caller: verification.Caller, command: command, descriptor: descriptor, rollback: rollback}
				domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 3 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
				if err != nil {
					t.Fatal(err)
				}
				lifecycle, err := lifecyclepg.NewContributor()
				if err != nil {
					t.Fatal(err)
				}
				registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, lifecycle, phase})
				if err != nil {
					t.Fatal("closed action registration", err)
				}
				coordinator, err := kernel.NewCoordinator(pool, registry, config.Coordinator)
				if err != nil {
					t.Fatal(err)
				}
				builder, err := audit.NewBuilder(audit.BuilderConfig{})
				if err != nil {
					t.Fatal(err)
				}
				phase.record, err = builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "identifier", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "9"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": "identifier", "aggregate.id": binding.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
				if err != nil {
					t.Fatal(err)
				}
				digest, err := kernel.FeatureAuditBindingDigest(binding, op, "identifier", phase.record)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := coordinator.PrepareCommandPlan(binding, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "identifier", Feature: &kernel.FeatureRegistration{Contributor: descriptor, Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "identifier.updated.v1", BeforeVersion: 0, AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
				if err != nil {
					t.Fatal("action plan", err)
				}
				reservation, result, err := coordinator.ReserveCommand(ctx, binding, command, plan)
				if err != nil {
					return result, err
				}
				work, err := coordinator.Begin(ctx, reservation)
				if err != nil {
					return result, err
				}
				defer coordinator.Abort(work, identity.UnavailableError{})
				result, err = coordinator.ApplyFeature(ctx, work, command)
				if err != nil {
					return coordinator.Abort(work, err)
				}
				return coordinator.Commit(work, result)
			}
			assertState := func(used bool, count int) {
				var actual bool
				var effects int
				if err := pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NOT NULL,(SELECT count(*) FROM action_primary_fixture.effects WHERE operation=$2) FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(request.Proof.Proof.ID), action).Scan(&actual, &effects); err != nil || actual != used || effects != count {
					t.Fatal("proof/effect atomicity", err)
				}
			}
			if result, err := run(true); err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("final denial did not roll back", err)
			}
			assertState(false, 0)
			result, err := run(false)
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("action consumption commit", err)
			}
			assertState(true, 1)
			consumer, _ := base64.RawURLEncoding.Strict().DecodeString(string(result.Binding.CommandID))
			var purpose string
			if err := pool.Raw().QueryRow(ctx, `SELECT consumed_purpose FROM identity_password.reauthentication_records WHERE proof_id=$1 AND user_id=$2 AND consumed_command_id=$3`, string(request.Proof.Proof.ID), string(verification.Caller.Request.Subject.ID), consumer).Scan(&purpose); err != nil || purpose != action {
				t.Fatal("proof consumption changed actor/command scope", err)
			}
			if _, err := run(false); err == nil {
				t.Fatal("one-use proof admitted twice")
			}
			assertState(true, 1)
		})
	}
}

type actionPrimaryFixturePhase struct {
	source     *passwordpg.ActionPrimarySource
	caller     authorization.DecisionContext
	command    identity.Command
	descriptor kernel.ContributorDescriptor
	rollback   bool
	record     audit.Record
}

func (p *actionPrimaryFixturePhase) Descriptor() kernel.ContributorDescriptor { return p.descriptor }
func (p *actionPrimaryFixturePhase) FeatureOperations() []identity.FeatureOperation {
	spec, _ := p.command.Feature()
	return []identity.FeatureOperation{spec.Operation}
}
func (p *actionPrimaryFixturePhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *actionPrimaryFixturePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	a, err := p.source.RestoreCommand(ctx, c, p.caller, session.CSRFToken{})
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := a.Consume(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := c.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO action_primary_fixture.effects VALUES($1,$2)`, string(spec.Binding.CommandID), spec.Operation.OperationID); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: 0, AfterVersion: 1}, nil
}
func (p *actionPrimaryFixturePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.rollback {
		return identity.ForbiddenError{}
	}
	a, err := p.source.RestoreCommand(ctx, c, p.caller, session.CSRFToken{})
	if err != nil {
		return err
	}
	return a.Check(ctx, w, p, c)
}
func (p *actionPrimaryFixturePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.source.Recover(ctx, w, p)
}
