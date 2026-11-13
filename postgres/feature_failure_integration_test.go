//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

type featureFailurePhase struct {
	scimUpdatePhase
	code                         FeatureFailureCode
	generated, restored, applied int
	declaration                  CommandPlan
}

func (p *featureFailurePhase) FeatureOperations() []identity.FeatureOperation {
	spec, _ := p.expected.Feature()
	return []identity.FeatureOperation{spec.Operation}
}

func (p *featureFailurePhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.applied++
	if p.mode == "forged-error" {
		return identity.FeatureReceipt{}, TypedFeatureFailureError{Code: p.code}
	}
	if p.mode == "ordinary-conflict" {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if p.mode == "core-conflict" {
		current := identity.UserStatusRecord{User: identity.User{TenantID: p.intent.Binding.TenantID, ID: p.intent.Binding.UserID, Status: identity.StatusActive, Version: 1}, AuthorityVersion: 1}
		if err := w.RequireActiveUserStatus(ctx, p, current); err != nil {
			return identity.FeatureReceipt{}, err
		}
		_, err := p.domain.Apply(ctx, w, p, command, p.intent)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) {
			return identity.FeatureReceipt{}, invalidWork()
		}
	} else {
		rows, err := w.Query(ctx, `SELECT 1 /* private-feature-failure */`)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{}, w.DenyFeature(ctx, p, command, p.code)
}
func (p *featureFailurePhase) ValidateFeaturePreparation(c identity.Command, _ CommandPlan) error {
	if c != p.expected {
		return invalidPreparation()
	}
	return nil
}
func (p *featureFailurePhase) AdmitFeaturePreparation(ctx context.Context, w Work, c identity.Command) error {
	b, _, _, err := w.FeatureScope(p)
	if err != nil || c != p.expected || b != p.intent.Binding {
		return invalidPreparation()
	}
	return ctx.Err()
}
func (p *featureFailurePhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, g uint64) ([]byte, error) {
	if c != p.expected || g == 0 || ctx.Err() != nil {
		return nil, invalidPreparation()
	}
	p.generated++
	return []byte("private-opaque-fixture"), nil
}
func (p *featureFailurePhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, g uint64, wire []byte) (identity.Command, CommandPlan, error) {
	if c != p.expected || g == 0 || ctx.Err() != nil || !bytes.Equal(wire, []byte("private-opaque-fixture")) {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	p.restored++
	return p.expected, p.declaration, nil
}

func assertFeatureFailure(t *testing.T, result identity.CommandResult, err error, code FeatureFailureCode) {
	t.Helper()
	var typed TypedFeatureFailureError
	var conflict identity.ConflictError
	if result.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, &typed) || typed.Code != code || !errors.As(err, &conflict) || result.Validate() != nil {
		t.Fatal("original finite terminal failure lost", result.Outcome, err)
	}
}

func TestFeatureFailurePostgres(t *testing.T) {
	testFeatureFailurePostgres(t, "")
}

func TestGroupFeatureFailurePostgres(t *testing.T) {
	for _, operation := range []string{"identity.scim.group-create", "identity.scim.group-replace", "identity.scim.group-patch", "identity.scim.group-delete"} {
		t.Run(operation, func(t *testing.T) { testFeatureFailurePostgres(t, operation) })
	}
}

func testFeatureFailurePostgres(t *testing.T, groupOperation string) {
	t.Helper()
	ctx, pool, _ := anonymousKernelDatabase(t)
	history, err := (PreparationMigrationSource{Base: MigrationSource{}, Version: 16}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_scim_update_effect(command_id text PRIMARY KEY,user_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	var databaseName string
	if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		t.Fatal(err)
	}
	modes := []string{"uniqueness", "precondition", "generic-conflict", "prepared", "forged-error", "ordinary-conflict", "rollback-ack-lost", "terminal-ack-lost"}
	if groupOperation == "" {
		modes = append(modes, "core-conflict")
	} else if groupOperation != "identity.scim.group-delete" {
		modes = append(modes, "invalid-member")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			executionPool := pool
			var fault *registrationCommitFault
			if mode == "rollback-ack-lost" || mode == "terminal-ack-lost" {
				fault = &registrationCommitFault{marker: []byte("public.identity_test_audits(")}
				if mode == "rollback-ack-lost" {
					fault.marker = []byte("private-feature-failure")
					fault.tag = []byte("ROLLBACK\x00")
				}
				executionPool, err = database.Connect(ctx, database.Config{DSN: os.Getenv("IDENTITY_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = databaseName
					c.ConnConfig.DialFunc = fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if err := executionPool.Close(bounded); err != nil {
						t.Error(err)
					}
				})
			}
			schema := storageSchema()
			for n := range schema.Fields {
				schema.Fields[n].WriteAuthorization = identity.FieldWriteSystem
			}
			repository, err := NewRepository(executionPool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{schema}})
			if err != nil {
				t.Fatal(err)
			}
			intent := scimUpdateIntentFixture("identity.scim.user-patch")
			intent.Binding.CommandID, _ = identity.NewCommandID()
			id, _ := identity.NewSubjectID()
			intent.Binding.UserID = identity.UserID(id)
			intent.Binding.RecordID = "scim-" + string(id)
			intent.ExpectedVersion = 1
			intent.Attributes = nil
			code := FeatureFailureUniqueness
			if mode == "precondition" || mode == "core-conflict" {
				code = FeatureFailurePrecondition
			}
			if mode == "generic-conflict" {
				code = FeatureFailureConflict
			}
			if mode == "invalid-member" {
				code = FeatureFailureInvalidGroupMember
			}
			if mode == "core-conflict" {
				seedAudits, seedOutbox := &anonymousCreationAuditPhase{}, &recoveryLifecyclePhase{}
				seedRegistry, err := NewContributorRegistry([]Contributor{repository, seedAudits, seedOutbox})
				if err != nil {
					t.Fatal(err)
				}
				configuration := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}
				seedCoordinator, err := NewCoordinator(executionPool, seedRegistry, configuration)
				if err != nil {
					t.Fatal(err)
				}
				seedOwner, err := NewCreationUnitOfWork(seedCoordinator, repository, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
				if err != nil {
					t.Fatal(err)
				}
				b := intent.Binding
				b.OperationID = "identity.user.create"
				b.SchemaID = schema.ID
				b.SchemaVersion = schema.Version
				b.RecordID = ""
				b.CommandID, _ = identity.NewCommandID()
				command, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: b, Status: identity.StatusActive, Attributes: storageValues()})
				if err != nil {
					t.Fatal(err)
				}
				seeded, err := seedOwner.Execute(ctx, command)
				if err != nil || seeded.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("actual CAS-refinement seed", err)
				}
				intent.ExpectedVersion = 2
				intent.Attributes = storageValues()[:1]
			}
			fields, err := SCIMUserUpdateFields(intent, schema)
			if err != nil {
				t.Fatal(err)
			}
			op := scimUserUpdateOperation(intent.Binding.OperationID)
			subjectType := "scim_user"
			if groupOperation != "" {
				op = groupFailureOperation(groupOperation)
				intent.Binding.OperationID = op.OperationID
				intent.Binding.SchemaID = op.SchemaID
				fields = nil
				subjectType = "scim_group"
			}
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: intent.Binding, Operation: op, Fields: fields})
			domain, err := NewSCIMUserUpdateDomain(repository)
			if err != nil {
				t.Fatal(err)
			}
			phase := &featureFailurePhase{scimUpdatePhase: scimUpdatePhase{domain: domain, expected: command, intent: intent, mode: mode}, code: code}
			registry, err := NewContributorRegistry([]Contributor{repository, &anonymousCreationAuditPhase{}, &recoveryLifecyclePhase{}, phase})
			if err != nil {
				t.Fatal(err)
			}
			policy := &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: dc.PolicyRevision}, nil
			})}
			configuration := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: policy}
			coordinator, err := NewCoordinator(executionPool, registry, configuration)
			if err != nil {
				t.Fatal(err)
			}
			_, _, plan := featurePlanFixture(t)
			plan.Contributors = registry.Descriptors()
			plan.Feature = &FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}
			plan.SubjectType = subjectType
			if groupOperation == "" {
				plan.SCIMUserUpdate = &SCIMUserUpdatePlan{Required: len(intent.Attributes) > 0, ExpectedVersion: intent.ExpectedVersion}
			}
			plan.Lifecycle = &LifecyclePlan{EventType: "identity.scim.user_patched.v1", BeforeVersion: 7, AfterVersion: 8}
			if groupOperation != "" {
				plan.Lifecycle.EventType = "identity.scim.group_changed.v1"
			}
			plan.Audits[0].EventType = op.OperationID
			plan.Audits[0].RetentionClass = "protected"
			seed, err := securityMutationAudit(ctx, intent.Binding, 7, 8, time.Now().UTC().Truncate(time.Microsecond), "committed", op.OperationID, subjectType, intent.Binding.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(intent.Binding, op, subjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			var result identity.CommandResult
			var denied error
			if mode == "prepared" {
				phase.declaration = plan
				plan, err = coordinator.PrepareFeaturePreparationPlan(command, plan)
				if err != nil {
					t.Fatal(err)
				}
				phase.declaration = plan
				result, denied = coordinator.ExecutePreparedFeature(ctx, command, plan)
			} else {
				plan, err = coordinator.PrepareCommandPlan(intent.Binding, command, plan)
				if err != nil {
					t.Fatal(err)
				}
				reservation, _, err := coordinator.ReserveCommand(ctx, intent.Binding, command, plan)
				if err != nil {
					t.Fatal(err)
				}
				work, err := coordinator.Begin(ctx, reservation)
				if err != nil {
					t.Fatal(err)
				}
				_, applyErr := coordinator.ApplyFeature(ctx, work, command)
				result, denied = coordinator.Abort(work, applyErr)
			}
			query, caller := queryInputs(intent.Binding)
			if fault != nil {
				var typed TypedFeatureFailureError
				if !fault.hit.Load() || result.Outcome != identity.CommitOutcomeUnknown || errors.As(denied, &typed) {
					t.Fatal("lost ACK disclosed finite outcome", result.Outcome, denied)
				}
				observed, queryErr := coordinator.QueryCommand(ctx, query, caller)
				if mode == "rollback-ack-lost" {
					if observed.Outcome != identity.CommitOutcomeInProgress || queryErr != nil {
						t.Fatal("lost rollback ACK minted terminal detail", observed.Outcome, queryErr)
					}
					return
				}
				recovered, recoveryErr := coordinator.RecoverFeatureCommand(ctx, query, caller)
				assertFeatureFailure(t, recovered, recoveryErr, code)
				if observed.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(queryErr, &typed) || typed.Code != code {
					t.Fatal("lost terminal ACK failed primary readback", queryErr)
				}
				return
			}
			if mode == "forged-error" || mode == "ordinary-conflict" {
				var typed TypedFeatureFailureError
				var conflict identity.ConflictError
				if result.Outcome != identity.CommitOutcomeNotCommitted || errors.As(denied, &typed) || !errors.As(denied, &conflict) {
					t.Fatal("caller error minted detail or broke legacy conflict", denied)
				}
				_, replayed, replayErr := coordinator.ReserveCommand(ctx, intent.Binding, command, plan)
				if replayed.Outcome != identity.CommitOutcomeNotCommitted || replayErr != nil {
					t.Fatal("zero-code terminal replay behavior changed", replayErr)
				}
				return
			}
			assertFeatureFailure(t, result, denied, code)
			// Change today's contributor diagnosis. The retained original failure must
			// still replay, without another Apply or renewed uniqueness/CAS decision.
			phase.code = FeatureFailurePrecondition
			for range 2 {
				if mode == "prepared" {
					replayed, replayErr := coordinator.ExecutePreparedFeature(ctx, command, plan)
					assertFeatureFailure(t, replayed, replayErr, code)
				} else {
					reservation, replayed, replayErr := coordinator.ReserveCommand(ctx, intent.Binding, command, plan)
					if reservation.state != nil {
						t.Fatal("terminal failure granted Apply")
					}
					assertFeatureFailure(t, replayed, replayErr, code)
				}
				observed, queryErr := coordinator.QueryCommand(ctx, query, caller)
				var typed TypedFeatureFailureError
				if observed.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(queryErr, &typed) || typed.Code != code {
					t.Fatal("query lost finite terminal error", queryErr)
				}
				recovered, recoveryErr := coordinator.RecoverFeatureCommand(ctx, query, caller)
				assertFeatureFailure(t, recovered, recoveryErr, code)
			}
			if phase.applied != 1 || mode == "prepared" && (phase.generated != 1 || phase.restored != 1) {
				t.Fatal("terminal failure repeated generation/Apply", phase.applied, phase.generated, phase.restored)
			}
		})
	}
}
