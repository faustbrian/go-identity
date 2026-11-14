//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

type reductionCapturePhase struct {
	featureFailurePhase
	descriptor ContributorDescriptor
	ready      chan struct{}
	release    <-chan struct{}
	once       sync.Once
}

func (p *reductionCapturePhase) Descriptor() ContributorDescriptor {
	if p.descriptor != (ContributorDescriptor{}) {
		return p.descriptor
	}
	return ContributorDescriptor{Owner: "identity/apikey/postgres", ContractID: "identity.apikey", Version: 1}
}

func (p *reductionCapturePhase) AdmitFeaturePreparation(ctx context.Context, w Work, command identity.Command) error {
	binding, _, _, err := w.FeatureScope(p)
	if err != nil || command != p.expected || binding != p.intent.Binding {
		return invalidPreparation()
	}
	return ctx.Err()
}

func (p *reductionCapturePhase) GenerateFeaturePreparation(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	wire, err := p.featureFailurePhase.GenerateFeaturePreparation(ctx, command, generation)
	if err != nil || p.ready == nil {
		return wire, err
	}
	p.once.Do(func() { close(p.ready) })
	select {
	case <-p.release:
		return wire, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *reductionCapturePhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_scim_update_effect(command_id,user_id) VALUES($1,$2)`, string(p.intent.Binding.CommandID), string(p.intent.Binding.UserID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := command.Feature()
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: 1, AfterVersion: 2}, nil
}

func TestAPIKeyPermissionReductionOriginalCapturePostgres(t *testing.T) {
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
	for _, mode := range []string{"committed", "lost-commit-ack", "busy-retained-key", "human-actor", "another-schema", "foreign-contributor", "verification-decorated"} {
		t.Run(mode, func(t *testing.T) {
			executionPool := pool
			var fault *registrationCommitFault
			if mode == "lost-commit-ack" {
				fault = &registrationCommitFault{marker: []byte("INSERT INTO public.identity_test_scim_update_effect")}
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
			repository, err := NewRepository(executionPool, Config{MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.update", SchemaID: "apikey-permission-reduction-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			if mode == "another-schema" {
				op.SchemaID = "apikey-unselected-maintenance-v1"
			}
			binding := codecBinding()
			binding.CommandID, _ = identity.NewCommandID()
			recordID, _ := identity.NewSubjectID()
			binding.RecordID = string(recordID)
			binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			binding.ActorID, binding.ActorKind = "policy-maintenance", authorization.SubjectServiceAccount
			if mode == "human-actor" {
				binding.ActorKind = authorization.SubjectUser
			}
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: binding, Operation: op})
			phase := &reductionCapturePhase{featureFailurePhase: featureFailurePhase{scimUpdatePhase: scimUpdatePhase{expected: command, intent: SCIMUserUpdateIntent{Binding: binding}}}}
			if mode == "foreign-contributor" {
				phase.descriptor = ContributorDescriptor{Owner: "identity/apikey/postgres", ContractID: "identity.apikey.foreign", Version: 1}
			}
			registry, err := NewContributorRegistry([]Contributor{repository, &anonymousCreationAuditPhase{}, &recoveryLifecyclePhase{}, phase})
			if err != nil {
				t.Fatal(err)
			}
			policy := &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(_ context.Context, decision authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: decision.PolicyRevision}, nil
			})}
			configuration := CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: policy, AdmissionPolicy: policy}
			coordinator, err := NewCoordinator(executionPool, registry, configuration)
			if err != nil {
				t.Fatal(err)
			}
			_, _, declaration := featurePlanFixture(t)
			declaration.Contributors = registry.Descriptors()
			declaration.Feature = &FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}
			declaration.SubjectType = "api_key"
			declaration.Lifecycle = &LifecyclePlan{EventType: "api_key.permissions_changed.v1", BeforeVersion: 1, AfterVersion: 2}
			declaration.Audits[0].EventType, declaration.Audits[0].RetentionClass = op.OperationID, "protected"
			audit, err := securityMutationAudit(ctx, binding, 1, 2, time.Now().UTC().Truncate(time.Microsecond), "committed", op.OperationID, "api_key", binding.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			declaration.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(binding, op, "api_key", audit)
			if err != nil {
				t.Fatal(err)
			}
			phase.declaration = declaration
			prepared, err := coordinator.PrepareFeaturePreparationPlan(command, declaration)
			if err != nil {
				t.Fatal(err)
			}
			phase.declaration = prepared
			if mode == "verification-decorated" {
				prepared.APIKeyVerification = &APIKeyVerificationPlan{}
			}
			claim, err := prepareClaim(command, coordinator.keys.retained[1])
			if err != nil {
				t.Fatal(err)
			}
			expected := claimFingerprint(coordinator.keys.retained[1], claim.canonical)
			if mode == "busy-retained-key" {
				phase.ready = make(chan struct{})
				release := make(chan struct{})
				phase.release = release
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				finished := make(chan struct{})
				var first identity.CommandResult
				var firstFingerprint [32]byte
				var firstErr error
				go func() {
					defer close(finished)
					first, firstFingerprint, firstErr = coordinator.ExecutePreparedAPIKeyPermissionReduction(ctx, command, prepared)
				}()
				defer func() { unblock(); <-finished }()
				select {
				case <-phase.ready:
				case <-finished:
					t.Fatal("original preparation did not enter generation", firstErr)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				rotatedConfiguration := configuration
				rotatedConfiguration.CurrentFingerprintKeyVersion = 2
				rotatedConfiguration.RetainedFingerprintKeys = map[uint32][32]byte{1: {1}, 2: {2}}
				rotated, err := NewCoordinator(executionPool, registry, rotatedConfiguration)
				if err != nil {
					t.Fatal(err)
				}
				rotatedPlan, err := rotated.PrepareFeaturePreparationPlan(command, declaration)
				if err != nil {
					t.Fatal(err)
				}
				busy, fingerprint, err := rotated.ExecutePreparedAPIKeyPermissionReduction(ctx, command, rotatedPlan)
				if err != nil || busy.Outcome != identity.CommitOutcomeInProgress || fingerprint != expected {
					t.Fatal("live lease lost original retained-key fingerprint", busy.Outcome, err)
				}
				unblock()
				<-finished
				if firstErr != nil || first.Outcome != identity.CommitOutcomeCommitted || firstFingerprint != expected || phase.generated != 1 {
					t.Fatal("observation repeated generation or changed original commitment", firstErr)
				}
				return
			}
			result, fingerprint, executeErr := coordinator.ExecutePreparedAPIKeyPermissionReduction(ctx, command, prepared)
			if mode == "human-actor" || mode == "another-schema" || mode == "foreign-contributor" || mode == "verification-decorated" {
				if executeErr == nil || result != (identity.CommandResult{}) || fingerprint != ([32]byte{}) || phase.generated != 0 {
					t.Fatal("unselected profile disclosed a commitment or started work", executeErr)
				}
				return
			}
			if fingerprint != expected || fingerprint == ([32]byte{}) {
				t.Fatal("execution lost actual matched original commitment", executeErr)
			}
			if mode == "lost-commit-ack" {
				var unknown identity.UnknownCommitError
				if !fault.hit.Load() || result.Outcome != identity.CommitOutcomeUnknown || !errors.As(executeErr, &unknown) {
					t.Fatal("lost commit ACK disclosed a fabricated outcome", result.Outcome, executeErr)
				}
			} else if executeErr != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("actual capture participant did not commit", executeErr)
			}
			query, caller := queryInputs(binding)
			observed, err := coordinator.QueryCommand(ctx, query, caller)
			if err != nil || observed.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original captured command could not be observed", err)
			}
			claimKey := claimFingerprint(coordinator.keys.retained[1], claim.canonical)
			if !bytes.Equal(claimKey[:], fingerprint[:]) {
				t.Fatal("captured fingerprint does not bind original canonical input")
			}
		})
	}
}
