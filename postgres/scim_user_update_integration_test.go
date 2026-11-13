//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

type scimUpdatePhase struct {
	domain   *SCIMUserUpdateDomain
	expected identity.Command
	intent   SCIMUserUpdateIntent
	mode     string
}

func (*scimUpdatePhase) Descriptor() ContributorDescriptor { return scimUserCreationDescriptor() }
func (p *scimUpdatePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{scimUserUpdateOperation(p.intent.Binding.OperationID)}
}
func (p *scimUpdatePhase) ValidateFeatureCommand(command identity.Command, _ CommandPlan) error {
	if command != p.expected {
		return invalidSCIMUpdate()
	}
	return nil
}
func (p *scimUpdatePhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	status := identity.UserStatusRecord{User: identity.User{TenantID: p.intent.Binding.TenantID, ID: p.intent.Binding.UserID, Status: identity.StatusActive, Version: 1}, AuthorityVersion: 1}
	if err := w.RequireActiveUserStatus(ctx, p, status); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if len(p.intent.Attributes) > 0 && p.mode != "missing-kernel" {
		candidate := command
		if p.mode == "reconstructed-command" {
			spec, _ := command.Feature()
			candidate, _ = identity.NewFeatureCommand(spec)
		}
		owner := FeatureExecutionContributor(p)
		if p.mode == "foreign-participant" {
			foreign := *p
			owner = &foreign
		}
		callContext := ctx
		if p.mode == "cancelled-apply" {
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			callContext = cancelled
		}
		user, err := p.domain.Apply(callContext, w, owner, candidate, p.intent)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		observed, err := w.SCIMUserUpdate(p)
		if err != nil || observed != user || user.Version != p.intent.ExpectedVersion+1 || user.Status != identity.StatusActive {
			return identity.FeatureReceipt{}, invalidSCIMUpdate()
		}
		if p.mode == "duplicate-kernel" {
			_, _ = p.domain.Apply(ctx, w, p, command, p.intent)
		}
	} else if _, err := w.SCIMUserUpdate(p); err == nil {
		return identity.FeatureReceipt{}, invalidSCIMUpdate()
	}
	if p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	_, err := w.Exec(ctx, `INSERT INTO public.identity_test_scim_update_effect(command_id,user_id) VALUES($1,$2)`, string(p.intent.Binding.CommandID), string(p.intent.Binding.UserID))
	spec, _ := command.Feature()
	after := uint64(8)
	if p.mode == "no-core-update" && spec.Operation.OperationID == "identity.scim.user-patch" {
		after = 7
	}
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: 7, AfterVersion: after}, err
}
func (*scimUpdatePhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_scim_update_effect")
}
func (p *scimUpdatePhase) CheckFeatureCommit(ctx context.Context, w Work, command identity.Command) error {
	if command != p.expected || p.mode == "final-check-failure" {
		return identity.ForbiddenError{}
	}
	if p.mode == "final-apply" {
		_, err := p.domain.Apply(ctx, w, p, command, p.intent)
		return err
	}
	if _, err := w.SCIMUserUpdate(p); err == nil {
		return invalidSCIMUpdate()
	}
	return ctx.Err()
}

func TestSCIMUserUpdatePostgres(t *testing.T) {
	ctx, pool, _ := anonymousKernelDatabase(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_scim_update_effect(command_id text PRIMARY KEY,user_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	schema := storageSchema()
	for i := range schema.Fields {
		schema.Fields[i].WriteAuthorization = identity.FieldWriteSystem
	}
	repository, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{schema}, ProfileSchema: ProfileSchemaRef{ID: schema.ID, Version: schema.Version}})
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"identity.scim.user-replace", "identity.scim.user-patch"} {
		for _, mode := range []string{"commit", "no-core-update", "missing-kernel", "duplicate-kernel", "reconstructed-command", "changed-subject", "changed-attributes", "stale-version", "foreign-repository", "foreign-participant", "cancelled-apply", "native-failure", "audit-failure", "outbox-failure", "final-check-failure", "final-apply", "corrupt-storage", "inactive-user", "changed-security-epoch", "commit-acknowledgement-lost", "pending-original-core", "pending-successor-core"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				binding := codecBinding()
				binding.CommandID, _ = identity.NewCommandID()
				userID, _ := identity.NewSubjectID()
				binding.UserID = identity.UserID(userID)
				binding.ActorKind = authorization.SubjectServiceAccount
				seedAudits, seedOutbox := &anonymousCreationAuditPhase{}, &recoveryLifecyclePhase{}
				seedRegistry, err := NewContributorRegistry([]Contributor{repository, seedAudits, seedOutbox})
				if err != nil {
					t.Fatal(err)
				}
				configuration := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}
				seedCoordinator, err := NewCoordinator(pool, seedRegistry, configuration)
				if err != nil {
					t.Fatal(err)
				}
				seedOwner, err := NewCreationUnitOfWork(seedCoordinator, repository, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
				if err != nil {
					t.Fatal(err)
				}
				values := storageValues()
				values[0].Value.Scalar.String = "original"
				seedCommand, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: binding, Status: identity.StatusActive, Attributes: values})
				if err != nil {
					t.Fatal(err)
				}
				seeded, err := seedOwner.Execute(ctx, seedCommand)
				if err != nil || seeded.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("actual kernel fixture creation", err)
				}
				binding.CommandID, _ = identity.NewCommandID()
				op := scimUserUpdateOperation(operation)
				binding.OperationID, binding.SchemaID, binding.SchemaVersion, binding.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, "scim-resource-"+string(userID)
				intent := SCIMUserUpdateIntent{Binding: binding, SchemaID: schema.ID, SchemaVersion: schema.Version, ExpectedVersion: 1, Attributes: storageValues()[:1]}
				if mode == "no-core-update" {
					intent.Attributes = nil
				}
				if mode == "stale-version" {
					intent.ExpectedVersion = 2
				}
				if len(intent.Attributes) > 0 {
					policy := queryDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
						if dc.Request.Action != authorization.Action(operation) || dc.Request.Subject.Kind != authorization.SubjectServiceAccount {
							t.Fatal("field preparation impersonated user/admin")
						}
						return authorization.Decision{Outcome: authorization.Allow, Revision: authorization.Revision(binding.PolicyVersion)}, nil
					})
					processor, err := identity.NewAttributeProcessor(schema, policy, func(_ context.Context, _ identity.NormalizationPolicy, v identity.AttributeScalar) (identity.AttributeScalar, error) {
						return v, nil
					}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: binding.PolicyVersion, ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil }, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil }})
					if err != nil {
						t.Fatal(err)
					}
					caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(binding.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(binding.TenantID), Subject: authorization.Subject{Kind: binding.ActorKind, ID: authorization.SubjectID(binding.ActorID)}, Action: authorization.Action(operation), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)}}}
					intent.Attributes, err = processor.Prepare(ctx, identity.AttributePrepareRequest{TenantID: binding.TenantID, UserID: binding.UserID, SchemaVersion: schema.Version, Updates: intent.Attributes, Context: caller})
					if err != nil {
						t.Fatal("actual SCIM field preparation", err)
					}
				}
				fields, err := SCIMUserUpdateFields(intent, schema)
				if err != nil {
					t.Fatal(err)
				}
				command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields})
				domainRepository := repository
				if mode == "foreign-repository" {
					foreign := *repository
					domainRepository = &foreign
				}
				domain, err := NewSCIMUserUpdateDomain(domainRepository)
				if err != nil {
					t.Fatal(err)
				}
				phase := &scimUpdatePhase{domain: domain, expected: command, intent: intent, mode: mode}
				if mode == "changed-subject" {
					phase.intent.Binding.UserID = "foreign-user"
				}
				if mode == "changed-attributes" {
					phase.intent.Attributes[0].Value.Scalar.String = "different"
				}
				if mode == "corrupt-storage" {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.user_attributes SET document=decode('00','hex') WHERE tenant_id=$1 AND user_id=$2`, string(binding.TenantID), string(binding.UserID)); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "inactive-user" {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, string(binding.TenantID), string(binding.UserID)); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "changed-security-epoch" {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`, string(binding.TenantID), string(binding.UserID)); err != nil {
						t.Fatal(err)
					}
				}
				var before []byte
				if err := pool.Raw().QueryRow(ctx, `SELECT document FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2`, string(binding.TenantID), string(binding.UserID)).Scan(&before); err != nil {
					t.Fatal(err)
				}
				audits := &anonymousCreationAuditPhase{recoveryAuditPhase: recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}}
				outbox := &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}
				registry, err := NewContributorRegistry([]Contributor{repository, audits, outbox, phase})
				if err != nil {
					t.Fatal(err)
				}
				executionPool := pool
				var fault *registrationCommitFault
				if mode == "commit-acknowledgement-lost" {
					fault = &registrationCommitFault{marker: []byte("public.identity_test_scim_update_effect(")}
					var databaseName string
					if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
						t.Fatal(err)
					}
					executionPool, err = database.Connect(ctx, database.Config{DSN: os.Getenv("IDENTITY_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
						c.ConnConfig.Database, c.ConnConfig.DialFunc = databaseName, fault.dial
						return nil
					}})
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						if err := executionPool.Close(bounded); err != nil {
							t.Error(err)
						}
					}()
				}
				coordinator, err := NewCoordinator(executionPool, registry, configuration)
				if err != nil {
					t.Fatal(err)
				}
				_, _, plan := featurePlanFixture(t)
				plan.Contributors, plan.Feature, plan.SubjectType = registry.Descriptors(), &FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, "scim_user"
				plan.SCIMUserUpdate = &SCIMUserUpdatePlan{Required: len(intent.Attributes) > 0, ExpectedVersion: intent.ExpectedVersion}
				plan.Lifecycle = &LifecyclePlan{EventType: "identity.scim.user_updated.v1", BeforeVersion: 7, AfterVersion: 8}
				if mode == "no-core-update" && operation == "identity.scim.user-patch" {
					plan.Lifecycle.AfterVersion = 7
				}
				plan.Audits[0].EventType, plan.Audits[0].RetentionClass = op.OperationID, "protected"
				seed, err := securityMutationAudit(ctx, binding, 7, plan.Lifecycle.AfterVersion, time.Now().UTC().Truncate(time.Microsecond), "committed", op.OperationID, "scim_user", binding.RecordID, "protected", true)
				if err != nil {
					t.Fatal(err)
				}
				plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(binding, op, "scim_user", seed)
				if err != nil {
					t.Fatal(err)
				}
				plan, err = coordinator.PrepareCommandPlan(binding, command, plan)
				if err != nil {
					t.Fatal("SCIM update plan", err)
				}
				reservation, _, err := coordinator.ReserveCommand(ctx, binding, command, plan)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "pending-original-core" || mode == "pending-successor-core" {
					if mode == "pending-successor-core" {
						if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(binding.TenantID), string(binding.UserID)); err != nil {
							t.Fatal(err)
						}
					}
					raw, _ := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
						t.Fatal(err)
					}
					recovered, recoveryErr := coordinator.recoverCommandReceipt(ctx, creationRecoveryQuery(binding))
					if mode == "pending-successor-core" {
						if recovered.Outcome != identity.CommitOutcomeInProgress || recoveryErr == nil {
							t.Fatal("changed core was falsely released as NotCommitted", recovered.Outcome, recoveryErr)
						}
					} else {
						var unavailable identity.UnavailableError
						if recovered.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(recoveryErr, &unavailable) {
							t.Fatal("unchanged core negative evidence did not reconcile", recovered.Outcome, recoveryErr)
						}
					}
					return
				}
				work, err := coordinator.Begin(ctx, reservation)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _, _ = coordinator.Abort(work, identity.UnavailableError{}) }()
				result, applyErr := coordinator.ApplyFeature(ctx, work, command)
				if applyErr != nil {
					result, err = coordinator.Abort(work, applyErr)
				} else {
					result, err = coordinator.Commit(work, result)
				}
				success := mode == "commit" || mode == "no-core-update" || fault != nil
				if fault != nil {
					if err == nil || result.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() {
						t.Fatal("actual lost commit acknowledgement was not exercised", err)
					}
					coordinator, err = NewCoordinator(pool, registry, configuration)
					if err != nil {
						t.Fatal(err)
					}
				} else if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
					t.Fatal("SCIM typed update did not commit", result.Outcome, applyErr, err)
				}
				if !success && result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("invalid SCIM update committed")
				}
				var version string
				var after []byte
				var effects int
				if err := pool.Raw().QueryRow(ctx, `SELECT u.version::text,a.document,(SELECT count(*) FROM public.identity_test_scim_update_effect WHERE command_id=$3) FROM identity.users u JOIN identity.user_attributes a USING(tenant_id,user_id) WHERE tenant_id=$1 AND user_id=$2`, string(binding.TenantID), string(binding.UserID), string(binding.CommandID)).Scan(&version, &after, &effects); err != nil {
					t.Fatal(err)
				}
				wantVersion := "1"
				if mode == "commit" || fault != nil {
					wantVersion = "2"
				}
				wantEffects := 0
				if success {
					wantEffects = 1
				}
				if version != wantVersion || effects != wantEffects {
					t.Fatal("kernel/native effects were not atomic", version, effects)
				}
				if !success || mode == "no-core-update" {
					if !bytes.Equal(before, after) {
						t.Fatal("failure/no-op changed typed document")
					}
				}
				if mode == "commit" || fault != nil {
					values, err := decodeAttributeDocument(schema, after)
					if err != nil || len(values) != 6 || values[0].Value.Scalar.String != "" || values[1].Value.Scalar.Bool {
						t.Fatal("SCIM merge lost empty replacement or omitted fields", err)
					}
				}
				if success {
					for range 2 {
						replayed, receipt, err := coordinator.ReserveCommand(ctx, binding, command, plan)
						if err != nil || replayed.state != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Feature.AfterVersion != plan.Lifecycle.AfterVersion {
							t.Fatal("original SCIM projection result did not replay independently of core version", err)
						}
					}
				}
			})
		}
	}
}
