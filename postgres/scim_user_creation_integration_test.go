//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// These typed native/audit/outbox SQL seams prove kernel transaction custody,
// not SCIM credential authentication or the still-unimplemented native store.
type scimCreationPhase struct {
	domain   *SCIMUserCreationDomain
	expected identity.Command
	intent   identity.CreateUserCommand
	mode     string
}

func (*scimCreationPhase) Descriptor() ContributorDescriptor { return scimUserCreationDescriptor() }
func (*scimCreationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{scimUserCreationOperation()}
}
func (p *scimCreationPhase) ValidateFeatureCommand(c identity.Command, _ CommandPlan) error {
	if c != p.expected {
		return invalidSCIMCreation()
	}
	return nil
}
func (p *scimCreationPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	if p.mode != "missing-kernel" {
		candidate := command
		if p.mode == "reconstructed-command" {
			spec, _ := command.Feature()
			candidate, _ = identity.NewFeatureCommand(spec)
		}
		user, err := p.domain.Apply(ctx, w, p, candidate, p.intent)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		observed, err := w.SCIMUserCreation(p)
		if err != nil || user != observed || user.ID != p.intent.Binding.UserID || user.Status != identity.StatusActive || user.Version != 1 {
			return identity.FeatureReceipt{}, invalidSCIMCreation()
		}
		if p.mode == "duplicate-kernel" {
			// A swallowed duplicate must leave the whole Work poisoned.
			_, _ = p.domain.Apply(ctx, w, p, command, p.intent)
		}
	}
	if p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	spec, _ := command.Feature()
	_, err := w.Exec(ctx, `INSERT INTO public.identity_test_scim_effect(command_id,user_id) VALUES($1,$2)`, string(spec.Binding.CommandID), string(p.intent.Binding.UserID))
	return identity.FeatureReceipt{Operation: spec.Operation, AfterVersion: 1}, err
}
func (*scimCreationPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_scim_effect")
}
func (p *scimCreationPhase) CheckFeatureCommit(ctx context.Context, w Work, command identity.Command) error {
	if command != p.expected || p.mode == "final-check-failure" {
		return identity.ForbiddenError{}
	}
	if _, err := w.SCIMUserCreation(p); err == nil {
		return invalidSCIMCreation()
	}
	return ctx.Err()
}

func TestSCIMUserCreationPostgres(t *testing.T) {
	// Reuse the existing task-owned isolated kernel database/migration fixture;
	// it creates no anonymous user and supplies no anonymous authority here.
	ctx, pool, repository := anonymousKernelDatabase(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_scim_effect(command_id text PRIMARY KEY,user_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-kernel", "duplicate-kernel", "reconstructed-command", "changed-subject", "changed-attributes", "changed-actor", "changed-tenant", "unknown-field", "foreign-repository", "native-failure", "audit-failure", "outbox-failure", "final-check-failure", "commit-acknowledgement-lost", "pending-with-existing-user", "pending-without-user"} {
		t.Run(mode, func(t *testing.T) {
			intent := scimCreationIntentFixture()
			var err error
			intent.Binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			intent.Binding.UserID = identity.UserID(id)
			fields, err := SCIMUserCreationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown-field" {
				fields = append(fields, identity.FeatureField{Name: "scim.creation.extra", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
			}
			b, op := intent.Binding, scimUserCreationOperation()
			b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, string(id)
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			domainRepository := repository
			if mode == "foreign-repository" {
				foreign := *repository
				domainRepository = &foreign
			}
			domain, err := NewSCIMUserCreationDomain(domainRepository)
			if err != nil {
				t.Fatal(err)
			}
			phase := &scimCreationPhase{domain: domain, expected: command, intent: intent, mode: mode}
			switch mode {
			case "changed-subject":
				phase.intent.Binding.UserID = "another-user"
			case "changed-attributes":
				phase.intent.Attributes = storageValues()
				phase.intent.Attributes[0].Value.Scalar.String = "another name"
			case "changed-actor":
				phase.intent.Binding.ActorID = "another-actor"
			case "changed-tenant":
				phase.intent.Binding.TenantID = "another-tenant"
			}
			auditing := &anonymousCreationAuditPhase{recoveryAuditPhase: recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}}
			outbox := &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}
			registry, err := NewContributorRegistry([]Contributor{repository, auditing, outbox, phase})
			if err != nil {
				t.Fatal(err)
			}
			executionPool := pool
			var fault *registrationCommitFault
			if mode == "commit-acknowledgement-lost" {
				fault = &registrationCommitFault{marker: []byte("public.identity_test_scim_effect(")}
				var name string
				if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
					t.Fatal(err)
				}
				executionPool, err = database.Connect(ctx, database.Config{DSN: os.Getenv("IDENTITY_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database, c.ConnConfig.DialFunc = name, fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal("owned fault pool", err)
				}
				defer func() {
					bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if err := executionPool.Close(bounded); err != nil {
						t.Error("owned fault pool cleanup", err)
					}
				}()
			}
			config := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}
			coordinator, err := NewCoordinator(executionPool, registry, config)
			if err != nil {
				t.Fatal(err)
			}
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.Feature, plan.SubjectType = registry.Descriptors(), &FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, "scim_user"
			plan.Lifecycle = &LifecyclePlan{EventType: "identity.scim.user_created.v1", AfterVersion: 1}
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = op.OperationID, "protected"
			seed, err := securityMutationAudit(ctx, b, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", op.OperationID, plan.SubjectType, b.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal("SCIM kernel plan", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "pending-with-existing-user" || mode == "pending-without-user" {
				key, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				if mode == "pending-with-existing-user" {
					// Retained kernel evidence cannot be declared absent merely
					// because the other frozen participants report no effect.
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(b.TenantID), string(b.UserID)); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); err != nil {
					t.Fatal(err)
				}
				recovered, recoveryErr := coordinator.recoverCommandReceipt(ctx, creationRecoveryQuery(b))
				var state string
				var users, effects, audits int
				if err := pool.Raw().QueryRow(ctx, `SELECT state,
(SELECT count(*) FROM identity.users WHERE tenant_id=$2 AND user_id=$3),
(SELECT count(*) FROM public.identity_test_scim_effect WHERE command_id=$4),
(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$4)
FROM identity.commands WHERE command_id=$1`, key, string(b.TenantID), string(b.UserID), string(b.CommandID)).Scan(&state, &users, &effects, &audits); err != nil {
					t.Fatal(err)
				}
				if mode == "pending-with-existing-user" {
					if recovered.Outcome != identity.CommitOutcomeInProgress || recoveryErr == nil || state != "pending" || users != 1 || effects != 0 || audits != 0 {
						t.Fatal("existing SCIM kernel evidence was released or success fabricated", recovered.Outcome, state, recoveryErr)
					}
				} else {
					var unavailable identity.UnavailableError
					if recovered.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(recoveryErr, &unavailable) || state != "aborted" || users != 0 || effects != 0 || audits != 1 {
						t.Fatal("unanimous SCIM noncommit was not terminalized with failure audit", recovered.Outcome, state, recoveryErr)
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
			success := mode == "commit" || fault != nil
			if fault != nil {
				if err == nil || result.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() {
					t.Fatal("lost COMMIT acknowledgement was not actually exercised", err)
				}
				coordinator, err = NewCoordinator(pool, registry, config)
				if err != nil {
					t.Fatal(err)
				}
			} else if mode == "commit" && (err != nil || applyErr != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("SCIM kernel did not commit", err, applyErr, result.Outcome)
			} else if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid SCIM kernel creation committed")
			}
			var users, attributes, native, audits, lifecycle int
			err = pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),
(SELECT count(*) FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2),
(SELECT count(*) FROM public.identity_test_scim_effect WHERE command_id=$3),
(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3 AND succeeded),
(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3)`, string(b.TenantID), string(id), string(b.CommandID)).Scan(&users, &attributes, &native, &audits, &lifecycle)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if users != want || attributes != want || native != want || audits != want || lifecycle != want {
				t.Fatalf("SCIM kernel atomicity: users=%d attributes=%d native=%d audits=%d lifecycle=%d", users, attributes, native, audits, lifecycle)
			}
			if success {
				for range 2 {
					replayed, receipt, err := coordinator.ReserveCommand(ctx, b, command, plan)
					if err != nil || replayed.state != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Feature.AfterVersion != 1 {
						t.Fatal("original SCIM result did not recover/replay", err)
					}
				}
			}
		})
	}
}
