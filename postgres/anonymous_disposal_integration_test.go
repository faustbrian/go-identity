//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This kernel-owner consumer deliberately supplies no session/risk authority.
// The native anonymous service separately proves that full admission boundary.
type anonymousDisposalPhase struct {
	domain   *AnonymousDisposalDomain
	expected identity.Command
	intent   AnonymousDisposalIntent
	mode     string
	applied  bool
}

func (*anonymousDisposalPhase) Descriptor() ContributorDescriptor {
	return anonymousCreationDescriptor()
}
func (*anonymousDisposalPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{anonymousDisposalOperation()}
}
func (p *anonymousDisposalPhase) ValidateFeatureCommand(c identity.Command, _ CommandPlan) error {
	if c != p.expected {
		return invalidAnonymousDisposal()
	}
	return nil
}
func (p *anonymousDisposalPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.mode != "missing-kernel" {
		actual := c
		if p.mode == "reconstructed" {
			s, _ := c.Feature()
			actual, _ = identity.NewFeatureCommand(s)
		}
		u, err := p.domain.Apply(ctx, w, p, actual, p.intent)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		got, err := w.AnonymousDisposal(p)
		if err != nil || got != u {
			return identity.FeatureReceipt{}, invalidAnonymousDisposal()
		}
		p.applied = true
		if p.mode == "duplicate" {
			_, _ = p.domain.Apply(ctx, w, p, c, p.intent)
		}
	}
	if p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	_, err := w.Exec(ctx, `INSERT INTO public.identity_test_anonymous_effect(command_id,user_id) VALUES($1,$2)`, string(w.state.binding.CommandID), string(w.state.binding.UserID))
	return identity.FeatureReceipt{Operation: anonymousDisposalOperation(), BeforeVersion: 1, AfterVersion: 2}, err
}
func (p *anonymousDisposalPhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if p.mode == "final-failure" {
		return identity.ForbiddenError{}
	}
	return p.domain.Check(ctx, w, p, c, p.intent)
}
func (*anonymousDisposalPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_anonymous_effect")
}

func anonymousOwnerTestPlan(t *testing.T, coordinator *Coordinator, registry *ContributorRegistry, c identity.Command, event string, before, after uint64) CommandPlan {
	t.Helper()
	spec, _ := c.Feature()
	b := spec.Binding
	_, _, plan := featurePlanFixture(t)
	plan.Contributors, plan.Feature, plan.SubjectType = registry.Descriptors(), &FeatureRegistration{Contributor: anonymousCreationDescriptor(), Operation: spec.Operation}, "anonymous"
	subject := b.RecordID
	if spec.Operation == anonymousCreationOperation() {
		plan.SubjectType = "anonymous_flow"
		subject = b.AnonymousFlowID
	}
	plan.Lifecycle = &LifecyclePlan{EventType: event, BeforeVersion: before, AfterVersion: after}
	plan.Audits[0].EventType, plan.Audits[0].RetentionClass = b.OperationID, "protected"
	seed, err := securityMutationAudit(context.Background(), b, before, after, time.Now().UTC().Truncate(time.Microsecond), "committed", b.OperationID, plan.SubjectType, subject, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, spec.Operation, plan.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = coordinator.PrepareCommandPlan(b, c, plan)
	if err != nil {
		t.Fatal("owner plan", err)
	}
	return plan
}

func createAnonymousForDisposal(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) AnonymousAuthorityRecord {
	t.Helper()
	intent := anonymousCreationIntentFixture()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	intent.Creation.Binding.CommandID = commandID
	intent.Creation.Binding.UserID = identity.UserID(id)
	intent.Placeholder.ID, intent.Placeholder.UserID, intent.Placeholder.CanonicalValue = identity.IdentifierID(id), identity.UserID(id), string(id)+"@anonymous.invalid"
	b := intent.Creation.Binding
	op := anonymousCreationOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, 1
	b.UserID, b.AnonymousFlowID = "", string(commandID)
	fields, err := AnonymousCreationFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	domain, _ := NewAnonymousCreationDomain(repo)
	p := &anonymousCreationPhase{domain: domain, intent: intent, expected: c, mode: "commit"}
	r, err := NewContributorRegistry([]Contributor{repo, &anonymousCreationAuditPhase{}, &recoveryLifecyclePhase{}, p})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(pool, r, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	plan := anonymousOwnerTestPlan(t, coordinator, r, c, "anonymous.created.v1", 0, 0)
	reservation, _, err := coordinator.ReserveCommand(ctx, b, c, plan)
	if err != nil {
		t.Fatal(err)
	}
	w, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.ApplyFeature(ctx, w, c)
	if err != nil {
		_, _ = coordinator.Abort(w, err)
		t.Fatal("creation prerequisite", err)
	}
	result, err = coordinator.Commit(w, result)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("creation prerequisite commit", err)
	}
	a, err := repo.GetAnonymousAuthority(ctx, identity.UserStatusQuery{TenantID: b.TenantID, UserID: identity.UserID(id)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAnonymousDisposalPostgres(t *testing.T) {
	ctx, pool, repo := anonymousKernelDatabase(t)
	domain, err := NewAnonymousDisposalDomain(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"delete", "anonymize", "retain", "hold-retain", "held", "changed-hold", "changed-epoch", "linked-credential", "linked-contact", "reconstructed", "missing-kernel", "duplicate", "native-failure", "audit-failure", "outbox-failure", "final-failure"} {
		t.Run(mode, func(t *testing.T) {
			a := createAnonymousForDisposal(t, ctx, pool, repo)
			q := identity.UserStatusQuery{TenantID: a.User.TenantID, UserID: a.User.ID}
			if mode == "held" || mode == "hold-retain" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=2 WHERE tenant_id=$1 AND user_id=$2`, string(q.TenantID), string(q.UserID)); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err := repo.GetAnonymousDisposal(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			i := AnonymousDisposalIntent{Snapshot: snapshot, Action: AnonymousDisposeDelete, RetentionPolicyVersion: 1}
			if mode == "anonymize" {
				i.Action = AnonymousDisposeAnonymize
			}
			if mode == "retain" || mode == "hold-retain" {
				i.Action = AnonymousDisposeRetain
			}
			if mode == "held" {
				if _, err := AnonymousDisposalFields(i); err == nil {
					t.Fatal("held erasure mapped")
				}
				return
			}
			fields, err := AnonymousDisposalFields(i)
			if err != nil {
				t.Fatal(err)
			}
			commandID, _ := identity.NewCommandID()
			op := anonymousDisposalOperation()
			b := codecBinding()
			b.CommandID, b.TenantID, b.UserID, b.ActorID, b.ActorKind, b.RecordID = commandID, q.TenantID, q.UserID, identity.ActorID(q.UserID), authorization.SubjectUser, string(q.UserID)
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, 1
			c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "changed-hold":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=2 WHERE tenant_id=$1 AND user_id=$2`, string(q.TenantID), string(q.UserID))
			case "changed-epoch":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET credential_version=2 WHERE tenant_id=$1 AND user_id=$2`, string(q.TenantID), string(q.UserID))
			case "linked-credential":
				_, err = pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'permanent',1,'identity/password',1,true)`, string(q.TenantID), string(q.UserID))
			case "linked-contact":
				_, err = pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,'permanent-contact','email',$3,true,true,1,2,1,clock_timestamp())`, string(q.TenantID), string(q.UserID), string(q.UserID)+"@example.test")
			}
			if err != nil {
				t.Fatal("owner-state control", err)
			}
			p := &anonymousDisposalPhase{domain: domain, expected: c, intent: i, mode: mode}
			audits := &anonymousCreationAuditPhase{recoveryAuditPhase: recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}}
			outbox := &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}
			r, err := NewContributorRegistry([]Contributor{repo, audits, outbox, p})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, r, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan := anonymousOwnerTestPlan(t, coordinator, r, c, "anonymous.deleted.v1", 1, 2)
			reservation, _, err := coordinator.ReserveCommand(ctx, b, c, plan)
			if err != nil {
				t.Fatal(err)
			}
			w, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			result, applyErr := coordinator.ApplyFeature(ctx, w, c)
			if applyErr != nil {
				result, _ = coordinator.Abort(w, applyErr)
			} else {
				result, err = coordinator.Commit(w, result)
			}
			success := mode == "delete" || mode == "anonymize" || mode == "retain" || mode == "hold-retain"
			if success && (err != nil || applyErr != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("kernel disposal did not commit", err, applyErr, result.Outcome)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid disposal committed")
			}
			var status, version string
			var attrs, effects, native, auditCount, outboxCount int
			if err := pool.Raw().QueryRow(ctx, `SELECT u.status,u.version::text,(SELECT count(*) FROM identity.user_attributes WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM identity.anonymous_disposals WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM public.identity_test_anonymous_effect WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3 AND succeeded),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3) FROM identity.users u WHERE tenant_id=$1 AND user_id=$2`, string(q.TenantID), string(q.UserID), string(b.CommandID)).Scan(&status, &version, &attrs, &effects, &native, &auditCount, &outboxCount); err != nil {
				t.Fatal(err)
			}
			wantStatus := "deleted"
			if mode == "anonymize" {
				wantStatus = "anonymized"
			}
			if success {
				wantAttrs := 0
				if i.Action == AnonymousDisposeRetain {
					wantAttrs = 1
				}
				if status != wantStatus || version != "2" || attrs != wantAttrs || effects != 1 || native != 1 || auditCount != 1 || outboxCount != 1 {
					t.Fatal("disposal lost typed policy/atomicity", status, version, attrs, effects, native, auditCount, outboxCount)
				}
				_, receipt, e := coordinator.ReserveCommand(ctx, b, c, plan)
				if e != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("original disposal replay lost", e)
				}
			} else if status != "active" || version != "1" || attrs != 1 || effects != 0 || native != 0 || auditCount != 0 || outboxCount != 0 {
				t.Fatal("failed disposal escaped rollback", status, version, attrs, effects, native, auditCount, outboxCount)
			}
			if (mode == "outbox-failure" || mode == "final-failure") && (!p.applied || !audits.successAttempted) {
				t.Fatal("late rollback never reached actual kernel write/audit")
			}
		})
	}
}
