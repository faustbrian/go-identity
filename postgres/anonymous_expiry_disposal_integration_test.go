//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// Deliberately does not implement FeatureCommitContributor: an optional final
// callback must not be what rejects a receipt unbacked by a kernel mutation.
type anonymousExpiryReceiptOnly struct {
	command identity.Command
	reached bool
}

func (*anonymousExpiryReceiptOnly) Descriptor() ContributorDescriptor {
	return anonymousCreationDescriptor()
}
func (*anonymousExpiryReceiptOnly) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{anonymousExpiryDisposalOperation()}
}
func (p *anonymousExpiryReceiptOnly) ValidateFeatureCommand(c identity.Command, _ CommandPlan) error {
	if c != p.command {
		return invalidAnonymousDisposal()
	}
	return nil
}
func (p *anonymousExpiryReceiptOnly) ApplyFeature(context.Context, Work, identity.Command) (identity.FeatureReceipt, error) {
	p.reached = true
	return identity.FeatureReceipt{Operation: anonymousExpiryDisposalOperation(), BeforeVersion: 1, AfterVersion: 2}, nil
}
func (*anonymousExpiryReceiptOnly) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, identity.UnavailableError{}
}

func TestAnonymousExpiryReceiptCannotReplaceKernelDisposal(t *testing.T) {
	ctx, pool, repository := anonymousKernelDatabase(t)
	guest := createAnonymousForDisposal(t, ctx, pool, repository)
	snapshot, err := repository.GetAnonymousDisposal(ctx, identity.UserStatusQuery{TenantID: guest.User.TenantID, UserID: guest.User.ID})
	if err != nil {
		t.Fatal(err)
	}
	fields, err := AnonymousDisposalFields(AnonymousDisposalIntent{Snapshot: snapshot, Action: AnonymousDisposeDelete, RetentionPolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	op := anonymousExpiryDisposalOperation()
	b := codecBinding()
	b.CommandID, _ = identity.NewCommandID()
	b.TenantID, b.UserID, b.RecordID = guest.User.TenantID, guest.User.ID, string(guest.User.ID)
	b.ActorKind, b.ActorID = authorization.SubjectServiceAccount, "guest-maintenance"
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	phase := &anonymousExpiryReceiptOnly{command: command}
	registry, err := NewContributorRegistry([]Contributor{repository, &anonymousCreationAuditPhase{}, &recoveryLifecyclePhase{}, phase})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	plan := anonymousOwnerTestPlan(t, coordinator, registry, command, "anonymous.expired.v1", 1, 2)
	reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	w, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Abort(w, identity.UnavailableError{})
	result, err := coordinator.ApplyFeature(ctx, w, command)
	if err != nil {
		result, err = coordinator.Abort(w, err)
	} else {
		result, err = coordinator.Commit(w, result)
	}
	if !phase.reached || err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("receipt-only expiry committed without kernel disposal", phase.reached, err, result.Outcome)
	}
	var status string
	var disposals, audits, events int
	if err := pool.Raw().QueryRow(ctx, `SELECT u.status,(SELECT count(*) FROM identity.anonymous_disposals WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3 AND succeeded),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3) FROM identity.users u WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID), string(b.CommandID)).Scan(&status, &disposals, &audits, &events); err != nil || status != "active" || disposals+audits+events != 0 {
		t.Fatal("receipt-only command escaped rejection", err, status, disposals, audits, events)
	}
}
