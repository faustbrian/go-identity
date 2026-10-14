package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// SEND-02: suppression must complete in the same coordinator, with original
// counted admission but no code/challenge/delivery and no recipient discovery.
func TestAuthenticationSendSuppressionHasTerminalNativePreparation(t *testing.T) {
	ctx := context.Background()
	owner, command, _, _, _, calls := authenticationSendFixture(t, (&kernel.Repository{}).Descriptor(), kernel.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1}, kernel.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1})
	base, dims, err := owner.original(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := owner.store.originalPreparedSend(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := owner.restoreInitiationReference(ctx, command, func() []byte { s, _ := command.Feature(); return s.Fields[2].Value.Bytes }())
	if err != nil {
		t.Fatal(err)
	}
	record.recipient = nil
	aad, err := owner.store.sendInitiationAAD(reference.retainedBinding)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := owner.store.sealSendInitiationRecord(ctx, aad, record, reference.binding, dims, true)
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := command.SessionToken()
	input, err := owner.store.restoreSendInitiation(ctx, reference.retainedBinding, wire, bearer)
	if err != nil || !input.suppressed {
		t.Fatal("suppressed custody", err)
	}
	suppressed, err := owner.mapSuppressedSend(ctx, input, bearer)
	if err != nil {
		t.Fatal("suppression has no native completion", err)
	}
	plan, err := owner.suppressedSendPlan(suppressed)
	if err != nil || plan.Delivery != nil || plan.Lifecycle.AfterVersion != 0 {
		t.Fatal("suppression invents challenge/delivery", err)
	}
	spec, _ := suppressed.Feature()
	if spec.Operation.RecordRequirement != identity.FeatureRecordOmitted || spec.Binding.RecordID != "" {
		t.Fatal("suppression has challenge target")
	}
	if _, err := kernel.FeaturePlanDigest(spec.Binding, [32]byte{1}, plan); err != nil {
		t.Fatal("not a coordinator plan", err)
	}
	if err := owner.ValidateFeaturePreparation(suppressed, plan); err != nil {
		t.Fatal(err)
	}
	admitted, err := owner.PrepareFeatureAdmission(ctx, suppressed)
	if err != nil {
		t.Fatal(err)
	}
	output, err := admitted.Generate(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	restored, final, err := owner.RestoreFeaturePreparation(ctx, suppressed, 1, output)
	if err != nil || final.Delivery != nil {
		t.Fatal("suppression generated delivery", err)
	}
	if _, ok := restored.OneTimeCode(); ok {
		t.Fatal("suppression generated code")
	}
	if *calls != 3 {
		t.Fatal("suppression bypassed or repeated risk", *calls)
	}
}
