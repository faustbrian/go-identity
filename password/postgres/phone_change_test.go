package passwordpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/phone"
)

// Composition must not turn an enrollment proof owner or a missing recovery
// owner into permission to replace a verified number.
func TestPhoneChangeRequiresActualOwners(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := NewPhoneChangeService(nil, nil, nil, nil, policy, PhoneChangeConfig{}, nil); err == nil || owner != nil {
		t.Fatal("missing actual proof/session/recovery owners enabled replacement")
	}
	for _, owner := range []*PhoneChangeService{nil, {}} {
		if err := owner.Initialize(context.Background()); err == nil {
			t.Fatal("zero owner initialized replacement")
		}
		if result, err := owner.SendChange(context.Background(), phone.ChangeRequest{}); err == nil || result.Binding.CommandID != "" {
			t.Fatal("zero owner supplied a replacement challenge")
		}
		if result, err := owner.Update(context.Background(), phone.UpdateRequest{}); err == nil || result.Result.Binding.CommandID != "" {
			t.Fatal("zero owner supplied phone replacement")
		}
		if result, err := owner.RecoverUpdate(context.Background(), phone.UpdateRecoveryRequest{}); err == nil || result.Result.Binding.CommandID != "" {
			t.Fatal("zero owner disclosed replacement history")
		}
	}
}

func TestPhoneChangeProofConsumptionActionIsClosed(t *testing.T) {
	if !reauthenticationConsumptionAction("identity.phone.update") {
		t.Fatal("fresh update proof cannot be consumed atomically")
	}
	for _, action := range []string{"identity.phone.update.recover", "identity.phone.update.other", "identity.phone.verify", ""} {
		if reauthenticationConsumptionAction(action) {
			t.Fatal("unselected phone action acquired proof consumption")
		}
	}
}
