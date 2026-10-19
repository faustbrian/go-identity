package passwordpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/phone"
)

func TestPhoneRemovalRequiresActualRecoveryAndOriginalCustody(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := NewPhoneRemovalService(nil, nil, nil, policy, PhoneRemovalConfig{}, nil); err == nil || owner != nil {
		t.Fatal("missing actual authentication/recovery owners advertised phone removal")
	}
	for _, owner := range []*PhoneRemovalService{nil, {}} {
		if result, err := owner.Remove(context.Background(), phone.RemoveRequest{}); err == nil || result != (identity.CommandResult{}) {
			t.Fatal("zero service supplied phone removal")
		}
		if user, err := owner.RemovalRateSource(context.Background(), phone.RemoveRequest{}); err == nil || user != "" {
			t.Fatal("zero service supplied rate authority")
		}
		if result, err := owner.RecoverRemoval(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil || result != (identity.CommandResult{}) {
			t.Fatal("zero service supplied a historical removal")
		}
	}
}
