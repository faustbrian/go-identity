package passwordpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
)

func TestVerificationSigninRequiresNativeSelection(t *testing.T) {
	if s, err := NewVerificationSigninService(nil, VerificationSigninConfig{}); err == nil || s != nil {
		t.Fatal("missing native composition admitted")
	}
	var s *VerificationSigninService
	if out, err := s.VerificationConfirmAndSignin(context.Background(), email.VerificationSigninRequest{}); err == nil || out.Verification.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("zero service authenticated")
	}
	if out, err := s.VerificationSigninRecover(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil || out.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("zero service recovered issuance")
	}
}
