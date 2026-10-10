package passwordpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

type registrationVerificationConfirmer interface {
	ConfirmRegistrationVerification(context.Context, capability.Proof, string, identity.CommandID, string, authorization.DecisionContext) (identity.CommandResult, error)
}

type registrationVerificationRecovery interface {
	RecoverRegistrationVerification(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (identity.CommandResult, error)
}

func TestNativeRegistrationConfirmation(t *testing.T) {
	var service *SignupService
	owner, ok := any(service).(registrationVerificationConfirmer)
	if !ok {
		t.Fatal("native signup owner has no explicit registration confirmation")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		result, err := owner.ConfirmRegistrationVerification(ctx, capability.Proof{}, "", "", "", authorization.DecisionContext{})
		if err == nil || result.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("invalid confirmation composition admitted effects")
		}
	}
}

func TestNativeRegistrationConfirmationRecovery(t *testing.T) {
	var service *SignupService
	owner, ok := any(service).(registrationVerificationRecovery)
	if !ok {
		t.Fatal("native registration confirmation has no proof-free recovery")
	}
	result, err := owner.RecoverRegistrationVerification(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{})
	if err == nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("invalid confirmation recovery disclosed history")
	}
}
