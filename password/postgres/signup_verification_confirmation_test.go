package passwordpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type registrationVerificationConfirmer interface {
	ConfirmRegistrationVerification(context.Context, capability.Proof, string, identity.CommandID, string, authorization.DecisionContext) (identity.CommandResult, error)
}

func TestNativeRegistrationConfirmationReservationReplayProvenance(t *testing.T) {
	for name, observation := range map[string]struct {
		outcome  identity.CommitOutcome
		err      error
		replayed bool
	}{
		"fresh denial":       {identity.CommitOutcomeNotCommitted, identity.ForbiddenError{}, false},
		"fresh ambiguity":    {identity.CommitOutcomeUnknown, identity.UnavailableError{}, false},
		"fresh conflict":     {identity.CommitOutcomeConflict, identity.ConflictError{}, false},
		"unobserved":         {identity.CommitOutcomeInvalid, nil, false},
		"retained pending":   {identity.CommitOutcomeInProgress, nil, true},
		"retained committed": {identity.CommitOutcomeCommitted, nil, true},
		"retained denied":    {identity.CommitOutcomeNotCommitted, nil, true},
	} {
		t.Run(name, func(t *testing.T) {
			got := confirmationReservationReplayed(kernel.Reservation{}, identity.CommandResult{Outcome: observation.outcome}, observation.err)
			if got != observation.replayed {
				t.Fatal("reservation outcome falsely classified as replay", got)
			}
		})
	}
}

func TestNativeRegistrationConfirmationTypedPort(t *testing.T) {
	var service *SignupService
	owner, ok := any(service).(email.RegistrationVerificationService)
	if !ok {
		t.Fatal("native signup owner has no typed email confirmation port")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		result, err := owner.VerificationConfirm(ctx, email.VerificationConfirmRequest{})
		if err == nil || result.Outcome != identity.CommitOutcomeInvalid || result.Address != (identity.IdentifierProjection{}) {
			t.Fatal("invalid typed confirmation disclosed output")
		}
		recovered, err := owner.VerificationRecover(ctx, email.VerificationRecoveryRequest{})
		if err == nil || recovered.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("invalid typed recovery admitted")
		}
	}
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
