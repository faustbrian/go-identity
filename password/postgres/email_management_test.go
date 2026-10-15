package passwordpostgres_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

func TestManagedEmailRequiresNativeComposition(t *testing.T) {
	if _, err := passwordpg.NewEmailManagementService(nil, passwordpg.EmailManagementConfig{}, nil); err == nil {
		t.Fatal("missing native owners enabled email management")
	}
	var absent *passwordpg.EmailManagementService
	for _, ctx := range []context.Context{nil, context.Background()} {
		changer, ok := any(absent).(email.ChangeConfirmationService)
		if !ok {
			t.Fatal("native email owner has no supported primary-change confirmation and recovery")
		}
		if out, err := changer.ChangeConfirm(ctx, email.ChangeConfirmRequest{}); err == nil || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("absent owner granted primary change")
		}
		if out, err := changer.ChangeRecover(ctx, email.ChangeRecoveryRequest{}); err == nil || out.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("absent owner disclosed change history")
		}
		resender, ok := any(absent).(interface {
			VerificationResend(context.Context, passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error)
		})
		if !ok {
			t.Fatal("native management owner has no public resend")
		}
		if out, err := resender.VerificationResend(ctx, passwordpg.EmailManagementRequest{}); err == nil || out.AddressID != "" {
			t.Fatal("absent native owners granted replacement")
		}
		recovery, ok := any(absent).(interface {
			VerificationSendRecover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (passwordpg.EmailManagementResult, error)
		})
		if !ok {
			t.Fatal("managed request has no proof-free native recovery")
		}
		if out, err := recovery.VerificationSendRecover(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil || out.AddressID != "" {
			t.Fatal("absent native owners disclosed request history")
		}
		if result, err := absent.VerificationSend(ctx, passwordpg.EmailManagementRequest{}); err == nil || result.AddressID != "" {
			t.Fatal("zero email owner granted attachment")
		}
		if spec, replay, err := absent.ReadManagedVerification(ctx, capability.Proof{}, authorization.DecisionContext{}); err == nil || spec.IdentifierID != "" || replay != 0 {
			t.Fatal("zero owner disclosed original link intent")
		}
		if valid, err := absent.ValidateManagedVerification(ctx, capability.Proof{}, "", authorization.DecisionContext{}); err == nil || valid {
			t.Fatal("zero owner admitted scanner inspection")
		}
		if out, err := absent.VerificationConfirm(ctx, email.VerificationConfirmRequest{}); err == nil || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("zero composition granted confirmation")
		}
		if out, err := absent.VerificationRecover(ctx, email.VerificationRecoveryRequest{}); err == nil || out.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("zero composition disclosed recovery")
		}
		if user, challenge, lifetime, err := absent.ManagedVerificationRateSource(ctx, capability.Proof{}, "", authorization.DecisionContext{}); err == nil || user != "" || challenge != "" || lifetime != 0 {
			t.Fatal("zero composition disclosed managed rate identity")
		}
	}
}
