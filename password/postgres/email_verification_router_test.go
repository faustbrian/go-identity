package passwordpostgres_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

func TestEmailVerificationRouterRequiresRealOwners(t *testing.T) {
	for _, c := range []struct{ email, username *passwordpg.SignupService }{{}, {email: &passwordpg.SignupService{}}, {username: &passwordpg.SignupService{}}, {email: &passwordpg.SignupService{}, username: &passwordpg.SignupService{}}} {
		if s, err := passwordpg.NewRegistrationVerificationRouter(c.email, c.username, nil); err == nil || s != nil {
			t.Fatal("absent registration owners enabled shared confirmation")
		}
	}
	for _, c := range []struct {
		signup  *passwordpg.SignupService
		managed *passwordpg.EmailManagementService
	}{{}, {signup: &passwordpg.SignupService{}}, {managed: &passwordpg.EmailManagementService{}}} {
		if s, err := passwordpg.NewEmailVerificationRouter(c.signup, c.managed); err == nil || s != nil {
			t.Fatal("absent native owners enabled unified confirmation")
		}
	}
	var absent *passwordpg.EmailVerificationRouter
	for _, ctx := range []context.Context{nil, context.Background()} {
		if user, grant, lifetime, err := absent.VerificationRateSource(ctx, capability.Proof{}, "", authorization.DecisionContext{}); err == nil || user != "" || grant != "" || lifetime != 0 {
			t.Fatal("absent router disclosed rate identity")
		}
		if out, err := absent.VerificationConfirm(ctx, email.VerificationConfirmRequest{}); err == nil || out.Address != (identity.IdentifierProjection{}) || out.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("absent router granted verification")
		}
	}
}
