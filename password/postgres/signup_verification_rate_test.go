package passwordpostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// The transport consumes original issuance metadata, not adapter-private state.
type registrationVerificationRateSource interface {
	RegistrationVerificationRateSource(context.Context, capability.Proof, string, authorization.DecisionContext) (identity.UserID, string, time.Duration, error)
}

func TestNativeRegistrationConfirmationRateSource(t *testing.T) {
	var service *SignupService
	owner, ok := any(service).(registrationVerificationRateSource)
	if !ok {
		t.Fatal("native confirmation has no original rate-source port")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		user, challenge, lifetime, err := owner.RegistrationVerificationRateSource(ctx, capability.Proof{}, "", authorization.DecisionContext{})
		if err == nil || user != "" || challenge != "" || lifetime != 0 {
			t.Fatal("invalid source disclosed partial original binding")
		}
	}
}
