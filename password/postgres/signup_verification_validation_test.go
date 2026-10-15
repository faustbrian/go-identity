package passwordpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
)

func TestScannerValidationRejectsUnconfiguredService(t *testing.T) {
	for _, service := range []*SignupService{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			valid, err := service.ValidateRegistrationVerification(ctx, capability.Proof{}, "https://example.test/finish", authorization.DecisionContext{})
			if err == nil || valid {
				t.Fatal("unconfigured service produced usable validation")
			}
		}
	}
}
