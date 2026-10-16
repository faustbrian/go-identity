package passwordpostgres_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

func TestChangeOriginRequiresNativeCommittedCustody(t *testing.T) {
	for _, native := range []*passwordpg.EmailManagementService{nil, {}} {
		var source email.ChangeOriginSource = native
		for _, ctx := range []context.Context{nil, context.Background()} {
			out, err := source.ReadChangeOrigin(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{})
			if err == nil || out.Spec.IdentifierID != "" || out.OutputDigest != ([32]byte{}) || out.FactorVersion != 0 {
				t.Fatal("absent original owner disclosed replacement intent")
			}
		}
	}
}
