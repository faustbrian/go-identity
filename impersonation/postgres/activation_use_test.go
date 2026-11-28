package impersonationpostgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestDerivedUseRejectsReservedActionsAndRedactsInput(t *testing.T) {
	if !permittedDerivedAction("profile.read") {
		t.Fatal("ordinary application permission was rejected")
	}
	for _, rejected := range []string{"", "profile read", "identity.apikey.create", "Identity:impersonation:start",
		"organization.transfer", "auth:factor:disable", strings.Repeat("p", 129)} {
		if permittedDerivedAction(rejected) {
			t.Fatal("derived credential accepted a reserved or malformed permission", rejected)
		}
	}
	input := UseInput{Tenant: "tenant", Bearer: "synthetic-credential-value", Permission: "profile.read"}
	for _, value := range []any{input, &input} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(verb, value), input.Bearer) {
				t.Fatal("compared bearer escaped input formatting")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("derived bearer input allowed implicit serialization")
		}
	}
}
