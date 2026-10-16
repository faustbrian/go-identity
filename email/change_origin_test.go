package email_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/email"
)

func TestChangeOriginRejectsImplicitDisclosure(t *testing.T) {
	for _, value := range []email.ChangeOrigin{{}, {Spec: email.ManagedVerificationSpec{SessionID: "private-original-session", Previous: email.PreviousAddress{CanonicalAddress: "private-old@example.invalid"}}, OutputDigest: [32]byte{1}, FactorVersion: 7}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if got := fmt.Sprintf(verb, value); got != "email.ChangeOrigin(redacted)" {
				t.Fatal("original custody disclosed by formatting")
			}
		}
		if !value.LogValue().Equal(slog.StringValue("email.ChangeOrigin(redacted)")) {
			t.Fatal("original custody disclosed by structured logging")
		}
		if wire, err := json.Marshal(value); err == nil || strings.Contains(string(wire), "private-") {
			t.Fatal("original custody exported implicitly")
		}
		if wire, err := value.MarshalText(); err == nil || wire != nil {
			t.Fatal("original custody exported as text or map key")
		}
	}
}
