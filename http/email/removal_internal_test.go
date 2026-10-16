package emailhttp

import (
	"encoding/json"
	"fmt"
	"github.com/faustbrian/go-identity/email"
	"strings"
	"testing"
)

func TestRemovalStateDiagnosticsDoNotTraverseRequest(t *testing.T) {
	s := removalState{request: email.AddressRemoveRequest{AddressID: "private-target", Network: "192.0.2.44"}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, s)
		if !strings.Contains(out, "redacted") || strings.Contains(out, "private-target") || strings.Contains(out, "192.0.2.44") {
			t.Fatal("removal diagnostics traversed retained request")
		}
	}
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("removal state implicitly exported")
	}
}

func TestRemovalDecoderRequiresExplicitAdministrativeSelection(t *testing.T) {
	for _, selected := range []bool{false, true} {
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal([]byte(`{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","addressID":"target-address","expectedIdentifierVersion":"2","expectedVerificationVersion":"3","reason":"admin-requested","primaryDisposition":"leave-unassigned","recoveryDisposition":"preserve-verified-email","targetSubjectID":"target-user"}`), &fields); err != nil {
			t.Fatal(err)
		}
		var r email.AddressRemoveRequest
		_, err := decodeRemovalFields(fields, &r, selected)
		if (err == nil) != selected || selected && r.TargetSubjectID != "target-user" {
			t.Fatal("administrative selector bypassed selection or lost target", selected, err)
		}
	}
}
