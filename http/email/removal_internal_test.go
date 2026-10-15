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
