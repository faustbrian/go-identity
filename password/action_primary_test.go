package password_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// This carrier grants no admission. It retains the existing native caller's
// opaque credential/proof inputs without requiring a persistence adapter.
func TestActionPrimaryRequestPreservesBorrowedCustodyAndRedacts(t *testing.T) {
	csrf, err := session.ParseCSRFToken(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	r := password.ActionPrimaryRequest{TenantID: "sensitive-tenant", TargetSubjectID: "sensitive-target", CommandID: "sensitive-command", RecordID: "sensitive-record", Session: auth.NewBearerCredential("sensitive-bearer"), CSRFToken: csrf, Caller: authorization.DecisionContext{CorrelationID: "sensitive-caller"}}
	for _, value := range []any{password.ActionPrimaryRequest{}, r, &r} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s", "%x"} {
			got := fmt.Sprintf(verb, value)
			if got != "passwordpostgres.ActionPrimaryRequest(redacted)" || strings.Contains(got, "sensitive") || strings.Contains(got, strings.Repeat("A", 43)) {
				t.Fatal("action custody diagnostic changed or disclosed input")
			}
		}
		if wire, err := json.Marshal(value); len(wire) != 0 || !errors.Is(err, password.ErrPasswordWork) {
			t.Fatal("action custody implicitly serialized")
		}
	}
	if wire, err := r.MarshalText(); len(wire) != 0 || !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("action custody text exported")
	}
	if r.Session.Token() != "sensitive-bearer" || r.Caller.CorrelationID != "sensitive-caller" || r.CommandID != "sensitive-command" || r.RecordID != "sensitive-record" || r.TargetSubjectID != "sensitive-target" {
		t.Fatal("diagnostics changed borrowed native inputs")
	}
	if wire, err := r.CSRFToken.Reveal(); err != nil || wire != strings.Repeat("A", 43) {
		t.Fatal("diagnostics consumed original synchronizer")
	}
}
