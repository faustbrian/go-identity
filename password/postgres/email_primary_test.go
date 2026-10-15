package passwordpostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestEmailPrimaryZeroCannotProduceOrConsumeAuthority(t *testing.T) {
	for _, source := range []*EmailPrimarySource{nil, {}} {
		if admission, err := source.Prepare(context.Background(), EmailPrimaryRequest{}); err == nil || admission.custody != nil {
			t.Fatal("zero source produced authority")
		}
	}
	if source, err := NewEmailPrimarySource(nil, EmailPrimaryConfig{}); err == nil || source != nil {
		t.Fatal("zero configuration admitted")
	}
	var admission EmailPrimaryAdmission
	if _, err := admission.Original(); err == nil {
		t.Fatal("zero original admitted")
	}
	if deadline, err := admission.Deadline(); err == nil || !deadline.IsZero() {
		t.Fatal("zero freshness admitted")
	}
	if _, err := admission.Command(identity.CommandBinding{}, nil); err == nil {
		t.Fatal("zero command custody admitted")
	}
	if err := admission.Admit(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero primary checks admitted")
	}
	if err := admission.Consume(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero proof consumed")
	}
	if err := admission.Check(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero terminal admission accepted")
	}
}

func TestEmailPrimaryDiagnosticsAndCallerBounds(t *testing.T) {
	request := EmailPrimaryRequest{TenantID: "private-tenant", AddressID: "private-address", Caller: authorization.DecisionContext{Request: authorization.Request{Subject: authorization.Subject{ID: "private-user"}}}}
	for _, value := range []any{request, EmailPrimarySource{}, EmailPrimaryAdmission{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			formatted := fmt.Sprintf(verb, value)
			if !strings.Contains(formatted, "redacted") || strings.Contains(formatted, "private") {
				t.Fatal("primary diagnostics revealed custody")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit primary export permitted")
		}
	}
	caller := authorization.DecisionContext{Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user", Attributes: authorization.Attributes{"label": authorization.StringValue("mötley team"), "empty": authorization.StringValue("")}}}}
	if !validEmailPrimaryCaller(caller) {
		t.Fatal("bounded Unicode/empty policy attributes denied")
	}
	caller.Request.Subject.Groups = make([]authorization.SubjectID, 65)
	if validEmailPrimaryCaller(caller) {
		t.Fatal("caller cloned before cardinality bound")
	}
	caller.Request.Subject.Groups = nil
	caller.Request.Attributes = authorization.Attributes{"label": authorization.StringValue(strings.Repeat("x", 4097))}
	if validEmailPrimaryCaller(caller) {
		t.Fatal("oversized policy value admitted")
	}
}
