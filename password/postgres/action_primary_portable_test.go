package passwordpostgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

func TestActionPrimaryRequestAcceptsPortableCustody(t *testing.T) {
	native := passwordpg.ActionPrimaryRequest{TenantID: "tenant", RecordID: "original-record"}
	var portable password.ActionPrimaryRequest = native
	var source *passwordpg.ActionPrimarySource
	if _, err := source.Prepare(context.Background(), portable); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("portable input invented native admission")
	}
	if portable.TenantID != native.TenantID || portable.RecordID != native.RecordID || fmt.Sprintf("%+v", native) != "passwordpostgres.ActionPrimaryRequest(redacted)" {
		t.Fatal("public alias changed original input or diagnostics")
	}
	if _, err := json.Marshal(native); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("public alias exported protected input")
	}
}
