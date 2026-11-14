package apikey_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestPermissionReductionUnknownPreservesCapturedOriginalRecoveryWithoutDisclosure(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	query := apikey.PermissionReductionReconcileQuery{CommandID: id, TenantID: "tenant-a", Fingerprint: [32]byte{1, 2, 3}}
	lost := apikey.PermissionReductionUnknownError{Recovery: query}
	if lost.Recovery != query || lost.Recovery.Validate() != nil {
		t.Fatal("unknown reduction lost actual captured original scope")
	}
	var original identity.UnknownCommitError
	if !errors.As(lost, &original) || original.CommandID != id {
		t.Fatal("new recovery handle hid existing unknown-commit classification")
	}
	if diagnostic := fmt.Sprintf("%v %#v", lost, lost); strings.Contains(diagnostic, "tenant-a") || strings.Contains(diagnostic, "Fingerprint") || strings.Contains(diagnostic, "1 2 3") {
		t.Fatal("unknown reduction diagnostics disclosed recovery custody")
	}
	if encoded, err := json.Marshal(lost); err == nil || len(encoded) != 0 {
		t.Fatal("unknown reduction implicitly serialized original recovery handle")
	}
	changed := lost.Recovery
	changed.Fingerprint = [32]byte{}
	if changed.Validate() == nil {
		t.Fatal("missing captured fingerprint became reconciliation authority")
	}
	if invalid := (apikey.PermissionReductionUnknownError{Recovery: changed}).Unwrap(); !errors.Is(invalid, apikey.ErrInvalid) {
		t.Fatal("invalid recovery custody acquired unknown-commit classification")
	}
}
