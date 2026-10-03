package session_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestFamilyRevocationCommandIsClosedScopedAndBounded(t *testing.T) {
	b := issueBinding(sessionSpec(t))
	op := session.RevokeFamilyOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.RecordID = "family-a"
	c, err := session.NewRevokeFamilyCommand(b, 7)
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := c.RevokeFamily()
	if !ok || spec.Binding != b || spec.ExpectedVersion != 7 {
		t.Fatal("native revocation changed")
	}
	spec.ExpectedVersion, spec.Binding.UserID = 1, "foreign"
	again, _ := c.RevokeFamily()
	if again.ExpectedVersion != 7 || again.Binding.UserID != b.UserID {
		t.Fatal("command projection aliases")
	}
	if _, ok := c.Issue(); ok {
		t.Fatal("revoke projected as issuance")
	}
	if err := c.ValidateIssueAt(sessionSpec(t).IssuedAt); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("revoke admitted as issue")
	}
	if _, ok := (session.SessionCommand{}).RevokeFamily(); ok {
		t.Fatal("zero revocation")
	}
	if fmt.Sprintf("%+v", c) != "session.SessionCommand(redacted)" {
		t.Fatal("scope disclosed")
	}
	if _, err := json.Marshal(c); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("serialization admitted")
	}
	for _, v := range []uint64{0, math.MaxUint64} {
		if _, err := session.NewRevokeFamilyCommand(b, v); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("invalid successor admitted")
		}
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.OperationID = "identity.session.issue" },
		func(b *identity.CommandBinding) { b.RecordID = "" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.TenantID = "" },
	} {
		bad := b
		mutate(&bad)
		if _, err := session.NewRevokeFamilyCommand(bad, 7); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("misbound command admitted")
		}
	}
	if _, err := session.NewRevokeFamilyCommand(b, math.MaxUint64-1); err != nil {
		t.Fatal("maximum legal successor denied")
	}
}
