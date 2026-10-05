package session_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestSingleRevocationRetainsExactRecordWithoutFamilyTransition(t *testing.T) {
	s := sessionSpec(t)
	record, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	b := issueBinding(s)
	op := session.RevokeOneOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	c, err := session.NewRevokeOneCommand(b, record)
	if err != nil {
		t.Fatal(err)
	}
	projection, ok := c.RevokeOne()
	got, bindErr := projection.Session.Bindings()
	if !ok || bindErr != nil || projection.Binding != b || got != s {
		t.Fatal("original session scope or authority lost")
	}
	projection.Binding.RecordID = "foreign"
	projection.Session = session.Session{}
	again, _ := c.RevokeOne()
	got, _ = again.Session.Bindings()
	if again.Binding != b || got != s {
		t.Fatal("mutable command")
	}
	if _, ok := c.RevokeFamily(); ok {
		t.Fatal("single logout became family revocation")
	}
	if _, ok := c.Issue(); ok {
		t.Fatal("revocation became issue")
	}
	if err := c.ValidateIssueAt(s.IssuedAt); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("revocation admitted as issuance")
	}
	if _, ok := (session.SessionCommand{}).RevokeOne(); ok {
		t.Fatal("zero command admitted")
	}
	familyBinding := b
	familyOp := session.RevokeFamilyOperation()
	familyBinding.OperationID, familyBinding.SchemaID = familyOp.OperationID, familyOp.SchemaID
	familyBinding.RecordID = s.FamilyID
	family, err := session.NewRevokeFamilyCommand(familyBinding, s.FamilyVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := family.RevokeOne(); ok {
		t.Fatal("family projected as single revocation")
	}
	issueSpec := sessionSpec(t)
	issueSpec.Version = 1
	issueAuthority := authoritySpec()
	issueAuthority.Session.Version = 1
	issueSpec.Authority, err = session.NewAuthoritySnapshot(issueAuthority)
	if err != nil {
		t.Fatal(err)
	}
	issueRecord, err := session.NewSession(issueSpec)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := session.NewIssueCommand(issueBinding(issueSpec), issueRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := issue.RevokeOne(); ok {
		t.Fatal("issuance projected as revocation")
	}
	if fmt.Sprintf("%+v", c) != "session.SessionCommand(redacted)" {
		t.Fatal("scope disclosed")
	}
	if _, err := json.Marshal(c); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("serialization disclosed scope")
	}
	if _, err := c.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("text serialization disclosed scope")
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.OperationID = session.RevokeFamilyOperation().OperationID },
		func(b *identity.CommandBinding) { b.RecordID = s.FamilyID },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
	} {
		bad := b
		mutate(&bad)
		if _, err := session.NewRevokeOneCommand(bad, record); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("misbound session command admitted")
		}
	}
	if _, err := session.NewRevokeOneCommand(b, session.Session{}); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("zero session admitted")
	}
	s.Version = math.MaxUint64
	a := authoritySpec()
	a.Session.Version = s.Version
	s.Authority, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	record, err = session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewRevokeOneCommand(b, record); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("version successor overflow admitted")
	}
	s.Version--
	a.Session.Version = s.Version
	s.Authority, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	record, err = session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewRevokeOneCommand(b, record); err != nil {
		t.Fatal("representable successor denied", err)
	}
}
