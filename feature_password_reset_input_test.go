package identity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password"
)

func TestFeaturePasswordResetInputPreservesBorrowedOwners(t *testing.T) {
	proof, wire := passwordResetProof(t, 0)
	secret, err := primitive.NewSecret([]byte(" original reset\x00\xffpassword "))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	s := passwordResetSpec()
	c, err := identity.NewFeaturePasswordResetInputCommand(s, secret, proof)
	if err != nil {
		t.Fatal(err)
	}
	s.Fields[2].Value.Bytes[0] = 99
	metadata, ok := c.PasswordResetInputFeature()
	if !ok || metadata.Binding != passwordResetSpec().Binding {
		t.Fatal("original reset scope lost")
	}
	for _, f := range metadata.Fields {
		if f.Value.Kind == identity.FeatureBytes && f.Value.Bytes[0] != 1 {
			t.Fatal("input fields alias original metadata")
		}
	}
	metadata.Fields[0].Name = "changed"
	again, _ := c.PasswordResetInputFeature()
	if again.Fields[0].Name == "changed" {
		t.Fatal("returned fields alias original metadata")
	}
	p, original, ok := c.PasswordResetInputCustody()
	if !ok {
		t.Fatal("original input custody missing")
	}
	if err := p.Use(func(raw []byte) error {
		if !bytes.Equal(raw, []byte(" original reset\x00\xffpassword ")) {
			t.Fatal("password bytes copied, normalized or replaced")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(value, wire) || strings.Contains(value, "original reset") {
			t.Fatal("diagnostic exported original custody")
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("original reset input implicitly serialized")
	}
	if _, ok := c.Feature(); ok {
		t.Fatal("legacy feature selected secret-bearing input")
	}
	if _, ok := c.PasswordResetFeature(); ok {
		t.Fatal("original reset input masqueraded as a verifier")
	}
	if err := original.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if string(raw) != wire {
			t.Fatal("proof bytes changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if proof.ValidateBounds(32, 4096) == nil {
		t.Fatal("constructor cloned terminal proof owner")
	}
	secret.Destroy()
	if p.Use(func([]byte) error { t.Fatal("constructor cloned password owner"); return nil }) == nil {
		t.Fatal("borrowed password survived destruction")
	}
	if _, ok := c.PasswordResetInputFeature(); !ok {
		t.Fatal("safe metadata vanished after terminal custody")
	}
}

func TestFeaturePasswordResetInputClosedBounds(t *testing.T) {
	proof, _ := passwordResetProof(t, 0)
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	for _, n := range []int{1, 1 << 20} {
		secret, err := primitive.NewSecret(bytes.Repeat([]byte{0xff}, n))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := identity.NewFeaturePasswordResetInputCommand(passwordResetSpec(), secret, proof); err != nil {
			t.Fatal("bounded raw password denied", err)
		}
		secret.Destroy()
	}
	for _, secret := range []primitive.Secret{{}, func() primitive.Secret { p, _ := primitive.NewSecret([]byte("destroyed")); p.Destroy(); return p }()} {
		if c, err := identity.NewFeaturePasswordResetInputCommand(passwordResetSpec(), secret, proof); err == nil || c != (identity.Command{}) {
			t.Fatal("zero/destroyed password admitted")
		}
	}
	secret, _ := primitive.NewSecret([]byte("synthetic"))
	defer secret.Destroy()
	if c, err := identity.NewFeaturePasswordResetInputCommand(passwordResetSpec(), secret, capability.Proof{}); err == nil || c != (identity.Command{}) {
		t.Fatal("zero original proof admitted")
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion++ },
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaID = "password-change" },
		func(s *identity.FeatureCommandSpec) { s.Operation.OperationID = "identity.password.change" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		},
		func(s *identity.FeatureCommandSpec) { s.Operation.RecordRequirement = identity.FeatureRecordOmitted },
	} {
		s := passwordResetSpec()
		change(&s)
		if c, err := identity.NewFeaturePasswordResetInputCommand(s, secret, proof); err == nil || c != (identity.Command{}) {
			t.Fatal("foreign reset preparation descriptor admitted")
		}
	}
}
