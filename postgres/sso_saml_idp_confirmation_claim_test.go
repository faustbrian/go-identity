package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestSSOSAMLIDPConfirmationClaimBindsBothOriginalValues(t *testing.T) {
	binding, _ := ssoOIDCSigninPlanFixture(t)
	op := SSOSAMLIDPConfirmationOperation()
	binding.OperationID, binding.SchemaID = op.OperationID, op.SchemaID
	binding.RecordID, binding.UserID, binding.AnonymousFlowID = "pending-confirmation", "linked-user", ""
	spec := identity.FeatureCommandSpec{Binding: binding, Operation: op}
	makeWire := func(value byte) string {
		return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
	}
	makeCommand := func(cookie, form string, spec identity.FeatureCommandSpec) identity.Command {
		t.Helper()
		c, err := identity.NewFeatureSAMLIDPConfirmationCommand(spec, authentication.NewBearerCredential(cookie), authentication.NewBearerCredential(form))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cookie, form, other := makeWire(1), makeWire(2), makeWire(3)
	command := makeCommand(cookie, form, spec)
	key := [32]byte{0x05}
	original, err := prepareClaim(command, key)
	if err != nil || original.feature == nil || *original.feature != op {
		t.Fatal("exact confirmation has no coordinator claim", err)
	}
	for _, raw := range []string{cookie, form} {
		if bytes.Contains(original.safeFields, []byte(raw)) || bytes.Contains(original.canonical, []byte(raw)) {
			t.Fatal("claim retains unkeyed submitted custody")
		}
	}
	for name, changed := range map[string]identity.Command{
		"different cookie": makeCommand(other, form, spec),
		"different form":   makeCommand(cookie, other, spec),
		"swapped values":   makeCommand(form, cookie, spec),
	} {
		got, err := prepareClaim(changed, key)
		if err != nil || !bytes.Equal(original.safeFields, got.safeFields) || bytes.Equal(original.canonical, got.canonical) || sameSSOSAMLIDPConfirmationCustody(command, changed) {
			t.Fatal("substituted pair shares original intent or changes safe scope", name, err)
		}
	}
	generated := spec
	generated.Fields = []identity.FeatureField{{Name: "test.prepared", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}}}
	if !sameSSOSAMLIDPConfirmationCustody(command, makeCommand(cookie, form, generated)) {
		t.Fatal("generated metadata could not preserve unchanged raw custody")
	}
	metadataOnly, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareClaim(metadataOnly, key); err == nil || sameSSOSAMLIDPConfirmationCustody(command, metadataOnly) {
		t.Fatal("scalar metadata bypassed required custody")
	}
}
