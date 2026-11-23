package postgres

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestSSOSAMLIDPConfirmationAccountRequiresExactLinkedUserAndPair(t *testing.T) {
	b, plan := samlIDPConfirmationPlanFixture(t)
	arrival, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b.RecordID = string(arrival)
	a := signinAccountFixture()
	a.Account.TenantID, a.Account.UserID = b.TenantID, b.UserID
	a.Account.Provider = "sso.saml.v1." + strings.Repeat("1", 64)
	a.Credential.Credential.TenantID, a.Credential.Credential.UserID, a.Credential.Credential.Owner = b.TenantID, b.UserID, "sso"
	fields, err := SSOSAMLIDPConfirmationAccountFields(a)
	if err != nil {
		t.Fatal(err)
	}
	paired := func(s identity.FeatureCommandSpec) identity.Command {
		t.Helper()
		c, err := identity.NewFeatureSAMLIDPConfirmationCommand(s,
			authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))),
			authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: plan.Feature.Operation, Fields: fields}
	command := paired(spec)
	if got, err := SSOSAMLIDPConfirmationAccount(command); err != nil || got != a {
		t.Fatal("did not retain the exact linked account and authority versions", err)
	}
	if _, err := SSOSAMLSigninAccount(command); err == nil {
		t.Fatal("SP fence accepted an unsolicited account command")
	}
	plain, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	spFields, err := SSOSAMLSigninAccountFields(a)
	if err != nil {
		t.Fatal(err)
	}
	mixed := spec
	mixed.Fields = append(append([]identity.FeatureField(nil), fields...), spFields[0])
	foreign := spec
	foreign.Binding.UserID = "other-linked-user"
	for _, c := range []identity.Command{plain, paired(mixed), paired(foreign)} {
		if got, err := SSOSAMLIDPConfirmationAccount(c); err == nil || got != (ProviderAccountAdmission{}) {
			t.Fatal("generic, mixed, or foreign-user command admitted", err)
		}
	}
}
