package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOriginalSessionAdmissionPreservesOwnerExpectations(t *testing.T) {
	record, command, profile := identifierSessionFixture(t)
	if profile.Validate() != nil || (IdentifierAdmissionConfig{}).Validate() == nil {
		t.Fatal("profile validation")
	}
	d, credential, policy, err := OriginalSessionAdmission(profile, record, command.Binding)
	if err != nil || d.GlobalVersion != 1 || d.TenantVersion != 2 || credential.UserAuthorityVersion != 5 || credential.IdentifierAuthorityVersion != 6 || credential.CredentialAuthorityVersion != 7 || credential.Credential.ID != "password-a" || credential.Credential.Version != 9 || policy.Version != 8 {
		t.Fatal("original authority not retained", err)
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "other" },
		func(b *identity.CommandBinding) { b.UserID = "other" },
		func(b *identity.CommandBinding) { b.ActorID = "other" },
	} {
		b := command.Binding
		change(&b)
		if _, _, _, err := OriginalSessionAdmission(profile, record, b); err == nil {
			t.Fatal("foreign owner admitted")
		}
	}
	if _, _, _, err := OriginalSessionAdmission(profile, session.Session{}, command.Binding); err == nil {
		t.Fatal("zero original admitted")
	}
	profile.Audience = "other"
	if _, _, _, err := OriginalSessionAdmission(profile, record, command.Binding); err == nil {
		t.Fatal("replacement profile admitted")
	}
}
