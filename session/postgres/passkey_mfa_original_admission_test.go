package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestOriginalMFAPasskeySessionAdmissionRetainsOriginalOwners(t *testing.T) {
	record, binding, profile := passkeyMFASessionFixture(t)
	binding.OperationID, binding.SchemaID, binding.RecordID = "identity.passkey.update", "identity.passkey.update.assertion-v1", "another-passkey"
	directory, credential, policy, err := OriginalMFAPasskeySessionAdmission(profile, record, binding)
	if err != nil || directory.GlobalVersion != 1 || directory.TenantVersion != 2 ||
		credential.UserAuthorityVersion != 5 || credential.IdentifierAuthorityVersion != 6 || credential.CredentialAuthorityVersion != 7 ||
		credential.Credential.Kind != identity.CredentialPasskey || credential.Credential.Owner != "passkey" ||
		credential.Credential.ID != "passkey-a" || credential.Credential.Version != 9 || policy.Version != 8 {
		t.Fatal("completed MFA lost original owners or target replaced authenticator", err)
	}
	for _, edit := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorID = "foreign" },
	} {
		foreign := binding
		edit(&foreign)
		if d, c, p, err := OriginalMFAPasskeySessionAdmission(profile, record, foreign); err == nil || d != (kernel.DirectoryAuthorityAdmission{}) || c != (kernel.CredentialAdmission{}) || p != (kernel.UserAuthorizationAdmission{}) {
			t.Fatal("foreign authority admitted or returned nonzero expectations")
		}
	}
	ordinary, _, _ := passkeySessionFixture(t)
	for _, candidate := range []session.Session{{}, ordinary} {
		if _, _, _, err := OriginalMFAPasskeySessionAdmission(profile, candidate, binding); err == nil {
			t.Fatal("missing completed TOTP admitted")
		}
	}
	if _, _, _, err := OriginalPasskeySessionAdmission(profile, record, binding); err == nil {
		t.Fatal("MFA record silently entered known-empty profile")
	}
	profile.Audience = "foreign"
	if _, _, _, err := OriginalMFAPasskeySessionAdmission(profile, record, binding); err == nil {
		t.Fatal("changed audience admitted")
	}
}
