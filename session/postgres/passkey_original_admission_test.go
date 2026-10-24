package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOriginalPasskeySessionAdmissionRetainsOriginalAuthority(t *testing.T) {
	record, b, profile := passkeySessionFixture(t)
	b.OperationID, b.SchemaID, b.RecordID = "identity.passkey.update", "identity.passkey.update.assertion-v1", "another-passkey"
	d, c, p, err := OriginalPasskeySessionAdmission(profile, record, b)
	if err != nil || d.GlobalVersion != 1 || d.TenantVersion != 2 || c.UserAuthorityVersion != 5 || c.IdentifierAuthorityVersion != 6 || c.CredentialAuthorityVersion != 7 || c.Credential.Kind != identity.CredentialPasskey || c.Credential.Owner != "passkey" || c.Credential.ID != "passkey-a" || c.Credential.Version != 9 || p.Version != 8 {
		t.Fatal("original passkey authority changed or target replaced authenticating credential", err)
	}
	for _, edit := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorID = "foreign" },
	} {
		foreign := b
		edit(&foreign)
		if _, _, _, err := OriginalPasskeySessionAdmission(profile, record, foreign); err == nil {
			t.Fatal("foreign current-session authority admitted")
		}
	}
	if _, _, _, err := OriginalPasskeySessionAdmission(profile, session.Session{}, b); err == nil {
		t.Fatal("zero original admitted")
	}
	profile.Audience = "foreign"
	if _, _, _, err := OriginalPasskeySessionAdmission(profile, record, b); err == nil {
		t.Fatal("changed audience admitted")
	}
}
