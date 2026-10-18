package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func usernameRegistrationFixture() PasswordRegistrationIntent {
	intent := registrationIntentFixture()
	intent.Username = identity.Identifier{ID: "username-id", UserID: intent.Identifier.UserID,
		Kind: identity.IdentifierUsername, CanonicalValue: "strasse", DisplayValue: "Straße", Version: 1,
		NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1}
	return intent
}

func TestPasswordRegistrationFreezesSupplementaryUsername(t *testing.T) {
	encode := func(intent PasswordRegistrationIntent) []byte {
		t.Helper()
		fields, err := PasswordRegistrationFields(intent)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := encodeFeature(identity.FeatureCommandSpec{Fields: fields}, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		return cborMap(wire)
	}
	baseline := encode(usernameRegistrationFixture())
	if bytes.Equal(baseline, encode(registrationIntentFixture())) {
		t.Fatal("username omitted from original registration intent")
	}
	for _, mutate := range []func(*identity.Identifier){
		func(i *identity.Identifier) { i.ID = "another-id" },
		func(i *identity.Identifier) { i.CanonicalValue = "another-name" },
		func(i *identity.Identifier) { i.DisplayValue = "STRASSE" },
		func(i *identity.Identifier) { i.NormalizationProfile = "identity.username.latin-v2" },
		func(i *identity.Identifier) { i.NormalizationVersion++ },
	} {
		changed := usernameRegistrationFixture()
		mutate(&changed.Username)
		if bytes.Equal(baseline, encode(changed)) {
			t.Fatal("supplementary username change did not alter original intent")
		}
	}
	for _, mutate := range []func(*PasswordRegistrationIntent){
		func(i *PasswordRegistrationIntent) { i.Username.ID = i.Identifier.ID },
		func(i *PasswordRegistrationIntent) { i.Username.UserID = "other-user" },
		func(i *PasswordRegistrationIntent) { i.Username.Kind = identity.IdentifierEmail },
		func(i *PasswordRegistrationIntent) { i.Username.Version = 2 },
		func(i *PasswordRegistrationIntent) { i.Username.Verified = true },
		func(i *PasswordRegistrationIntent) { i.Username.Primary = true },
		func(i *PasswordRegistrationIntent) {
			i.Username.NormalizationProfile = ""
			i.Username.NormalizationVersion = 0
		},
		func(i *PasswordRegistrationIntent) { i.Username.CanonicalValue = "" },
		func(i *PasswordRegistrationIntent) { i.Identifier.Kind = identity.IdentifierUsername },
	} {
		invalid := usernameRegistrationFixture()
		mutate(&invalid)
		if fields, err := PasswordRegistrationFields(invalid); err == nil || fields != nil {
			t.Fatal("invalid supplementary username admitted")
		}
	}
}
