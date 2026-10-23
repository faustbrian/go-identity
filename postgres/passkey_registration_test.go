package postgres

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func passkeyRegistrationIntentFixture() PasskeyRegistrationIntent {
	previous := registrationIntentFixture()
	previous.Creation.Binding.ActorKind = authorization.SubjectServiceAccount
	previous.Creation.Binding.ActorID = "signup-service"
	return PasskeyRegistrationIntent{Creation: previous.Creation, Credential: identity.CredentialRef{
		ID: "new-passkey-reference", TenantID: previous.Creation.Binding.TenantID,
		UserID: previous.Creation.Binding.UserID, Kind: identity.CredentialPasskey,
		Owner: "passkey", Version: 1,
	}}
}

func TestPasskeyRegistrationFieldsBindProspectiveCreation(t *testing.T) {
	original := passkeyRegistrationIntentFixture()
	fields, err := PasskeyRegistrationFields(original)
	if err != nil || len(fields) == 0 {
		t.Fatal("prospective no-password creation", err)
	}
	encode := func(fields []identity.FeatureField) []byte {
		t.Helper()
		encoded, err := encodeFeature(identity.FeatureCommandSpec{Fields: fields}, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		return cborMap(encoded)
	}
	baseline := encode(fields)
	digest, err := PasskeyRegistrationDigest(original)
	if err != nil || digest == ([32]byte{}) {
		t.Fatal("prospective creation commitment", err)
	}
	foundUser := false
	for _, field := range fields {
		if field.Name == "registration.user" {
			foundUser = field.Value.Kind == identity.FeatureText && field.Value.Text == string(original.Creation.Binding.UserID)
		}
	}
	if !foundUser {
		t.Fatal("protocol participant cannot bind the exact prospective user")
	}
	for _, change := range []func(*PasskeyRegistrationIntent){
		func(s *PasskeyRegistrationIntent) {
			s.Creation.Binding.UserID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
			s.Credential.UserID = s.Creation.Binding.UserID
		},
		func(s *PasskeyRegistrationIntent) { s.Creation.Binding.SchemaID = "other-fields" },
		func(s *PasskeyRegistrationIntent) { s.Creation.Binding.SchemaVersion++ },
		func(s *PasskeyRegistrationIntent) {
			s.Creation.Attributes[0].Value.Scalar.String = "different admitted value"
		},
		func(s *PasskeyRegistrationIntent) { s.Credential.ID = "another-new-passkey" },
	} {
		candidate := passkeyRegistrationIntentFixture()
		change(&candidate)
		changed, err := PasskeyRegistrationFields(candidate)
		if err != nil || bytes.Equal(encode(changed), baseline) {
			t.Fatal("changed prospective creation lost from original command", err)
		}
		changedDigest, err := PasskeyRegistrationDigest(candidate)
		if err != nil || changedDigest == digest {
			t.Fatal("changed prospective creation retained original commitment", err)
		}
	}
	original.Creation.Attributes[0].Value.Scalar.String = "caller mutation after preparation"
	if !bytes.Equal(encode(fields), baseline) {
		t.Fatal("caller changed already mapped creation inputs")
	}
}

func TestPasskeyRegistrationRejectsForeignOrNoninitialCreation(t *testing.T) {
	for _, change := range []func(*PasskeyRegistrationIntent){
		func(s *PasskeyRegistrationIntent) { s.Creation.Status = identity.StatusSuspended },
		func(s *PasskeyRegistrationIntent) { s.Creation.Binding.ActorKind = authorization.SubjectUser },
		func(s *PasskeyRegistrationIntent) {
			s.Creation.Attributes = append(s.Creation.Attributes, s.Creation.Attributes[0])
		},
		func(s *PasskeyRegistrationIntent) { s.Credential.UserID = "foreign-user" },
		func(s *PasskeyRegistrationIntent) { s.Credential.TenantID = "foreign-tenant" },
		func(s *PasskeyRegistrationIntent) { s.Credential.Owner = "identity/password" },
		func(s *PasskeyRegistrationIntent) { s.Credential.Kind = identity.CredentialPassword },
		func(s *PasskeyRegistrationIntent) { s.Credential.Version = 2 },
		func(s *PasskeyRegistrationIntent) { s.Credential.ID = "" },
	} {
		candidate := passkeyRegistrationIntentFixture()
		change(&candidate)
		if fields, err := PasskeyRegistrationFields(candidate); err == nil || fields != nil {
			t.Fatal("foreign/noninitial passkey creation admitted")
		}
		if digest, err := PasskeyRegistrationDigest(candidate); err == nil || digest != ([32]byte{}) {
			t.Fatal("invalid prospective creation received a commitment")
		}
	}
}

func TestPasskeyRegistrationIntentRemainsPrivate(t *testing.T) {
	candidate := passkeyRegistrationIntentFixture()
	if _, err := json.Marshal(candidate); err == nil {
		t.Fatal("prospective account attributes serialized")
	}
	if text := fmt.Sprintf("%#v", candidate); !strings.Contains(text, "redacted") || strings.Contains(text, "new-passkey-reference") || strings.Contains(text, "signup-service") {
		t.Fatal("prospective account context disclosed in diagnostics")
	}
}
