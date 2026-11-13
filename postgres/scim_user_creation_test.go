package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func scimCreationIntentFixture() identity.CreateUserCommand {
	return identity.CreateUserCommand{Binding: codecBinding(), Status: identity.StatusActive, Attributes: storageValues()}
}

func TestSCIMUserCreationFieldsBindCompleteKernelIntent(t *testing.T) {
	intent := scimCreationIntentFixture()
	fields, err := SCIMUserCreationFields(intent)
	if err != nil || len(fields) != 4 {
		t.Fatal("valid SCIM kernel creation intent rejected", err)
	}
	encode := func(fields []identity.FeatureField) []byte {
		t.Helper()
		encoded, err := encodeFeature(identity.FeatureCommandSpec{Fields: fields}, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		return cborMap(encoded)
	}
	original := encode(fields)
	for name, change := range map[string]func(*identity.CreateUserCommand){
		"subject":        func(s *identity.CreateUserCommand) { s.Binding.UserID = "another-user" },
		"schema":         func(s *identity.CreateUserCommand) { s.Binding.SchemaID = "another-schema" },
		"schema version": func(s *identity.CreateUserCommand) { s.Binding.SchemaVersion++ },
		"attribute":      func(s *identity.CreateUserCommand) { s.Attributes[0].Value.Scalar.String = "another name" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := scimCreationIntentFixture()
			change(&candidate)
			changed, err := SCIMUserCreationFields(candidate)
			if err != nil || bytes.Equal(original, encode(changed)) {
				t.Fatal("changed kernel intent was not bound", err)
			}
		})
	}
	intent.Attributes[0].Value.Scalar.String = "changed after mapping"
	if !bytes.Equal(original, encode(fields)) {
		t.Fatal("caller mutated frozen SCIM kernel fields")
	}
	for _, field := range fields {
		if strings.Contains(field.Value.Text, "private-value") {
			t.Fatal("attribute plaintext escaped its commitment")
		}
	}
	for name, change := range map[string]func(*identity.CreateUserCommand){
		"inactive":          func(s *identity.CreateUserCommand) { s.Status = identity.StatusSuspended },
		"missing binding":   func(s *identity.CreateUserCommand) { s.Binding = identity.CommandBinding{} },
		"wrong command":     func(s *identity.CreateUserCommand) { s.Binding.OperationID = "identity.scim.user-create" },
		"invalid attribute": func(s *identity.CreateUserCommand) { s.Attributes[0].Name = "id" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := scimCreationIntentFixture()
			change(&candidate)
			if fields, err := SCIMUserCreationFields(candidate); err == nil || fields != nil {
				t.Fatal("invalid SCIM kernel intent admitted")
			}
		})
	}
}

func TestSCIMUserCreationCannotInventAuthority(t *testing.T) {
	if domain, err := NewSCIMUserCreationDomain(nil); err == nil || domain != nil {
		t.Fatal("missing kernel repository admitted")
	}
	if user, err := (*SCIMUserCreationDomain)(nil).Apply(context.Background(), Work{}, nil, identity.Command{}, scimCreationIntentFixture()); err == nil || user != (identity.User{}) {
		t.Fatal("zero Work produced a user")
	}
	if user, err := (Work{}).SCIMUserCreation(nil); err == nil || user != (identity.User{}) {
		t.Fatal("zero Work fabricated creation evidence")
	}
	if _, err := json.Marshal(SCIMUserCreationDomain{}); err == nil {
		t.Fatal("runtime SCIM composition serialized")
	}
	if text := fmt.Sprintf("%#v", SCIMUserCreationDomain{}); !strings.Contains(text, "redacted") {
		t.Fatal("runtime SCIM composition lacks redaction")
	}
}

func TestSCIMCreationCannotUseSchemaAliasToSkipKernelEffect(t *testing.T) {
	descriptor := ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim", Version: 1}
	operation := identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.user-create", SchemaID: "identity.scim.user-create.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if !featureContributorOwns(descriptor, operation) {
		t.Fatal("exact native SCIM creation tuple denied")
	}
	for name, change := range map[string]func(*identity.FeatureOperation){
		"schema alias":   func(o *identity.FeatureOperation) { o.SchemaID = "scim.alias" },
		"future schema":  func(o *identity.FeatureOperation) { o.SchemaVersion++ },
		"omitted record": func(o *identity.FeatureOperation) { o.RecordRequirement = identity.FeatureRecordOmitted },
		"anonymous flow": func(o *identity.FeatureOperation) { o.SubjectRequirement = identity.FeatureSubjectAnonymousFlow },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := operation
			change(&candidate)
			if featureContributorOwns(descriptor, candidate) {
				t.Fatal("SCIM schema alias bypassed mandatory kernel creation")
			}
		})
	}
}
