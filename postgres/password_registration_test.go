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

func registrationIntentFixture() PasswordRegistrationIntent {
	b := codecBinding()
	b.SchemaID = "fields"
	return PasswordRegistrationIntent{Creation: identity.CreateUserCommand{Binding: b, Status: identity.StatusActive, Attributes: storageValues()}, Identifier: identity.Identifier{ID: "email-id", UserID: b.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "synthetic@example.test", Version: 1}, Credential: identity.CredentialRef{ID: "password", TenantID: b.TenantID, UserID: b.UserID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, ComparisonProfile: "email-v1"}
}

func TestPasswordRegistrationFieldsFreezeCompleteIntent(t *testing.T) {
	original := registrationIntentFixture()
	fields, err := PasswordRegistrationFields(original)
	if err != nil || len(fields) != 10 {
		t.Fatal("registration intent", err)
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
	for _, mutate := range []func(*PasswordRegistrationIntent){
		func(s *PasswordRegistrationIntent) {
			s.Creation.Binding.UserID = "other"
			s.Identifier.UserID = "other"
			s.Credential.UserID = "other"
		},
		func(s *PasswordRegistrationIntent) { s.Creation.Binding.SchemaID = "another" },
		func(s *PasswordRegistrationIntent) { s.Creation.Binding.SchemaVersion++ },
		func(s *PasswordRegistrationIntent) { s.Creation.Attributes[0].Value.Scalar.String = "changed" },
		func(s *PasswordRegistrationIntent) { s.Identifier.ID = "another" },
		func(s *PasswordRegistrationIntent) { s.Identifier.Kind = identity.IdentifierUsername },
		func(s *PasswordRegistrationIntent) { s.Identifier.CanonicalValue = "different@example.test" },
		func(s *PasswordRegistrationIntent) { s.Identifier.DisplayValue = "Display@example.test" },
		func(s *PasswordRegistrationIntent) { s.Credential.ID = "another-password" },
		func(s *PasswordRegistrationIntent) { s.ComparisonProfile = "email-v2" },
	} {
		s := registrationIntentFixture()
		mutate(&s)
		changed, err := PasswordRegistrationFields(s)
		if err != nil || bytes.Equal(encode(changed), baseline) {
			t.Fatal("changed registration intent lost", err)
		}
	}
	original.Creation.Attributes[0].Value.Scalar.String = "changed-after-mapping"
	if !bytes.Equal(encode(fields), baseline) {
		t.Fatal("caller mutated registration fields")
	}
	for _, mutate := range []func(*PasswordRegistrationIntent){
		func(s *PasswordRegistrationIntent) { s.Creation.Status = identity.StatusSuspended },
		func(s *PasswordRegistrationIntent) {
			s.Creation.Attributes = append(s.Creation.Attributes, s.Creation.Attributes[0])
		},
		func(s *PasswordRegistrationIntent) { s.Identifier.Verified = true },
		func(s *PasswordRegistrationIntent) { s.Identifier.Primary = true },
		func(s *PasswordRegistrationIntent) { s.Identifier.Version = 2 },
		func(s *PasswordRegistrationIntent) { s.Identifier.Kind = identity.IdentifierProviderSubject },
		func(s *PasswordRegistrationIntent) { s.Identifier.CanonicalValue = "" },
		func(s *PasswordRegistrationIntent) {
			s.Credential.Kind = identity.CredentialAPIKey
			s.Credential.Owner = "identity/apikey"
		},
		func(s *PasswordRegistrationIntent) { s.Credential.Version = 2 },
		func(s *PasswordRegistrationIntent) { s.Credential.TenantID = "other" },
		func(s *PasswordRegistrationIntent) { s.ComparisonProfile = "" },
	} {
		s := registrationIntentFixture()
		mutate(&s)
		if fields, err := PasswordRegistrationFields(s); err == nil || fields != nil {
			t.Fatal("invalid registration intent admitted")
		}
	}
}

func TestPasswordRegistrationCustodyAndDiagnosticsDeny(t *testing.T) {
	for _, value := range []any{registrationIntentFixture(), PasswordRegistrationDomainConfig{ComparisonProfile: "private-profile", RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}}, PasswordRegistrationDomain{comparison: "private-profile"}} {
		if text := fmt.Sprintf("%+v", value); strings.Contains(text, "synthetic@example.test") || strings.Contains(text, "private-profile") {
			t.Fatal("registration diagnostics disclosed private data")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("registration configuration serialized")
		}
	}
	if user, err := (*PasswordRegistrationDomain)(nil).Apply(context.Background(), Work{}, nil, identity.Command{}, PasswordRegistrationIntent{}); err == nil || user != (identity.User{}) {
		t.Fatal("zero Work acquired registration ownership")
	}
	if domain, err := NewPasswordRegistrationDomain(nil, PasswordRegistrationDomainConfig{}); err == nil || domain != nil {
		t.Fatal("missing repository admitted")
	}
	if passwordRegistrationOperation(identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 2, RecordRequirement: identity.FeatureRecordOmitted}) {
		t.Fatal("unknown registration schema admitted")
	}
}

func TestPasswordRegistrationMigrationPreservesHistory(t *testing.T) {
	ctx := context.Background()
	base, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source := PasswordRegistrationMigrationSource{Base: MigrationSource{}, Version: 10}
	history, err := source.Load(ctx)
	if err != nil || len(history) != len(base)+1 || history[len(base)].Version() != 10 {
		t.Fatal("registration migration history", err)
	}
	for i := range base {
		if history[i].UpSQL() != base[i].UpSQL() {
			t.Fatal("registration changed prior migration bytes")
		}
	}
	for _, bad := range []PasswordRegistrationMigrationSource{{}, {Base: MigrationSource{}, Version: 9}} {
		if _, err := bad.Load(ctx); err == nil {
			t.Fatal("invalid registration migration accepted")
		}
	}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil migration context accepted")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := source.Load(cancelled); err != context.Canceled {
		t.Fatal("migration cancellation lost")
	}
}
