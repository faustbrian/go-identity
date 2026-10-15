package passwordpostgres

import (
	"encoding/base64"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestSignupMaterialPreservesOriginalVerifierAndRegistration(t *testing.T) {
	_, row, policy := storedFixture(t)
	r := &Repository{policy: policy}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	base, _, _, _ := replacementFixture(t)
	b := base.Binding
	b.CommandID = id
	b.OperationID, b.RecordID, b.SchemaID = "identity.password.signup", "", "password-signup"
	creation := b
	creation.OperationID = "identity.user.create"
	intent := kernel.PasswordRegistrationIntent{
		Creation:          identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive},
		Identifier:        identity.Identifier{ID: "email", UserID: b.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "synthetic@example.test", Version: 1},
		Credential:        identity.CredentialRef{ID: "password", TenantID: b.TenantID, UserID: b.UserID, Owner: "identity/password", Kind: identity.CredentialPassword, Version: 1},
		ComparisonProfile: "email-v1",
	}
	fields, err := kernel.PasswordRegistrationFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: identity.FeatureOperation{Owner: "identity/password", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}, Fields: fields}
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	command, err := identity.NewFeaturePasswordSignupCommand(spec, row.hash, cookie)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := r.signupMaterial(command, intent)
	if err != nil || hash.String() != row.hash {
		t.Fatal("original signup verifier denied or normalized")
	}
	changed := intent
	changed.Identifier.CanonicalValue = "foreign@example.test"
	if hash, err := r.signupMaterial(command, changed); !errors.Is(err, password.ErrPasswordWork) || hash.String() != "" {
		t.Fatal("changed registration obtained original verifier")
	}
	for _, raw := range []string{"malformed", "$argon2id$v=19$m=16,t=1,p=1$c3ludGhldGlj$RkFLRUZBS0VGQUtFRkFLRQ"} {
		bad, err := identity.NewFeaturePasswordSignupCommand(spec, raw, cookie)
		if err != nil {
			t.Fatal(err)
		}
		if hash, err := r.signupMaterial(bad, intent); !errors.Is(err, password.ErrPasswordWork) || hash.String() != "" {
			t.Fatal("non-issuance signup verifier admitted")
		}
	}
	if hash, err := r.signupMaterial(identity.Command{}, intent); !errors.Is(err, password.ErrPasswordWork) || hash.String() != "" {
		t.Fatal("missing paired custody admitted")
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[1:] },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "registration.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "foreign"}})
		},
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.PolicyVersion++ },
	} {
		badSpec := spec
		badSpec.Fields = append([]identity.FeatureField(nil), spec.Fields...)
		mutate(&badSpec)
		bad, err := identity.NewFeaturePasswordSignupCommand(badSpec, row.hash, cookie)
		if err != nil {
			t.Fatal(err)
		}
		if hash, err := r.signupMaterial(bad, intent); !errors.Is(err, password.ErrPasswordWork) || hash.String() != "" {
			t.Fatal("incomplete or foreign original registration admitted")
		}
	}
	for _, repository := range []*Repository{nil, {}} {
		if hash, err := repository.signupMaterial(command, intent); !errors.Is(err, password.ErrPasswordWork) || hash.String() != "" {
			t.Fatal("zero material owner admitted signup")
		}
	}
}
