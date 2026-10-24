package postgres

import (
	"bytes"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func passkeySignupSessionFixture(t *testing.T) (session.Session, identity.FeatureCommandSpec) {
	t.Helper()
	original, b, _ := passkeySessionFixture(t)
	spec, _ := original.Bindings()
	spec.Authentication.CredentialVersion = 1
	v, _ := spec.Authority.Bindings()
	v.User.Version, v.Identifier.Version, v.Credential.Version, v.Authorization.Version = 1, 1, 1, 1
	v.Factor.Binding.Version, v.Passkey.Binding.Version = 1, 1
	spec.Authority, _ = session.NewAuthoritySnapshot(v)
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	b.UserID, b.AnonymousFlowID = "", "original-passkey-signup-flow"
	b.ActorID, b.ActorKind = "signup-service", authorization.SubjectServiceAccount
	b.OperationID, b.SchemaID, b.RecordID = "identity.passkey.register-verify", "identity.passkey.register-verify.signup-v1", spec.Authentication.CredentialID
	creation := b
	creation.OperationID, creation.SchemaID, creation.UserID, creation.AnonymousFlowID, creation.RecordID = "identity.user.create", "fields", spec.UserID, "", ""
	fields, err := kernel.PasskeyRegistrationFields(kernel.PasskeyRegistrationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Credential: identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID), TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return record, identity.FeatureCommandSpec{Binding: b, Operation: identity.FeatureOperation{Owner: "passkey", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}, Fields: fields}
}

func TestPasskeySignupSessionRetainsProspectiveSubject(t *testing.T) {
	record, commandSpec := passkeySignupSessionFixture(t)
	fields, err := PasskeySignupSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	commandSpec.Fields = append(commandSpec.Fields, fields...)
	command, err := identity.NewFeatureCommand(commandSpec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PasskeySignupSession(command)
	wantBytes, _, we := encodeRecord(record)
	gotBytes, _, ge := encodeRecord(got)
	if err != nil || we != nil || ge != nil || !bytes.Equal(wantBytes, gotBytes) {
		t.Fatal("original prospective passkey session not retained", err)
	}
	if _, err := PasskeySigninSession(command); err == nil {
		t.Fatal("signup command admitted as existing-account signin")
	}
	for name, change := range map[string]func(*identity.FeatureCommandSpec){
		"other-user": func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "registration.user" {
					s.Fields[i].Value.Text = "other-user"
				}
			}
		},
		"other-credential": func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "other-passkey" },
		"human-actor":      func(s *identity.FeatureCommandSpec) { s.Binding.ActorKind = authorization.SubjectUser },
		"unknown-session-field": func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "session.result.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "unsupported"}})
		},
		"missing-user": func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "registration.user" {
					s.Fields = append(s.Fields[:i], s.Fields[i+1:]...)
					break
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, _ := command.Feature()
			change(&candidate)
			changed, err := identity.NewFeatureCommand(candidate)
			if err != nil {
				t.Fatal("invalid denial fixture", err)
			}
			if _, err := PasskeySignupSession(changed); err == nil {
				t.Fatal("foreign or incomplete prospective session admitted")
			}
		})
	}
}

func TestPasskeySignupSessionRejectsAdoptedGenerations(t *testing.T) {
	record, _ := passkeySignupSessionFixture(t)
	for _, change := range []func(*session.AuthoritySnapshotSpec){
		func(v *session.AuthoritySnapshotSpec) { v.User.Version++ },
		func(v *session.AuthoritySnapshotSpec) { v.Identifier.Version++ },
		func(v *session.AuthoritySnapshotSpec) { v.Credential.Version++ },
		func(v *session.AuthoritySnapshotSpec) { v.Authorization.Version++ },
		func(v *session.AuthoritySnapshotSpec) { v.Factor.Binding.Version++ },
		func(v *session.AuthoritySnapshotSpec) { v.Passkey.Binding.Version++ },
	} {
		spec, _ := record.Bindings()
		v, _ := spec.Authority.Bindings()
		change(&v)
		spec.Authority, _ = session.NewAuthoritySnapshot(v)
		changed, err := session.NewSession(spec)
		if err != nil {
			t.Fatal("invalid generation-denial fixture", err)
		}
		if _, err := PasskeySignupSessionFields(changed); err == nil {
			t.Fatal("signup adopted a noninitial owner generation")
		}
	}
}
