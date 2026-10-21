package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func anonymousSessionMappingFixture(t *testing.T) (identity.FeatureCommandSpec, session.Session) {
	t.Helper()
	spec, err := testSession(t).Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: spec.IssuedAt}
	vector, _ := spec.Authority.Bindings()
	vector.ActiveOrganizationID, vector.Organization, vector.Factor, vector.Passkey = "", session.OptionalAuthorityBinding{}, session.OptionalAuthorityBinding{}, session.OptionalAuthorityBinding{}
	vector.User.Version, vector.Identifier.Version, vector.Credential.Version, vector.Session.Version, vector.SessionFamily.Version, vector.Authorization.Version = 1, 1, 1, 1, 1, 1
	spec.Version, spec.FamilyVersion = 1, 1
	spec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	b := revokeBinding()
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = "identity.anonymous.signin", "identity.anonymous.signin.native-v1", 1, ""
	b.TenantID, b.UserID, b.AnonymousFlowID = spec.TenantID, "", "original-flow"
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	fields, err := AnonymousSigninSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	return identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, record
}

func TestAnonymousSessionMappingPreservesUnprivilegedOriginal(t *testing.T) {
	spec, original := anonymousSessionMappingFixture(t)
	spec.Fields = append(spec.Fields, identity.FeatureField{Name: "anonymous.creation.user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "separately-owned-kernel-intent"}})
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := AnonymousSigninSession(command)
	if err != nil {
		t.Fatal("anonymous session projection rejected", err)
	}
	before, _, _ := encodeRecord(original)
	after, _, _ := encodeRecord(restored)
	if !bytes.Equal(before, after) {
		t.Fatal("anonymous original session, authority or remember changed")
	}
	if _, err := OriginalSessionFields(original); err == nil {
		t.Fatal("verified-source mapping acquired anonymous admission")
	}
	for j := range spec.Fields[:len(spec.Fields)-1] {
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields[:j]...)
		changed.Fields = append(changed.Fields, spec.Fields[j+1:]...)
		candidate, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AnonymousSigninSession(candidate); err == nil {
			t.Fatalf("missing anonymous session field %s admitted", spec.Fields[j].Name)
		}
	}
}

func TestAnonymousSessionMappingRejectsOtherProfileAndAuthority(t *testing.T) {
	spec, record := anonymousSessionMappingFixture(t)
	if _, err := AnonymousSigninSessionFields(testSession(t)); err == nil {
		t.Fatal("verified session became anonymous")
	}
	for _, mode := range []string{"schema", "user-scope", "unexpected-field", "verified-kind", "tenant"} {
		t.Run(mode, func(t *testing.T) {
			changed := spec
			changed.Fields = append([]identity.FeatureField(nil), spec.Fields...)
			switch mode {
			case "schema":
				changed.Operation.SchemaVersion, changed.Binding.SchemaVersion = 2, 2
			case "user-scope":
				s, _ := record.Bindings()
				changed.Binding.UserID, changed.Binding.AnonymousFlowID = s.UserID, ""
				changed.Operation.SubjectRequirement = identity.FeatureSubjectUser
			case "unexpected-field":
				changed.Fields = append(changed.Fields, identity.FeatureField{Name: "session.result.proof.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "fabricated"}})
			case "verified-kind":
				for j := range changed.Fields {
					if changed.Fields[j].Name == "session.result.authentication.kind" {
						changed.Fields[j].Value.Uint64 = uint64(session.AuthenticationVerified)
					}
				}
			case "tenant":
				changed.Binding.TenantID = "other-tenant"
			}
			candidate, err := identity.NewFeatureCommand(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AnonymousSigninSession(candidate); err == nil {
				t.Fatal("foreign anonymous mapping admitted")
			}
		})
	}
}
