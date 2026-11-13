package postgres

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func oauthSigninMappingFixture(t testing.TB, csrf bool) (identity.FeatureCommandSpec, session.Session, auth.BearerCredential) {
	t.Helper()
	record, _, _ := identifierSessionFixture(t)
	spec, _ := record.Bindings()
	spec.Version, spec.FamilyVersion = 1, 1
	vector, _ := spec.Authority.Bindings()
	vector.Session.Version, vector.SessionFamily.Version = 1, 1
	vector.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:tenant-a:user-a", Version: 19}}
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	binding := revokeBinding()
	binding.TenantID, binding.UserID, binding.AnonymousFlowID = spec.TenantID, "", "original-oauth-flow"
	binding.ActorID, binding.ActorKind = "oauth-login", authorization.SubjectServiceAccount
	binding.OperationID, binding.SchemaID, binding.RecordID = "identity.oauth.callback", "oauth-signin-callback-v1", ""
	spec.Authentication.Proof.ID, spec.Authentication.Proof.Method = auth.ProofID(binding.CommandID), "oauth"
	spec.Authentication.CredentialID = "provider-account"
	var err error
	record, err = session.NewSession(spec)
	if err != nil {
		t.Fatal("construct prospective provider session", err)
	}
	if csrf {
		record = withCSRFState(t, record, 23)
	}
	fields, err := OAuthSigninSessionFields(record)
	if err != nil {
		t.Fatal("map provider session", err)
	}
	operation := identity.FeatureOperation{Owner: "identity/oauth", OperationID: binding.OperationID, SchemaID: binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{21}, 32)))
	return identity.FeatureCommandSpec{Binding: binding, Operation: operation, Fields: fields}, record, cookie
}

func TestOAuthSigninMappingPreservesCompleteOriginalSession(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		spec, original, cookie := oauthSigninMappingFixture(t, csrf)
		spec.Fields = append(spec.Fields, identity.FeatureField{Name: "oauth.native-intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "native-owner"}})
		command, err := identity.NewFeaturePreAuthCommand(spec, cookie)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := OAuthSigninSession(command)
		if err != nil {
			t.Fatal("restore original provider session", err)
		}
		want, _, _ := encodeRecord(original)
		got, _, _ := encodeRecord(restored)
		if !bytes.Equal(want, got) {
			t.Fatal("provider credential, factor fence, Remember or CSRF changed")
		}
		feature, _ := command.Feature()
		if feature.Binding != spec.Binding {
			t.Fatal("selected user replaced original anonymous command scope")
		}
		for index := range spec.Fields[:len(spec.Fields)-1] {
			changed := spec
			changed.Fields = append([]identity.FeatureField{}, spec.Fields[:index]...)
			changed.Fields = append(changed.Fields, spec.Fields[index+1:]...)
			missing, err := identity.NewFeaturePreAuthCommand(changed, cookie)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OAuthSigninSession(missing); err == nil {
				t.Fatalf("omitted original field %s accepted", spec.Fields[index].Name)
			}
			changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
			changed.Fields[index].Value = identity.FeatureValue{Kind: identity.FeatureBool}
			if spec.Fields[index].Value.Kind == identity.FeatureBool {
				changed.Fields[index].Value = identity.FeatureValue{Kind: identity.FeatureText}
			}
			wrongKind, err := identity.NewFeaturePreAuthCommand(changed, cookie)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OAuthSigninSession(wrongKind); err == nil {
				t.Fatalf("wrong original field kind %s accepted", spec.Fields[index].Name)
			}
		}
	}
}

func TestOAuthSigninMappingRejectsOtherCustodyAndProfiles(t *testing.T) {
	spec, original, cookie := oauthSigninMappingFixture(t, true)
	plain, _ := identity.NewFeatureCommand(spec)
	bearer, _ := identity.NewFeatureSessionCommand(spec, cookie)
	code, _ := auth.NewOneTimeCode("123456")
	otp, _ := identity.NewFeatureOneTimeCodePreAuthCommand(spec, code, cookie)
	for _, command := range []identity.Command{{}, plain, bearer, otp} {
		if got, err := OAuthSigninSession(command); !errors.Is(err, session.ErrInvalidSessionCommand) || got != (session.Session{}) {
			t.Fatal("foreign OAuth custody admitted", err)
		}
	}
	for _, change := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.Authentication.Proof.Method = "password" },
		func(s *session.SessionSpec) { s.Authentication.Proof.Purpose = "reauthenticate" },
		func(s *session.SessionSpec) {
			v, _ := s.Authority.Bindings()
			v.Factor = session.OptionalAuthorityBinding{}
			s.Authority, _ = session.NewAuthoritySnapshot(v)
		},
	} {
		projection, _ := original.Bindings()
		change(&projection)
		record, err := session.NewSession(projection)
		if err != nil {
			t.Fatal("structural changed-profile control", err)
		}
		if _, err := OAuthSigninSessionFields(record); err == nil {
			t.Fatal("unselected provider session profile mapped")
		}
	}
}
