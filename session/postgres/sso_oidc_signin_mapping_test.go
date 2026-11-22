package postgres

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestSSOOIDCSigninMappingRetainsOrganizationAndOriginalBrowser(t *testing.T) {
	commandSpec, social, cookie := oauthSigninMappingFixture(t, true)
	spec, _ := social.Bindings()
	vector, _ := spec.Authority.Bindings()
	vector.ActiveOrganizationID = "org-selected"
	vector.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:tenant-a:org-selected", Version: 27}}
	var err error
	spec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication.Proof.Method = "sso-oidc"
	want, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	start, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	commandSpec.Operation = identity.FeatureOperation{Owner: "sso/oidc", OperationID: "identity.sso.oidc-callback", SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	commandSpec.Binding.OperationID, commandSpec.Binding.SchemaID = commandSpec.Operation.OperationID, commandSpec.Operation.SchemaID
	commandSpec.Binding.RecordID = string(start)
	commandSpec.Fields, err = SSOOIDCSigninSessionFields(want)
	if err != nil {
		t.Fatal(err)
	}
	commandSpec.Fields = append(commandSpec.Fields, identity.FeatureField{Name: "sso.oidc.callback-input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: make([]byte, 32)}})
	command, err := identity.NewFeaturePreAuthCommand(commandSpec, cookie)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SSOOIDCSigninSession(command)
	if err != nil {
		t.Fatal(err)
	}
	wantWire, _, _ := encodeRecord(want)
	gotWire, _, _ := encodeRecord(got)
	if !bytes.Equal(gotWire, wantWire) {
		t.Fatal("native mapping lost the original organization, factor fence, Remember, or CSRF state")
	}
	feature, _ := command.Feature()
	if feature.Binding.UserID != "" || feature.Binding.ActorKind != authorization.SubjectServiceAccount || feature.Binding.RecordID != string(start) {
		t.Fatal("mapping retargeted the original anonymous callback")
	}
	if _, err := OAuthSigninSession(command); err == nil {
		t.Fatal("enterprise command accepted by social OAuth")
	}
	if _, err := SSOOIDCSigninSessionFields(social); err == nil {
		t.Fatal("social session mapped to enterprise")
	}
	plain, _ := identity.NewFeatureCommand(commandSpec)
	if _, err := SSOOIDCSigninSession(plain); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("metadata without original browser custody admitted", err)
	}
	commandSpec.Binding.RecordID = string(commandSpec.Binding.CommandID)
	sameRecord, err := identity.NewFeaturePreAuthCommand(commandSpec, cookie)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SSOOIDCSigninSession(sameRecord); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("callback substituted its own ID for the original start", err)
	}
	commandSpec.Binding.RecordID = string(start)
	for i, field := range commandSpec.Fields {
		if !strings.HasSuffix(field.Name, ".authority.organization.version") {
			continue
		}
		commandSpec.Fields = append(commandSpec.Fields[:i:i], commandSpec.Fields[i+1:]...)
		missing, err := identity.NewFeaturePreAuthCommand(commandSpec, cookie)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := SSOOIDCSigninSession(missing); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("incomplete organization binding decoded", err)
		}
		return
	}
	t.Fatal("mapped fields lacked organization authority")
}
