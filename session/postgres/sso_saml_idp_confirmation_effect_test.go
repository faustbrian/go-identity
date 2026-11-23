package postgres

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestSSOSAMLIDPConfirmationSessionRetainsOriginalLinkedUserAndPair(t *testing.T) {
	feature, record, _ := oauthSigninMappingFixture(t, true)
	spec, _ := record.Bindings()
	authority, _ := spec.Authority.Bindings()
	authority.ActiveOrganizationID = "org-selected"
	authority.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:tenant-a:org-selected", Version: 27}}
	var err error
	spec.Authority, err = session.NewAuthoritySnapshot(authority)
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication.Proof.Method = "sso-saml"
	record, err = session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	arrival, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	feature.Operation = kernel.SSOSAMLIDPConfirmationOperation()
	feature.Binding.OperationID, feature.Binding.SchemaID = feature.Operation.OperationID, feature.Operation.SchemaID
	feature.Binding.RecordID, feature.Binding.UserID, feature.Binding.AnonymousFlowID = string(arrival), spec.UserID, ""
	feature.Fields, err = SSOSAMLIDPConfirmationSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	paired := func(f identity.FeatureCommandSpec) identity.Command {
		t.Helper()
		c, err := identity.NewFeatureSAMLIDPConfirmationCommand(f,
			authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))),
			authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cmd := paired(feature)
	got, err := SSOSAMLIDPConfirmationSession(cmd)
	gotWire, _, _ := encodeRecord(got)
	wantWire, _, _ := encodeRecord(record)
	if err != nil || len(wantWire) == 0 || !bytes.Equal(gotWire, wantWire) {
		t.Fatal("did not reconstruct the original enterprise session", err)
	}
	if _, err := SSOSAMLSigninSession(cmd); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("SP accepted unsolicited session fields", err)
	}
	plain, err := identity.NewFeatureCommand(feature)
	if err != nil {
		t.Fatal(err)
	}
	wrongUser := feature
	wrongUser.Binding.UserID = "other-linked-user"
	spFields, err := SSOSAMLSigninSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	mixed := feature
	mixed.Fields = append(append([]identity.FeatureField(nil), feature.Fields...), spFields[0])
	for _, c := range []identity.Command{plain, paired(wrongUser), paired(mixed)} {
		if _, err := SSOSAMLIDPConfirmationSession(c); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("generic custody, wrong user or mixed fields admitted", err)
		}
	}
}
