package identity_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func samlIDPConfirmationSpec(t *testing.T) identity.FeatureCommandSpec {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	operation := identity.FeatureOperation{
		Owner: "sso/saml", OperationID: "identity.sso.saml-idp-init", SchemaID: "sso-enterprise-saml-idp-init-v1",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser,
	}
	return identity.FeatureCommandSpec{Operation: operation, Binding: identity.CommandBinding{
		CommandID: id, TenantID: "tenant", UserID: "linked-user", ActorID: "native-saml",
		ActorKind: authorization.SubjectServiceAccount, OperationID: operation.OperationID,
		PolicyID: "saml-confirm", PolicyVersion: 1, SchemaID: operation.SchemaID,
		SchemaVersion: operation.SchemaVersion, CorrelationID: "request", RecordID: "pending-confirmation",
	}}
}

func confirmationFixtureWire(n int, marker byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{marker}, n))
}

func TestFeatureSAMLIDPConfirmationRetainsOnlyExplicitJointCustody(t *testing.T) {
	spec := samlIDPConfirmationSpec(t)
	cookie, form := confirmationFixtureWire(32, 1), confirmationFixtureWire(32, 2)
	command, err := identity.NewFeatureSAMLIDPConfirmationCommand(spec, auth.NewBearerCredential(cookie), auth.NewBearerCredential(form))
	if err != nil {
		t.Fatal(err)
	}
	gotCookie, gotForm, ok := command.SAMLIDPConfirmationCustody()
	if !ok || gotCookie.Token() != cookie || gotForm.Token() != form {
		t.Fatal("joint submitted custody changed")
	}
	got, ok := command.SAMLIDPConfirmationFeature()
	if !ok || got.Operation != spec.Operation || got.Binding != spec.Binding || len(got.Fields) != 0 {
		t.Fatal("exact record/subject projection did not survive")
	}
	_, ordinary := command.Feature()
	_, preauth := command.PreAuthCookie()
	_, otp := command.OneTimeCode()
	_, session := command.SessionToken()
	if ordinary || preauth || otp || session {
		t.Fatal("partial or legacy accessor admitted joint confirmation")
	}
	metadataOnly, err := identity.NewFeatureCommand(got)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := metadataOnly.SAMLIDPConfirmationCustody(); ok {
		t.Fatal("metadata reconstructed submitted possession")
	}
	if _, ok := metadataOnly.SAMLIDPConfirmationFeature(); ok {
		t.Fatal("metadata-only command matched the typed variant")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
		formatted := fmt.Sprintf(format, command)
		if strings.Contains(formatted, cookie) || strings.Contains(formatted, form) {
			t.Fatal("command format disclosed confirmation credentials")
		}
	}
	if _, err := json.Marshal(command); err == nil {
		t.Fatal("command serialized")
	}
}

func TestFeatureSAMLIDPConfirmationDeniesWrongScopeAndMalformedCustody(t *testing.T) {
	spec := samlIDPConfirmationSpec(t)
	cookie, form := confirmationFixtureWire(32, 1), confirmationFixtureWire(32, 2)
	reject := func(t *testing.T, s identity.FeatureCommandSpec, a, b string) {
		t.Helper()
		command, err := identity.NewFeatureSAMLIDPConfirmationCommand(s, auth.NewBearerCredential(a), auth.NewBearerCredential(b))
		if err == nil {
			t.Fatal("invalid confirmation input accepted")
		}
		if _, _, ok := command.SAMLIDPConfirmationCustody(); ok {
			t.Fatal("denied confirmation retained credentials")
		}
	}
	for _, bad := range []string{"", " " + cookie, cookie + "=", cookie[:42] + "B", confirmationFixtureWire(31, 1), confirmationFixtureWire(33, 1)} {
		reject(t, spec, bad, form)
		reject(t, spec, cookie, bad)
	}
	reject(t, spec, cookie, cookie)
	for name, mutate := range map[string]func(*identity.FeatureCommandSpec){
		"actor kind": func(s *identity.FeatureCommandSpec) { s.Binding.ActorKind = authorization.SubjectUser },
		"record":     func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "" },
		"owner":      func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "sso/oidc" },
		"schema":     func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion++; s.Binding.SchemaVersion++ },
		"anonymous": func(s *identity.FeatureCommandSpec) {
			s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
			s.Binding.UserID, s.Binding.AnonymousFlowID = "", "preceding-flow"
		},
		"sp callback": func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID, s.Binding.OperationID = "identity.sso.saml-acs", "identity.sso.saml-acs"
		},
	} {
		t.Run(name, func(t *testing.T) { changed := spec; mutate(&changed); reject(t, changed, cookie, form) })
	}
}
