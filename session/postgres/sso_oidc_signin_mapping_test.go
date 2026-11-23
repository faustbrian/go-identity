package postgres

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestSSOOIDCSigninMappingRetainsOrganizationAndOriginalBrowser(t *testing.T) {
	testSSOSigninMapping(t, ssoOIDCSessionOperation(), "sso-oidc", SSOOIDCSigninSessionFields, SSOOIDCSigninSession)
}

func TestSSOOAuth2SigninMappingRetainsOrganizationAndOriginalBrowser(t *testing.T) {
	testSSOSigninMapping(t, ssoOAuth2SessionOperation(), "sso-oauth2", SSOOAuth2SigninSessionFields, SSOOAuth2SigninSession)
}

func TestSSOSAMLSigninMappingRetainsOrganizationAndOriginalBrowser(t *testing.T) {
	testSSOSigninMapping(t, kernel.SSOSAMLSigninOperation(), "sso-saml", SSOSAMLSigninSessionFields, SSOSAMLSigninSession)
}

func testSSOSigninMapping(t *testing.T, operation identity.FeatureOperation, method string,
	fields func(session.Session) ([]identity.FeatureField, error), parse func(identity.Command) (session.Session, error),
) {
	t.Helper()
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
	spec.Authentication.Proof.Method = method
	want, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	start, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	commandSpec.Operation = operation
	commandSpec.Binding.ActorID = "native-sso-service"
	commandSpec.Binding.OperationID, commandSpec.Binding.SchemaID = commandSpec.Operation.OperationID, commandSpec.Operation.SchemaID
	commandSpec.Binding.RecordID = string(start)
	commandSpec.Fields, err = fields(want)
	if err != nil {
		t.Fatal(err)
	}
	callbackPrefix := strings.ReplaceAll(method, "-", ".")
	commandSpec.Fields = append(commandSpec.Fields, identity.FeatureField{Name: callbackPrefix + ".callback-input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: make([]byte, 32)}})
	command, err := identity.NewFeaturePreAuthCommand(commandSpec, cookie)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parse(command)
	if err != nil {
		t.Fatal(err)
	}
	wantWire, _, _ := encodeRecord(want)
	gotWire, _, _ := encodeRecord(got)
	if !bytes.Equal(gotWire, wantWire) {
		t.Fatal("native mapping lost the original organization, factor fence, Remember, or CSRF state")
	}
	feature, _ := command.Feature()
	if feature.Operation != operation || feature.Binding.UserID != "" || feature.Binding.ActorID != "native-sso-service" || feature.Binding.ActorKind != authorization.SubjectServiceAccount || feature.Binding.AnonymousFlowID != commandSpec.Binding.AnonymousFlowID || feature.Binding.RecordID != string(start) {
		t.Fatal("mapping retargeted the original anonymous callback")
	}
	if _, err := OAuthSigninSession(command); err == nil {
		t.Fatal("enterprise command accepted by social OAuth")
	}
	if _, err := fields(social); err == nil {
		t.Fatal("social session mapped to enterprise")
	}
	for _, foreign := range []struct {
		method, prefix string
		fields         func(session.Session) ([]identity.FeatureField, error)
		parse          func(identity.Command) (session.Session, error)
	}{
		{"sso-oidc", ssoOIDCSessionPrefix, SSOOIDCSigninSessionFields, SSOOIDCSigninSession},
		{"sso-oauth2", ssoOAuth2SessionPrefix, SSOOAuth2SigninSessionFields, SSOOAuth2SigninSession},
		{"sso-saml", ssoSAMLSessionPrefix, SSOSAMLSigninSessionFields, SSOSAMLSigninSession},
	} {
		if foreign.method == method {
			continue
		}
		t.Run("reject-"+foreign.method, func(t *testing.T) {
			if _, err := foreign.parse(command); !errors.Is(err, session.ErrInvalidSessionCommand) {
				t.Fatal("enterprise command accepted by another protocol", err)
			}
			if _, err := foreign.fields(want); !errors.Is(err, session.ErrInvalidSessionCommand) {
				t.Fatal("enterprise record mapped to another protocol", err)
			}
			mixedSpec := commandSpec
			mixedSpec.Fields = append(mixedSpec.Fields[:len(mixedSpec.Fields):len(mixedSpec.Fields)], identity.FeatureField{Name: foreign.prefix + "tenant.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(spec.TenantID)}})
			mixed, err := identity.NewFeaturePreAuthCommand(mixedSpec, cookie)
			if err != nil {
				t.Fatal("construct otherwise-valid mixed protocol command", err)
			}
			if _, err := parse(mixed); !errors.Is(err, session.ErrInvalidSessionCommand) {
				t.Fatal("mixed enterprise session fields admitted", err)
			}
		})
	}
	plain, _ := identity.NewFeatureCommand(commandSpec)
	if _, err := parse(plain); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("metadata without original browser custody admitted", err)
	}
	commandSpec.Binding.RecordID = string(commandSpec.Binding.CommandID)
	sameRecord, err := identity.NewFeaturePreAuthCommand(commandSpec, cookie)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(sameRecord); !errors.Is(err, session.ErrInvalidSessionCommand) {
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
		if _, err := parse(missing); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("incomplete organization binding decoded", err)
		}
		return
	}
	t.Fatal("mapped fields lacked organization authority")
}
