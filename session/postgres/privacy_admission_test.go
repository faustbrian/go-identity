package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func privacySessionFixture(t *testing.T) (session.Session, identity.PrivacyExportRequestCommand, PrivacyExportAdmissionConfig) {
	t.Helper()
	record, original, profile := identifierSessionFixture(t)
	return record, identity.PrivacyExportRequestCommand{Binding: original.Binding, SessionID: original.SessionID, SessionVersion: original.SessionVersion, ExpectedAuthorityVersion: 5}, PrivacyExportAdmissionConfig(profile)
}

func TestPrivacySessionBindsOriginalUserAuthority(t *testing.T) {
	record, command, profile := privacySessionFixture(t)
	directory, credential, policy, err := privacySessionBindings(profile, record, command)
	if err != nil || directory.GlobalVersion != 1 || directory.TenantVersion != 2 || credential.UserAuthorityVersion != 5 || credential.IdentifierAuthorityVersion != 6 || credential.CredentialAuthorityVersion != 7 || credential.Credential.ID != "password-a" || credential.Credential.Version != 9 || policy.Version != 8 {
		t.Fatal("original owner authorities not preserved", err)
	}
	for _, change := range []func(*identity.PrivacyExportRequestCommand){
		func(c *identity.PrivacyExportRequestCommand) { c.ExpectedAuthorityVersion = 6 },
		func(c *identity.PrivacyExportRequestCommand) { c.ExpectedAuthorityVersion = 0 },
		func(c *identity.PrivacyExportRequestCommand) { c.Binding.TenantID = "other" },
		func(c *identity.PrivacyExportRequestCommand) { c.Binding.UserID = "other" },
		func(c *identity.PrivacyExportRequestCommand) { c.Binding.ActorID = "other" },
		func(c *identity.PrivacyExportRequestCommand) { c.Binding.ActorKind = "workload" },
		func(c *identity.PrivacyExportRequestCommand) { c.SessionID = "other" },
		func(c *identity.PrivacyExportRequestCommand) { c.SessionVersion++ },
	} {
		other := command
		change(&other)
		var denied identity.ForbiddenError
		if _, _, _, err := privacySessionBindings(profile, record, other); !errors.As(err, &denied) {
			t.Fatal("foreign/stale authority admitted", err)
		}
	}
	if _, _, _, err := privacySessionBindings(profile, session.Session{}, command); err == nil {
		t.Fatal("zero session")
	}
	var _ kernel.PrivacyExportAdmissionContributor = (*Repository)(nil)
	if err := (&Repository{}).CheckPrivacyExport(context.Background(), kernel.PrivacyExportAdmissionWork{}); err == nil {
		t.Fatal("zero invocation")
	}
}

func TestPrivacySessionConfigurationFailsClosedAndRedacts(t *testing.T) {
	_, _, profile := privacySessionFixture(t)
	for _, change := range []func(*PrivacyExportAdmissionConfig){
		func(c *PrivacyExportAdmissionConfig) { c.GlobalAuthorityID = "" },
		func(c *PrivacyExportAdmissionConfig) { c.PolicyNamespace = "" },
		func(c *PrivacyExportAdmissionConfig) { c.Audience = "has space" },
		func(c *PrivacyExportAdmissionConfig) { c.AuthenticationMethod = "" },
		func(c *PrivacyExportAdmissionConfig) { c.CredentialOwner = "" },
		func(c *PrivacyExportAdmissionConfig) { c.CredentialKind = identity.CredentialKind(255) },
	} {
		other := profile
		change(&other)
		if IdentifierAdmissionConfig(other).valid() {
			t.Fatal("invalid profile accepted")
		}
		if r, err := NewRepositoryWithPrivacyExportAdmission(nil, Config{}, other); err == nil || r != nil {
			t.Fatal("invalid constructor")
		}
	}
	if r, err := NewRepositoryWithPrivacyExportAdmission(nil, Config{}, profile); err == nil || r != nil {
		t.Fatal("invalid primary pool")
	}
	if fmt.Sprintf("%#v", profile) != "postgres.PrivacyExportAdmissionConfig(redacted)" {
		t.Fatal("configuration disclosure")
	}
	if out, err := json.Marshal(profile); err == nil || len(out) != 0 {
		t.Fatal("configuration exported")
	}
}

func TestPrivacySessionRejectsForeignKeysAndUnsupportedOwners(t *testing.T) {
	record, command, profile := privacySessionFixture(t)
	original, _ := record.Bindings()
	for _, dimension := range []string{"global", "tenant", "user", "identifier", "credential", "family", "session", "authorization", "organization", "factor", "passkey", "method", "audience"} {
		t.Run(dimension, func(t *testing.T) {
			spec := original
			a, _ := spec.Authority.Bindings()
			switch dimension {
			case "global":
				a.Global.ScopeKey = "foreign"
			case "tenant":
				a.Tenant.ScopeKey = "foreign"
			case "user":
				a.User.ScopeKey = "foreign"
			case "identifier":
				a.Identifier.ScopeKey = "foreign"
			case "credential":
				a.Credential.ScopeKey = "foreign"
			case "family":
				a.SessionFamily.ScopeKey = "foreign"
			case "session":
				a.Session.ScopeKey = "foreign"
			case "authorization":
				a.Authorization.ScopeKey = "foreign"
			case "organization":
				a.ActiveOrganizationID = "org"
				a.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "org", Version: 1}}
			case "factor":
				a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor", Version: 1}}
			case "passkey":
				a.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey", Version: 1}}
			case "method":
				spec.Authentication.Proof.Method = "other"
			case "audience":
				spec.Audience = "other"
				spec.Authentication.Proof.Audience = "other"
			}
			var err error
			spec.Authority, err = session.NewAuthoritySnapshot(a)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := session.NewSession(spec)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := privacySessionBindings(profile, changed, command); err == nil {
				t.Fatal("required owner omitted")
			}
		})
	}
	after, _ := record.Bindings()
	beforeAuthority, _ := original.Authority.Bindings()
	afterAuthority, _ := after.Authority.Bindings()
	if after.Authentication != original.Authentication || afterAuthority != beforeAuthority {
		t.Fatal("original evidence rewritten")
	}
}
