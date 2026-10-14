package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication"
	authorization "github.com/faustbrian/go-authorization"
	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Bounded plan: independent scope-key bytes and ambiguity/foreign scope denial;
// bind original session ID/version/audience, credential linkage and all required
// authority keys; reject unsupported optional dimensions and metadata profiles.
// Successor comparison changes only the Work-owned identifier epoch.
func TestSessionAuthorityKeysAreOwnedAndFramed(t *testing.T) {
	keys, err := SessionAuthorityKeys("tenant-a", "user-a", "family-a", "session-a")
	if err != nil || keys.Family != "session_family:v1:zDcLaIn-nQMEhG1ZE1XlBxtrPDU29RIg8vJsdEvsNVc" || keys.Session != "session:v1:k0bKXVsqfs9CyClFuKUIpbbp012owRKfkx_MRpXpmPI" {
		t.Fatal("scope keys differ from independent golden bytes", err)
	}
	for _, ids := range [][4]string{{"tenant-b", "user-a", "family-a", "session-a"}, {"tenant-a", "other", "family-a", "session-a"}, {"tenant-a", "user-a", "other", "session-a"}} {
		other, e := SessionAuthorityKeys(identity.TenantID(ids[0]), identity.UserID(ids[1]), ids[2], ids[3])
		if e != nil || other.Family == keys.Family || other.Session == keys.Session {
			t.Fatal("foreign scope alias", e)
		}
	}
	other, _ := SessionAuthorityKeys("tenant-a", "user-a", "family-a", "other")
	if other.Family != keys.Family || other.Session == keys.Session {
		t.Fatal("session dimension ownership")
	}
	for _, bad := range []string{"", "has space", "\x7f", strings.Repeat("a", 129), "é"} {
		if k, e := SessionAuthorityKeys(identity.TenantID(bad), "user-a", "family-a", "session-a"); e == nil || k != (SessionAuthorityKeySet{}) {
			t.Fatal("invalid scope accepted")
		}
	}
	a, _ := SessionAuthorityKeys("a:b", "c", "d", "e")
	b, _ := SessionAuthorityKeys("a", "b:c", "d", "e")
	if a == b {
		t.Fatal("delimiter alias")
	}
	if fmt.Sprintf("%#v", keys) != "postgres.SessionAuthorityKeySet(redacted)" {
		t.Fatal("key disclosure")
	}
	if data, e := json.Marshal(keys); e == nil || len(data) != 0 {
		t.Fatal("key export")
	}
}

func identifierSessionFixture(t testing.TB) (session.Session, identity.IdentifierCommand, IdentifierAdmissionConfig) {
	t.Helper()
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment-a", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	spec, _ := testSession(t).Bindings()
	spec.Version, spec.FamilyVersion = 3, 4
	keys, e := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: spec.TenantID}, spec.UserID)
	if e != nil {
		t.Fatal(e)
	}
	sk, e := SessionAuthorityKeys(spec.TenantID, spec.UserID, spec.FamilyID, spec.SessionID)
	if e != nil {
		t.Fatal(e)
	}
	ak, e := (authority.AuthorityScope{TenantID: authorization.TenantID(spec.TenantID), PolicyNamespace: profile.PolicyNamespace, SubjectID: authorization.SubjectID(spec.UserID)}).Key()
	if e != nil {
		t.Fatal(e)
	}
	spec.Authority, e = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: session.AuthorityBinding{ScopeKey: keys.Global, Version: 1}, Tenant: session.AuthorityBinding{ScopeKey: keys.Tenant, Version: 2}, User: session.AuthorityBinding{ScopeKey: keys.User, Version: 5}, Identifier: session.AuthorityBinding{ScopeKey: keys.Identifier, Version: 6}, Credential: session.AuthorityBinding{ScopeKey: keys.Credential, Version: 7}, Session: session.AuthorityBinding{ScopeKey: sk.Session, Version: 3}, SessionFamily: session.AuthorityBinding{ScopeKey: sk.Family, Version: 4}, Authorization: session.AuthorityBinding{ScopeKey: ak, Version: 8}})
	if e != nil {
		t.Fatal(e)
	}
	spec.Authentication.Proof.Method = "password"
	spec.Authentication.CredentialID = "password-a"
	spec.Authentication.CredentialVersion = 9
	record, e := session.NewSession(spec)
	if e != nil {
		t.Fatal(e)
	}
	cmd := identity.IdentifierCommand{Binding: identity.CommandBinding{TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser}, SessionID: spec.SessionID, SessionVersion: spec.Version, Change: identity.IdentifierChange{TenantID: spec.TenantID, UserID: spec.UserID, ExpectedAuthorityVersion: 6}}
	return record, cmd, profile
}

func TestIdentifierSessionBindsOriginalAndOwnedEpoch(t *testing.T) {
	record, cmd, profile := identifierSessionFixture(t)
	for _, final := range []bool{false, true} {
		epoch := uint64(6)
		if final {
			epoch++
		}
		d, c, a, e := identifierSessionBindings(profile, record, cmd, epoch, final)
		if e != nil || d.GlobalVersion != 1 || d.TenantVersion != 2 || c.UserAuthorityVersion != 5 || c.IdentifierAuthorityVersion != epoch || c.CredentialAuthorityVersion != 7 || c.Credential.ID != "password-a" || c.Credential.Version != 9 || c.Credential.Owner != "identity/password" || a.Version != 8 {
			t.Fatal("authority forwarding", e)
		}
	}
	spec, _ := record.Bindings()
	for name, change := range map[string]func(*session.SessionSpec){
		"audience": func(s *session.SessionSpec) { s.Audience = "other"; s.Authentication.Proof.Audience = "other" },
		"method":   func(s *session.SessionSpec) { s.Authentication.Proof.Method = "passkey" },
		"anonymous": func(s *session.SessionSpec) {
			s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: s.IssuedAt}
		},
		"organization": func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.ActiveOrganizationID = "org"
			a.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "org", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
		"factor": func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
		"passkey": func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := spec
			change(&s)
			other, e := session.NewSession(s)
			if e != nil {
				t.Fatal("invalid test input", e)
			}
			if _, _, _, e = identifierSessionBindings(profile, other, cmd, 6, false); e == nil {
				t.Fatal("foreign or unsupported record admitted")
			}
		})
	}
	for _, change := range []func(*identity.IdentifierCommand){func(c *identity.IdentifierCommand) { c.SessionID = "other" }, func(c *identity.IdentifierCommand) { c.SessionVersion++ }, func(c *identity.IdentifierCommand) { c.Binding.UserID = "other" }, func(c *identity.IdentifierCommand) { c.Binding.ActorID = "other" }, func(c *identity.IdentifierCommand) { c.Binding.TenantID = "other" }, func(c *identity.IdentifierCommand) { c.Change.ExpectedAuthorityVersion++ }} {
		c := cmd
		change(&c)
		if _, _, _, e := identifierSessionBindings(profile, record, c, 6, false); e == nil {
			t.Fatal("changed command admitted")
		}
	}
	for _, epoch := range []uint64{0, 5, 7, 8} {
		if _, _, _, e := identifierSessionBindings(profile, record, cmd, epoch, false); e == nil {
			t.Fatal("unowned initial epoch")
		}
	}
	for _, epoch := range []uint64{0, 5, 6, 8} {
		if _, _, _, e := identifierSessionBindings(profile, record, cmd, epoch, true); e == nil {
			t.Fatal("unowned final epoch")
		}
	}
	if _, _, _, e := identifierSessionBindings(profile, session.Session{}, cmd, 6, false); e == nil {
		t.Fatal("zero record")
	}
	var _ kernel.IdentifierAdmissionContributor = (*Repository)(nil)
	if e := (&Repository{}).CheckIdentifier(context.Background(), kernel.IdentifierAdmissionWork{}); e == nil {
		t.Fatal("zero invocation")
	}
}

func TestIdentifierSessionRejectsEveryForeignAuthorityKey(t *testing.T) {
	record, cmd, profile := identifierSessionFixture(t)
	spec, _ := record.Bindings()
	for _, name := range []string{"global", "tenant", "user", "identifier", "credential", "family", "session", "authorization"} {
		t.Run(name, func(t *testing.T) {
			s := spec
			a, _ := s.Authority.Bindings()
			switch name {
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
			}
			var e error
			s.Authority, e = session.NewAuthoritySnapshot(a)
			if e != nil {
				t.Fatal(e)
			}
			other, e := session.NewSession(s)
			if e != nil {
				t.Fatal(e)
			}
			if _, _, _, e = identifierSessionBindings(profile, other, cmd, 6, false); e == nil {
				t.Fatal("scope key not compared")
			}
		})
	}
}

func TestIdentifierAdmissionConfigurationAndUnsupportedCredential(t *testing.T) {
	record, cmd, profile := identifierSessionFixture(t)
	if !profile.valid() {
		t.Fatal("valid profile denied")
	}
	for _, alter := range []func(*IdentifierAdmissionConfig){func(c *IdentifierAdmissionConfig) { c.GlobalAuthorityID = "" }, func(c *IdentifierAdmissionConfig) { c.PolicyNamespace = "" }, func(c *IdentifierAdmissionConfig) { c.Audience = strings.Repeat("x", 257) }, func(c *IdentifierAdmissionConfig) { c.AuthenticationMethod = "bad method" }, func(c *IdentifierAdmissionConfig) { c.CredentialOwner = "other" }, func(c *IdentifierAdmissionConfig) { c.CredentialKind = 0 }} {
		c := profile
		alter(&c)
		if c.valid() {
			t.Fatal("bad config accepted")
		}
		if r, e := NewRepositoryWithIdentifierAdmission(nil, Config{}, c); e == nil || r != nil {
			t.Fatal("invalid public construction")
		}
	}
	if r, e := NewRepositoryWithIdentifierAdmission(nil, Config{}, profile); e == nil || r != nil {
		t.Fatal("missing pool admitted")
	}
	// Dropping the optional passkey dimension cannot admit a passkey profile.
	profile.CredentialKind = identity.CredentialPasskey
	profile.CredentialOwner = "passkey"
	if _, _, _, e := identifierSessionBindings(profile, record, cmd, 6, false); e == nil {
		t.Fatal("unsupported passkey owner admitted")
	}
	spec, _ := record.Bindings()
	spec.Authentication.Proof.Assurance = authentication.AssuranceMultiFactor
	other, e := session.NewSession(spec)
	if e != nil {
		t.Fatal(e)
	}
	_, _, originalProfile := identifierSessionFixture(t)
	if _, _, _, e = identifierSessionBindings(originalProfile, other, cmd, 6, false); e == nil {
		t.Fatal("multifactor metadata without factor owner admitted")
	}
}
