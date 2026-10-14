package postgres

import (
	"errors"
	"testing"

	authority "github.com/faustbrian/go-authorization/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestMagicLinkReaderDerivesExactOwnerScopesAndRejectsOtherMethods(t *testing.T) {
	c := MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}
	record := magicLinkRecordFixture(t, true)
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: s.TenantID}, s.UserID)
	sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	pk, _ := (authority.AuthorityScope{TenantID: "tenant-a", PolicyNamespace: "users", SubjectID: "user-a"}).Key()
	a.Global.ScopeKey, a.Tenant.ScopeKey, a.User.ScopeKey, a.Identifier.ScopeKey, a.Credential.ScopeKey = keys.Global, keys.Tenant, keys.User, keys.Identifier, keys.Credential
	a.SessionFamily.ScopeKey, a.Session.ScopeKey, a.Authorization.ScopeKey = sk.Family, sk.Session, pk
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	record, err := session.NewSessionWithMagicLinkAndCSRF(s, record.MagicLinkAuthentication(), record.CSRFState())
	if err != nil {
		t.Fatal(err)
	}
	query, scope, err := magicLinkSessionAdmission(c, record)
	if err != nil || query.TenantID != s.TenantID || string(scope.SubjectID) != string(s.UserID) {
		t.Fatal("exact magic-link owners denied", err)
	}
	for _, change := range []func(*MagicLinkAdmissionConfig){func(c *MagicLinkAdmissionConfig) { c.GlobalAuthorityID = "foreign" }, func(c *MagicLinkAdmissionConfig) { c.PolicyNamespace = "foreign" }, func(c *MagicLinkAdmissionConfig) { c.Audience = "foreign" }, func(c *MagicLinkAdmissionConfig) { c.GlobalAuthorityID = "" }} {
		bad := c
		change(&bad)
		if _, _, err := magicLinkSessionAdmission(bad, record); !errors.Is(err, session.ErrUnauthenticated) {
			t.Fatal("foreign owner admitted", err)
		}
	}
	for _, other := range []session.Session{{}, testSession(t), otpRecordFixture(t, false)} {
		if _, _, err := magicLinkSessionAdmission(c, other); !errors.Is(err, session.ErrUnauthenticated) {
			t.Fatal("other method admitted", err)
		}
	}
	if got, err := NewMagicLinkSessionService(nil, MagicLinkSessionServiceConfig{}); got != nil || err == nil {
		t.Fatal("zero composition admitted")
	}
}
