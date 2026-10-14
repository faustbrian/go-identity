package identity

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func unlinkState(t *testing.T) (AccountUnlinkState, AccountUnlinkChange) {
	t.Helper()
	a := accessFixture(t)
	s := AccountUnlinkState{Access: a, AccountID: "account-a", SocialLinkVersion: 3, CredentialVersion: 5}
	c := AccountUnlinkChange{TenantID: a.User.TenantID, UserID: a.User.ID, AccountID: "account-a", ExpectedUserVersion: a.User.Version, ExpectedAccountVersion: 1, ExpectedSocialLinkVersion: 3, ExpectedCredentialVersion: 5}
	return s, c
}

func TestAccountUnlinkTransitionRemovesLinkCredentialsAndAdvancesAuthority(t *testing.T) {
	s, c := unlinkState(t)
	before := accessFixture(t)
	m, err := ApplyAccountUnlink(s, c, queryClock{}.Now())
	if err != nil || len(m.Access.Accounts) != 0 || len(m.Access.Methods) != 1 || m.Access.Methods[0].Credential.Kind != CredentialPassword || m.Access.User.Version != before.User.Version+1 || m.TombstoneVersion != 2 || m.SocialLinkVersion != 4 || m.CredentialVersion != 6 || !m.InvalidatesCredential || m.Removed != before.Accounts[0] {
		t.Fatal("unlink did not remove exact authority with next versions")
	}
	if !reflect.DeepEqual(s.Access, before) {
		t.Fatal("transition mutated locked input")
	}
	m.Access.Methods[0].Credential.ID = "changed"
	if s.Access.Methods[1].Credential.ID == "changed" {
		t.Fatal("next state aliases locked input")
	}
}

func TestAccountUnlinkTransitionRefusesStaleVersionInEveryDimension(t *testing.T) {
	for _, change := range []func(*AccountUnlinkChange){
		func(c *AccountUnlinkChange) { c.ExpectedUserVersion++ },
		func(c *AccountUnlinkChange) { c.ExpectedAccountVersion++ },
		func(c *AccountUnlinkChange) { c.ExpectedSocialLinkVersion++ },
		func(c *AccountUnlinkChange) { c.ExpectedCredentialVersion++ },
	} {
		s, c := unlinkState(t)
		change(&c)
		m, err := ApplyAccountUnlink(s, c, queryClock{}.Now())
		var conflict ConflictError
		if !errors.As(err, &conflict) || !reflect.DeepEqual(m, AccountUnlinkMutation{}) {
			t.Fatal("stale authority produced a transition")
		}
	}
}

func TestAccountUnlinkTransitionRechecksAccessRatherThanAcceptingEarlierPlan(t *testing.T) {
	s, c := unlinkState(t)
	if _, err := CheckAccountUnlink(s.Access, c.TenantID, c.UserID, c.AccountID, 1, queryClock{}.Now()); err != nil {
		t.Fatal(err)
	}
	s.Access.Methods[1].Usable = false
	m, err := ApplyAccountUnlink(s, c, queryClock{}.Now())
	var final FinalAccessError
	if !errors.As(err, &final) || !reflect.DeepEqual(m, AccountUnlinkMutation{}) {
		t.Fatal("stale eligibility plan orphaned access")
	}
}

func TestAccountUnlinkTransitionDataOnlyLinkPreservesCredentialVersion(t *testing.T) {
	s, c := unlinkState(t)
	s.Access.Methods = s.Access.Methods[1:]
	m, err := ApplyAccountUnlink(s, c, queryClock{}.Now())
	if err != nil || m.InvalidatesCredential || m.CredentialVersion != 5 || m.SocialLinkVersion != 4 || m.TombstoneVersion != 2 {
		t.Fatal("data-only unlink changed credential authority")
	}
}

func TestAccountUnlinkTransitionRejectsWrongScopeAndOverflow(t *testing.T) {
	for _, change := range []func(*AccountUnlinkState, *AccountUnlinkChange){
		func(s *AccountUnlinkState, c *AccountUnlinkChange) { c.TenantID = "foreign" },
		func(s *AccountUnlinkState, c *AccountUnlinkChange) { c.UserID = "foreign" },
		func(s *AccountUnlinkState, c *AccountUnlinkChange) { s.AccountID = "foreign" },
		func(s *AccountUnlinkState, c *AccountUnlinkChange) { s.CredentialVersion = 0 },
		func(s *AccountUnlinkState, c *AccountUnlinkChange) { s.SocialLinkVersion = 0 },
		func(s *AccountUnlinkState, c *AccountUnlinkChange) { c.ExpectedUserVersion = 0 },
		func(s *AccountUnlinkState, c *AccountUnlinkChange) { c.ExpectedCredentialVersion = 0 },
		func(s *AccountUnlinkState, c *AccountUnlinkChange) { c.ExpectedSocialLinkVersion = 0 },
		func(s *AccountUnlinkState, c *AccountUnlinkChange) {
			s.CredentialVersion = ^uint64(0)
			c.ExpectedCredentialVersion = ^uint64(0)
		},
		func(s *AccountUnlinkState, c *AccountUnlinkChange) {
			s.SocialLinkVersion = ^uint64(0)
			c.ExpectedSocialLinkVersion = ^uint64(0)
		},
	} {
		s, c := unlinkState(t)
		change(&s, &c)
		m, err := ApplyAccountUnlink(s, c, queryClock{}.Now())
		if err == nil || !reflect.DeepEqual(m, AccountUnlinkMutation{}) {
			t.Fatal("invalid scope/version produced mutation")
		}
	}
}

func TestAccountUnlinkTransitionsCannotEachRelyOnOtherRemovedProvider(t *testing.T) {
	s, c := unlinkState(t)
	s.Access.Methods = s.Access.Methods[:1]
	b := s.Access.Accounts[0]
	b.ID, b.Subject = "account-b", "subject-b"
	s.Access.Accounts = append(s.Access.Accounts, b)
	bm := s.Access.Methods[0]
	bm.AccountID, bm.Credential.ID = b.ID, "provider-b"
	s.Access.Methods = append(s.Access.Methods, bm)
	first, err := ApplyAccountUnlink(s, c, queryClock{}.Now())
	if err != nil || len(first.Access.Methods) != 1 || first.Access.Methods[0].AccountID != b.ID {
		t.Fatal("first removal failed to conserve independent provider")
	}
	second := AccountUnlinkState{Access: first.Access, AccountID: b.ID, SocialLinkVersion: 1, CredentialVersion: first.CredentialVersion}
	c.AccountID, c.ExpectedUserVersion, c.ExpectedSocialLinkVersion, c.ExpectedCredentialVersion = b.ID, first.Access.User.Version, 1, first.CredentialVersion
	got, err := ApplyAccountUnlink(second, c, queryClock{}.Now())
	var final FinalAccessError
	if !errors.As(err, &final) || !reflect.DeepEqual(got, AccountUnlinkMutation{}) {
		t.Fatal("successive removals orphaned user")
	}
}

func TestAccountUnlinkTransitionDiagnosticsWithholdPrimaryState(t *testing.T) {
	s, c := unlinkState(t)
	m, err := ApplyAccountUnlink(s, c, queryClock{}.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{s, m} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
			text := fmt.Sprintf(verb, value)
			if !strings.Contains(text, "redacted") || strings.Contains(text, "subject-a") || strings.Contains(text, "password-credential") || strings.Contains(text, "https://issuer.example") {
				t.Fatal("primary unlink state appeared in diagnostics")
			}
		}
	}
}
