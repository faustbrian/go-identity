package session_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func authoritySpec() session.AuthoritySnapshotSpec {
	return session.AuthoritySnapshotSpec{
		Global:        session.AuthorityBinding{ScopeKey: "global:deployment", Version: 1},
		Tenant:        session.AuthorityBinding{ScopeKey: "tenant:tenant-a", Version: 2},
		User:          session.AuthorityBinding{ScopeKey: "user:tenant-a:user-a", Version: 3},
		Identifier:    session.AuthorityBinding{ScopeKey: "identifier:tenant-a:user-a", Version: 4},
		Credential:    session.AuthorityBinding{ScopeKey: "credential:tenant-a:user-a", Version: 5},
		SessionFamily: session.AuthorityBinding{ScopeKey: "family:tenant-a:family-a", Version: 6},
		Session:       session.AuthorityBinding{ScopeKey: "session:tenant-a:session-a", Version: 7},
		Authorization: session.AuthorityBinding{ScopeKey: "authorization:tenant-a:user-a", Version: 8},
	}
}

func bindings(s *session.AuthoritySnapshotSpec) []*session.AuthorityBinding {
	return []*session.AuthorityBinding{&s.Global, &s.Tenant, &s.User, &s.Identifier, &s.Credential, &s.SessionFamily, &s.Session, &s.Authorization}
}

func TestAuthorityRejectsAnyMissingRequiredDimension(t *testing.T) {
	for i := range 8 {
		s := authoritySpec()
		*bindings(&s)[i] = session.AuthorityBinding{}
		if _, e := session.NewAuthoritySnapshot(s); !errors.Is(e, session.ErrInvalidAuthority) {
			t.Fatal("partial snapshot accepted")
		}
	}
	for _, key := range []string{"", string(make([]byte, 257)), "scope key", "scope\n", "é"} {
		s := authoritySpec()
		s.User.ScopeKey = key
		if _, e := session.NewAuthoritySnapshot(s); !errors.Is(e, session.ErrInvalidAuthority) {
			t.Fatal("invalid scope key accepted")
		}
	}
	s := authoritySpec()
	s.User.ScopeKey = s.Tenant.ScopeKey
	if _, e := session.NewAuthoritySnapshot(s); !errors.Is(e, session.ErrInvalidAuthority) {
		t.Fatal("dimension scope reuse accepted")
	}
	if _, e := (session.AuthoritySnapshot{}).Bindings(); !errors.Is(e, session.ErrInvalidAuthority) {
		t.Fatal("zero projection accepted")
	}
}

func TestCompleteAuthorityComparisonCannotRenewAStaleVersion(t *testing.T) {
	stored, e := session.NewAuthoritySnapshot(authoritySpec())
	if e != nil {
		t.Fatal(e)
	}
	equal, e := session.NewAuthoritySnapshot(authoritySpec())
	if e != nil {
		t.Fatal(e)
	}
	if e = stored.CompareCurrent(equal); e != nil {
		t.Fatal(e)
	}
	for i := range 8 {
		for _, change := range []func(*session.AuthorityBinding){
			func(b *session.AuthorityBinding) { b.Version++ },
			func(b *session.AuthorityBinding) { b.Version = 1 },
			func(b *session.AuthorityBinding) { b.ScopeKey += "-other" },
		} {
			s := authoritySpec()
			change(bindings(&s)[i])
			current, e := session.NewAuthoritySnapshot(s)
			if e != nil {
				t.Fatal(e)
			}
			// Version1 is unchanged only for the global dimension.
			if s == authoritySpec() {
				continue
			}
			if e = stored.CompareCurrent(current); !errors.Is(e, session.ErrAuthorityMismatch) {
				t.Fatal("changed authority accepted")
			}
			if e = current.CompareCurrent(stored); !errors.Is(e, session.ErrAuthorityMismatch) {
				t.Fatal("regressed authority accepted")
			}
		}
	}
	if e = stored.CompareCurrent(session.AuthoritySnapshot{}); !errors.Is(e, session.ErrInvalidAuthority) {
		t.Fatal("missing current authority accepted")
	}
	if e = (session.AuthoritySnapshot{}).CompareCurrent(stored); !errors.Is(e, session.ErrInvalidAuthority) {
		t.Fatal("zero stored authority accepted")
	}
	projection, e := stored.Bindings()
	if e != nil {
		t.Fatal(e)
	}
	projection.User.Version++
	retained, e := stored.Bindings()
	if e != nil || retained != authoritySpec() {
		t.Fatal("caller projection changed retained bindings")
	}
	if e = stored.CompareCurrent(equal); e != nil {
		t.Fatal("caller projection changed retained authority")
	}
	if fmt.Sprintf("%#v", stored) != "session.AuthoritySnapshot(redacted)" {
		t.Fatal("snapshot format exposed scope data")
	}
	if _, e = json.Marshal(stored); !errors.Is(e, session.ErrAuthoritySerialization) {
		t.Fatal("snapshot implicitly encoded")
	}
}

func FuzzAuthoritySnapshot(f *testing.F) {
	for _, key := range []string{"user:tenant-a:user-a", "", "tenant:tenant-a", "user\n", "é"} {
		f.Add(key, uint64(1))
	}
	f.Fuzz(func(t *testing.T, key string, version uint64) {
		s := authoritySpec()
		s.User = session.AuthorityBinding{ScopeKey: key, Version: version}
		snapshot, e := session.NewAuthoritySnapshot(s)
		if e != nil {
			if !errors.Is(e, session.ErrInvalidAuthority) {
				t.Fatal("unstable authority error")
			}
			return
		}
		got, e := snapshot.Bindings()
		if e != nil || got != s || snapshot.CompareCurrent(snapshot) != nil {
			t.Fatal("validated vector lost bindings")
		}
	})
}

func TestOptionalAuthorityIsExplicitAndCannotBeDowngraded(t *testing.T) {
	s := authoritySpec()
	s.ActiveOrganizationID = "01JTESTORGANIZATION"
	s.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:tenant-a:org-a", Version: 9}}
	s.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:tenant-a:user-a", Version: 10}}
	s.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:tenant-a:user-a", Version: 11}}
	stored, e := session.NewAuthoritySnapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*session.AuthoritySnapshotSpec){
		func(s *session.AuthoritySnapshotSpec) { s.ActiveOrganizationID = "other-org" },
		func(s *session.AuthoritySnapshotSpec) { s.Organization.Binding.Version++ },
		func(s *session.AuthoritySnapshotSpec) { s.Factor.Binding.Version++ },
		func(s *session.AuthoritySnapshotSpec) { s.Passkey.Binding.Version++ },
		func(s *session.AuthoritySnapshotSpec) {
			s.ActiveOrganizationID = ""
			s.Organization = session.OptionalAuthorityBinding{}
		},
		func(s *session.AuthoritySnapshotSpec) { s.Factor = session.OptionalAuthorityBinding{} },
		func(s *session.AuthoritySnapshotSpec) { s.Passkey = session.OptionalAuthorityBinding{} },
	} {
		changed := s
		change(&changed)
		current, e := session.NewAuthoritySnapshot(changed)
		if e != nil {
			t.Fatal(e)
		}
		if e = stored.CompareCurrent(current); !errors.Is(e, session.ErrAuthorityMismatch) {
			t.Fatal("optional authority downgraded")
		}
	}
	for _, change := range []func(*session.AuthoritySnapshotSpec){
		func(s *session.AuthoritySnapshotSpec) { s.ActiveOrganizationID = "" },
		func(s *session.AuthoritySnapshotSpec) { s.ActiveOrganizationID = "bad organization" },
		func(s *session.AuthoritySnapshotSpec) { s.Organization.Present = false },
		func(s *session.AuthoritySnapshotSpec) { s.Factor.Present = false },
		func(s *session.AuthoritySnapshotSpec) { s.Passkey.Present = false },
		func(s *session.AuthoritySnapshotSpec) { s.Organization.Binding.Version = 0 },
		func(s *session.AuthoritySnapshotSpec) { s.Factor.Binding.Version = 0 },
		func(s *session.AuthoritySnapshotSpec) { s.Passkey.Binding.Version = 0 },
		func(s *session.AuthoritySnapshotSpec) { s.Factor.Binding.ScopeKey = s.Credential.ScopeKey },
	} {
		bad := s
		change(&bad)
		if _, e = session.NewAuthoritySnapshot(bad); !errors.Is(e, session.ErrInvalidAuthority) {
			t.Fatal("malformed optional authority accepted")
		}
	}
	plain := authoritySpec()
	plain.ActiveOrganizationID = "org-a"
	if _, e = session.NewAuthoritySnapshot(plain); !errors.Is(e, session.ErrInvalidAuthority) {
		t.Fatal("unversioned organization accepted")
	}
}
