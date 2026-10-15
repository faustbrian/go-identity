package otp_test

import (
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func originalSessionSpec(t *testing.T) session.SessionSpec {
	t.Helper()
	now := time.Date(2026, 10, 7, 12, 0, 0, 123456789, time.UTC)
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{
		Global:        session.AuthorityBinding{ScopeKey: "global:deployment", Version: 1},
		Tenant:        session.AuthorityBinding{ScopeKey: "tenant:tenant", Version: 2},
		User:          session.AuthorityBinding{ScopeKey: "user:tenant:subject", Version: 3},
		Identifier:    session.AuthorityBinding{ScopeKey: "identifier:tenant:subject", Version: 4},
		Credential:    session.AuthorityBinding{ScopeKey: "credential:tenant:subject", Version: 5},
		SessionFamily: session.AuthorityBinding{ScopeKey: "family:tenant:family", Version: 6},
		Session:       session.AuthorityBinding{ScopeKey: "session:tenant:session", Version: 7},
		Authorization: session.AuthorityBinding{ScopeKey: "authorization:tenant:subject", Version: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return session.SessionSpec{SessionID: "session", FamilyID: "family", TenantID: "tenant", UserID: "subject", Audience: "identity-service", Version: 7, FamilyVersion: 6, Remember: rememberPolicy(t), Authority: authority,
		Lookup: session.TokenDigest{KeyVersion: 3, Sum: [32]byte{1}}, IssuedAt: now, LastActivityAt: now,
		Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1,
			Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "subject", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}}}
}

func TestBoundSessionContinuationRetainsOriginalWithoutRenewal(t *testing.T) {
	base := originalSessionSpec(t)
	scope := digestScopeSpec(t)
	scope.AuthorizationBinding = [32]byte{}
	scope.Purpose = otp.PurposeStepUp
	scope.SubjectID = "subject"
	bind := func(spec session.SessionSpec) [32]byte {
		record, err := session.NewSession(spec)
		if err != nil {
			t.Fatal(err)
		}
		flow, err := otp.NewBoundSessionAuthorization(record)
		if err != nil {
			t.Fatal(err)
		}
		retained, ok := flow.AuthenticatedSession()
		if !ok || retained != record {
			t.Fatal("original session custody lost")
		}
		if _, ok := flow.PreAuthTransaction(); ok {
			t.Fatal("mixed flow custody")
		}
		c, err := otp.NewContinuation(scope, flow, session.RememberPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.Bindings()
		return b.Scope.AuthorizationBinding
	}
	want := bind(base)
	changes := []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.SessionID = "other-session" },
		func(s *session.SessionSpec) { s.FamilyID = "other-family" },
		func(s *session.SessionSpec) {
			s.Audience = "other-audience"
			s.Authentication.Proof.Audience = s.Audience
		},
		func(s *session.SessionSpec) { s.Lookup.KeyVersion++ },
		func(s *session.SessionSpec) { s.Lookup.Sum[1] = 1 },
		func(s *session.SessionSpec) { s.IssuedAt = s.IssuedAt.Add(-time.Nanosecond) },
		func(s *session.SessionSpec) { s.LastActivityAt = s.LastActivityAt.Add(time.Nanosecond) },
		func(s *session.SessionSpec) { s.Authentication.ProofVersion++ },
		func(s *session.SessionSpec) { s.Authentication.CredentialID = "other-credential" },
		func(s *session.SessionSpec) { s.Authentication.CredentialVersion++ },
		func(s *session.SessionSpec) { s.Authentication.Proof.ID = "bcdefghijklmnopqrstuvw" },
		func(s *session.SessionSpec) { s.Authentication.Proof.Method = "otp" },
		func(s *session.SessionSpec) { s.Authentication.Proof.Purpose = "other-purpose" },
		func(s *session.SessionSpec) { s.Authentication.Proof.Assurance = auth.AssuranceMultiFactor },
		func(s *session.SessionSpec) {
			s.Authentication.Proof.IssuedAt = s.Authentication.Proof.IssuedAt.Add(-time.Nanosecond)
		},
		func(s *session.SessionSpec) {
			s.Authentication.Proof.ExpiresAt = s.Authentication.Proof.ExpiresAt.Add(time.Nanosecond)
		},
		func(s *session.SessionSpec) {
			p, _ := s.Remember.Bindings()
			p.AbsoluteTTL -= time.Nanosecond
			s.Remember, _ = session.NewRememberPolicy(p)
		},
	}
	for i := range 11 {
		changes = append(changes, func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			required := []*session.AuthorityBinding{&a.Global, &a.Tenant, &a.User, &a.Identifier, &a.Credential, &a.SessionFamily, &a.Session, &a.Authorization}
			if i < 8 {
				required[i].Version++
				if i == 5 {
					s.FamilyVersion++
				}
				if i == 6 {
					s.Version++
				}
			} else {
				o := []*session.OptionalAuthorityBinding{&a.Organization, &a.Factor, &a.Passkey}[i-8]
				*o = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: []string{"organization:tenant:org", "factor:tenant:subject", "passkey:tenant:subject"}[i-8], Version: 1}}
				if i == 8 {
					a.ActiveOrganizationID = "org"
				}
			}
			var err error
			s.Authority, err = session.NewAuthoritySnapshot(a)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, change := range changes {
		other := base
		change(&other)
		if bind(other) == want {
			t.Fatal("changed original session shared commitment")
		}
	}
	for i := range 8 {
		other := base
		a, _ := other.Authority.Bindings()
		bindings := []*session.AuthorityBinding{&a.Global, &a.Tenant, &a.User, &a.Identifier, &a.Credential, &a.SessionFamily, &a.Session, &a.Authorization}
		bindings[i].ScopeKey += ":other"
		other.Authority, _ = session.NewAuthoritySnapshot(a)
		if bind(other) == want {
			t.Fatal("changed authority key shared commitment")
		}
	}
	legacy, _ := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: base.SessionID})
	if _, ok := legacy.AuthenticatedSession(); ok {
		t.Fatal("legacy fabricated original session")
	}
	c, err := otp.NewContinuation(scope, legacy, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bindings()
	if b.Scope.AuthorizationBinding == want {
		t.Fatal("complete custody borrowed legacy framing")
	}
}

func TestBoundSessionContinuationRejectsScopeAndAnonymousSubstitution(t *testing.T) {
	if _, err := otp.NewBoundSessionAuthorization(session.Session{}); err == nil {
		t.Fatal("zero session admitted")
	}
	base := originalSessionSpec(t)
	anonymous := base
	anonymous.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: base.IssuedAt}
	record, err := session.NewSession(anonymous)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = otp.NewBoundSessionAuthorization(record); err == nil {
		t.Fatal("anonymous authenticated")
	}
	record, _ = session.NewSession(base)
	flow, _ := otp.NewBoundSessionAuthorization(record)
	scope := digestScopeSpec(t)
	scope.AuthorizationBinding = [32]byte{}
	scope.Purpose = otp.PurposeStepUp
	scope.SubjectID = "subject"
	for _, mutate := range []func(*otp.DigestScopeSpec){
		func(s *otp.DigestScopeSpec) { s.TenantID = "foreign" },
		func(s *otp.DigestScopeSpec) { s.SubjectID = "foreign" },
		func(s *otp.DigestScopeSpec) { s.Purpose = otp.PurposeSignin },
	} {
		other := scope
		mutate(&other)
		if _, err := otp.NewContinuation(other, flow, session.RememberPolicy{}); err == nil {
			t.Fatal("scope substitution admitted")
		}
	}
}
