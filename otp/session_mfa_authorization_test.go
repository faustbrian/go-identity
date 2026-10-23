package otp_test

import (
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func TestBoundSessionCommitsCompletedMFAProvenance(t *testing.T) {
	s := originalSessionSpec(t)
	a, _ := s.Authority.Bindings()
	a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:tenant:subject", Version: 11}}
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	s.Authentication.Proof.ID = "AwMDAwMDAwMDAwMDAwMDAw"
	s.Authentication.Proof.Purpose = session.PasswordMFAPrimaryPurpose
	p, _ := s.Remember.Bindings()
	base := session.MFAAuthenticationSpec{CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: identity.CommandID(s.Authentication.Proof.ID), ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1}, Method: "otp", FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 3, FactorAuthorityVersion: 11, ContinuationVersion: 4, Remember: p, VerifiedAt: s.IssuedAt.Add(-time.Second), ValidUntil: s.Authentication.Proof.ExpiresAt}
	bind := func(m session.MFAAuthenticationSpec, csrf bool) [32]byte {
		factor, err := session.NewMFAAuthentication(m)
		if err != nil {
			t.Fatal(err)
		}
		r, err := session.NewSessionWithPasswordMFA(s, factor)
		if csrf {
			state, e := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version}, KeyVersion: 3, Digest: [32]byte{9}})
			if e != nil {
				t.Fatal(e)
			}
			r, err = session.NewSessionWithPasswordMFAAndCSRF(s, factor, state)
		}
		if err != nil {
			t.Fatal(err)
		}
		flow, err := otp.NewBoundSessionAuthorization(r)
		if err != nil {
			t.Fatal(err)
		}
		scope := digestScopeSpec(t)
		scope.AuthorizationBinding, scope.Purpose, scope.SubjectID = [32]byte{}, otp.PurposeStepUp, "subject"
		c, err := otp.NewContinuation(scope, flow, session.RememberPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.Bindings()
		return b.Scope.AuthorizationBinding
	}
	for _, csrf := range []bool{false, true} {
		want := bind(base, csrf)
		for _, change := range []func(*session.MFAAuthenticationSpec){
			func(m *session.MFAAuthenticationSpec) { m.CommandID = "CAgICAgICAgICAgICAgICA" },
			func(m *session.MFAAuthenticationSpec) { m.ContinuationID = "CAgICAgICAgICAgICAgICA" },
			func(m *session.MFAAuthenticationSpec) { m.ContinuationScopeDigest[0]++ },
			func(m *session.MFAAuthenticationSpec) { m.Method = "totp" },
			func(m *session.MFAAuthenticationSpec) { m.FactorID = "CAgICAgICAgICAgICAgICA" },
			func(m *session.MFAAuthenticationSpec) { m.EnrollmentVersion++ },
			func(m *session.MFAAuthenticationSpec) { m.ContinuationVersion++ },
			func(m *session.MFAAuthenticationSpec) { m.VerifiedAt = m.VerifiedAt.Add(-time.Nanosecond) },
			func(m *session.MFAAuthenticationSpec) { m.ValidUntil = m.ValidUntil.Add(-time.Nanosecond) },
			func(m *session.MFAAuthenticationSpec) {
				m.Method = "recovery-code"
				m.RecoverySetID = "CAgICAgICAgICAgICAgICA"
				m.RecoverySetVersion = 2
			},
		} {
			other := base
			change(&other)
			if bind(other, csrf) == want {
				t.Fatal("changed completed factor shared original OTP authorization commitment")
			}
		}
	}
	if bind(base, false) == bind(base, true) {
		t.Fatal("MFA profile lost CSRF presence")
	}
}
