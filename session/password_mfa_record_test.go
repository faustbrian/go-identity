package session

import (
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

func passwordMFARecordFixture(t *testing.T) (SessionSpec, MFAAuthentication) {
	t.Helper()
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	remember, err := NewRememberPolicy(RememberPolicySpec{Choice: BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: 30 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	vector := AuthoritySnapshotSpec{}
	for i, binding := range []*AuthorityBinding{&vector.Global, &vector.Tenant, &vector.User, &vector.Identifier, &vector.Credential, &vector.SessionFamily, &vector.Session, &vector.Authorization} {
		*binding = AuthorityBinding{ScopeKey: string(rune('a' + i)), Version: 1}
	}
	vector.Factor = OptionalAuthorityBinding{Present: true, Binding: AuthorityBinding{ScopeKey: "factor", Version: 7}}
	authority, err := NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := remember.Bindings()
	factor, err := NewMFAAuthentication(MFAAuthenticationSpec{CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: "AwMDAwMDAwMDAwMDAwMDAw", ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1}, Method: "totp", FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 1, FactorAuthorityVersion: 7, ContinuationVersion: 1, Remember: policy, VerifiedAt: now, ValidUntil: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	spec := SessionSpec{SessionID: "session", FamilyID: "family", TenantID: "tenant", UserID: "user", Audience: "identity", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, IssuedAt: now, LastActivityAt: now, Authentication: AuthenticationMetadata{Kind: AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID("AwMDAwMDAwMDAwMDAwMDAw"), Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity", IssuedAt: now.Add(-4 * time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 3}}
	spec.Authentication.Proof.Purpose = "identity.password.mfa-primary"
	return spec, factor
}

func TestPasswordMFARecordRetainsPrimaryCredentialAndFreshness(t *testing.T) {
	spec, factor := passwordMFARecordFixture(t)
	record, err := newSessionWithMFA(spec, OTPAuthentication{}, MagicLinkAuthentication{}, factor)
	if err != nil {
		t.Fatal("genuine password primary with completed factor rejected", err)
	}
	got, _ := record.Bindings()
	if got.Authentication != spec.Authentication || record.MFAAuthentication() != factor || record.MagicLinkAuthentication() != (MagicLinkAuthentication{}) {
		t.Fatal("password primary was replaced or factor provenance lost")
	}
	lifetime, err := record.Lifetime(spec.Authentication.Proof.IssuedAt.Add(15 * time.Minute))
	if err != nil || lifetime.Fresh {
		t.Fatal("factor renewed password freshness", err)
	}
	updated, err := rebuildSession(spec, record, CSRFState{})
	if err != nil || updated.MFAAuthentication() != factor {
		t.Fatal("reconstruction lost factor", err)
	}
}

func TestPasswordMFARecordRejectsForeignOrExpandedPrimary(t *testing.T) {
	for name, change := range map[string]func(*SessionSpec, *MFAAuthenticationSpec){
		"final signin substitution": func(s *SessionSpec, _ *MFAAuthenticationSpec) { s.Authentication.Proof.Purpose = "session-issue" },
		"foreign primary":           func(_ *SessionSpec, m *MFAAuthenticationSpec) { m.PrimaryCommandID = "BwcHBwcHBwcHBwcHBwcHBw" },
		"renewed expiry":            func(_ *SessionSpec, m *MFAAuthenticationSpec) { m.ValidUntil = m.ValidUntil.Add(time.Second) },
		"factor predates primary": func(s *SessionSpec, m *MFAAuthenticationSpec) {
			s.Authentication.Proof.IssuedAt = m.VerifiedAt.Add(time.Second)
		},
		"wrong method": func(s *SessionSpec, _ *MFAAuthenticationSpec) { s.Authentication.Proof.Method = "oauth" },
		"fabricated assurance": func(s *SessionSpec, _ *MFAAuthenticationSpec) {
			s.Authentication.Proof.Assurance = auth.AssuranceMultiFactor
		},
		"changed policy": func(_ *SessionSpec, m *MFAAuthenticationSpec) { m.Remember.Choice = PersistentSession },
		"stale factor":   func(_ *SessionSpec, m *MFAAuthenticationSpec) { m.FactorAuthorityVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			s, factor := passwordMFARecordFixture(t)
			m, _ := factor.Bindings()
			change(&s, &m)
			factor, err := NewMFAAuthentication(m)
			if err != nil {
				return
			}
			if _, err := newSessionWithMFA(s, OTPAuthentication{}, MagicLinkAuthentication{}, factor); err == nil {
				t.Fatal("invalid completed password record accepted")
			}
		})
	}
}

func TestPasswordMFAIssuanceUsesOriginalPrimaryAndContinuationDeadline(t *testing.T) {
	spec, factor := passwordMFARecordFixture(t)
	record, err := NewSessionWithPasswordMFA(spec, factor)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMFAIssuanceAt(record, spec.IssuedAt); err != nil {
		t.Fatal("valid completed password intent denied", err)
	}
	if err := validateMFAIssuanceAt(record, spec.IssuedAt.Add(-time.Second)); err == nil {
		t.Fatal("factor admitted before verification")
	}
	if err := validateMFAIssuanceAt(record, spec.Authentication.Proof.ExpiresAt); err == nil {
		t.Fatal("expired original password admitted")
	}
}
