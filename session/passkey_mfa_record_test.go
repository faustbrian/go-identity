package session

import (
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

// These are trusted-storage projection tests, not authentication proof. Native
// completion must authenticate the retained assertion and TOTP in one Work.
func passkeyMFARecordFixture(t *testing.T) (SessionSpec, MFAAuthentication) {
	t.Helper()
	spec, factor := passwordMFARecordFixture(t)
	spec.Authentication.CredentialID = "passkey"
	spec.Authentication.Proof.Method = "passkey"
	spec.Authentication.Proof.Assurance = auth.AssurancePhishingResistant
	spec.Authentication.Proof.Purpose = "identity.passkey.mfa-primary"
	authority, err := spec.Authority.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	authority.Passkey = OptionalAuthorityBinding{Present: true, Binding: AuthorityBinding{ScopeKey: "passkey", Version: 4}}
	spec.Authority, err = NewAuthoritySnapshot(authority)
	if err != nil {
		t.Fatal(err)
	}
	return spec, factor
}

func TestPasskeyMFARecordRetainsIndependentFactorAndOriginalFreshness(t *testing.T) {
	spec, factor := passkeyMFARecordFixture(t)
	record, err := newSessionWithMFA(spec, OTPAuthentication{}, MagicLinkAuthentication{}, factor)
	if err != nil {
		t.Fatal("completed TOTP with retained passkey primary rejected", err)
	}
	got, err := record.Bindings()
	if err != nil || got.Authentication != spec.Authentication || got.Authority != spec.Authority || record.MFAAuthentication() != factor {
		t.Fatal("original passkey, authority or independent factor lost", err)
	}
	lifetime, err := record.Lifetime(spec.Authentication.Proof.IssuedAt.Add(15 * time.Minute))
	if err != nil || lifetime.Fresh {
		t.Fatal("TOTP completion renewed primary freshness", err)
	}
	rebuilt, err := rebuildSession(spec, record, CSRFState{})
	if err != nil || rebuilt.MFAAuthentication() != factor {
		t.Fatal("reconstruction lost completed factor", err)
	}
	if _, err := NewSessionWithPasskeyMFA(spec, factor); err != nil {
		t.Fatal("explicit passkey reconstruction denied", err)
	}
	if _, err := NewSessionWithPasswordMFA(spec, factor); err == nil {
		t.Fatal("passkey entered password reconstruction")
	}
	if _, err := NewSession(spec); err == nil {
		t.Fatal("non-final passkey primary reconstructed without factor")
	}
	state, err := NewCSRFState(CSRFStateSpec{Binding: CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, KeyVersion: 1, Digest: [32]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	withCSRF, err := NewSessionWithPasskeyMFAAndCSRF(spec, factor, state)
	if err != nil || withCSRF.CSRFState() != state || withCSRF.MFAAuthentication() != factor {
		t.Fatal("synchronizer or factor lost", err)
	}
	if err := validateMFAIssuanceAt(record, spec.IssuedAt); err != nil {
		t.Fatal("valid prospective passkey-MFA issuance denied", err)
	}
	if err := validateMFAIssuanceAt(record, spec.Authentication.Proof.ExpiresAt); err == nil {
		t.Fatal("expired original primary admitted")
	}
}

func TestPasskeyMFARecordRejectsSubstitutionAndAuthorityLoss(t *testing.T) {
	for name, change := range map[string]func(*SessionSpec, *MFAAuthenticationSpec){
		"ordinary signin": func(s *SessionSpec, _ *MFAAuthenticationSpec) { s.Authentication.Proof.Purpose = "session-issue" },
		"password purpose": func(s *SessionSpec, _ *MFAAuthenticationSpec) {
			s.Authentication.Proof.Purpose = PasswordMFAPrimaryPurpose
		},
		"password relabel": func(s *SessionSpec, _ *MFAAuthenticationSpec) { s.Authentication.Proof.Method = "password" },
		"UP-only assertion": func(s *SessionSpec, _ *MFAAuthenticationSpec) {
			s.Authentication.Proof.Assurance = auth.AssuranceSingleFactor
		},
		"MFA assurance relabel": func(s *SessionSpec, _ *MFAAuthenticationSpec) {
			s.Authentication.Proof.Assurance = auth.AssuranceMultiFactor
		},
		"foreign primary":  func(_ *SessionSpec, m *MFAAuthenticationSpec) { m.PrimaryCommandID = "BwcHBwcHBwcHBwcHBwcHBw" },
		"expiry extension": func(_ *SessionSpec, m *MFAAuthenticationSpec) { m.ValidUntil = m.ValidUntil.Add(time.Second) },
		"factor before primary": func(s *SessionSpec, m *MFAAuthenticationSpec) {
			s.Authentication.Proof.IssuedAt = m.VerifiedAt.Add(time.Second)
		},
		"factor epoch substitution": func(_ *SessionSpec, m *MFAAuthenticationSpec) { m.FactorAuthorityVersion++ },
		"remember upgrade":          func(_ *SessionSpec, m *MFAAuthenticationSpec) { m.Remember.Choice = PersistentSession },
		"missing passkey epoch": func(s *SessionSpec, _ *MFAAuthenticationSpec) {
			a, _ := s.Authority.Bindings()
			a.Passkey = OptionalAuthorityBinding{}
			s.Authority, _ = NewAuthoritySnapshot(a)
		},
		"organization substitution": func(s *SessionSpec, _ *MFAAuthenticationSpec) {
			a, _ := s.Authority.Bindings()
			a.Organization = OptionalAuthorityBinding{Present: true, Binding: AuthorityBinding{ScopeKey: "organization", Version: 1}}
			s.Authority, _ = NewAuthoritySnapshot(a)
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec, factor := passkeyMFARecordFixture(t)
			metadata, _ := factor.Bindings()
			change(&spec, &metadata)
			factor, err := NewMFAAuthentication(metadata)
			if err != nil {
				t.Fatal("invalid denial fixture", err)
			}
			if _, err := NewSessionWithPasskeyMFA(spec, factor); err == nil {
				t.Fatal("substituted completed primary admitted")
			}
		})
	}
}
