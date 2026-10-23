package postgres

import (
	"bytes"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func passwordMFACustodyFixture(t testing.TB, method string, csrf bool) session.Session {
	t.Helper()
	_, _, original := sessionCustodyFixture(t)
	s, _ := original.Bindings()
	a, _ := s.Authority.Bindings()
	a.Organization, a.Passkey = session.OptionalAuthorityBinding{}, session.OptionalAuthorityBinding{}
	a.ActiveOrganizationID = ""
	var err error
	s.Authority, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	s.Authentication.Proof.ID = "AwMDAwMDAwMDAwMDAwMDAw"
	s.Authentication.Proof.Purpose = session.PasswordMFAPrimaryPurpose
	s.Authentication.Proof.Assurance = auth.AssuranceSingleFactor
	p, _ := s.Remember.Bindings()
	m := session.MFAAuthenticationSpec{CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: identity.CommandID(s.Authentication.Proof.ID), ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1}, Method: method, FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 3, FactorAuthorityVersion: a.Factor.Binding.Version, ContinuationVersion: 4, Remember: p, VerifiedAt: s.IssuedAt.Add(-time.Second), ValidUntil: s.Authentication.Proof.ExpiresAt}
	if method == "recovery-code" {
		m.RecoverySetID, m.RecoverySetVersion = "BwcHBwcHBwcHBwcHBwcHBw", 2
	}
	factor, err := session.NewMFAAuthentication(m)
	if err != nil {
		t.Fatal(err)
	}
	if csrf {
		state, e := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version}, KeyVersion: 3, Digest: [32]byte{9}})
		if e != nil {
			t.Fatal(e)
		}
		original, err = session.NewSessionWithPasswordMFAAndCSRF(s, factor, state)
	} else {
		original, err = session.NewSessionWithPasswordMFA(s, factor)
	}
	if err != nil {
		t.Fatal(err)
	}
	return original
}

func TestSessionCustodyPreservesPasswordMFAProvenance(t *testing.T) {
	for _, method := range []string{"otp", "totp", "recovery-code"} {
		for _, csrf := range []bool{false, true} {
			original := passwordMFACustodyFixture(t, method, csrf)
			plain := appendSessionRecord(nil, original)
			r := &recordReader{data: plain, ok: true}
			restored, err := readSessionRecord(r, csrf)
			if err != nil || !r.ok || len(r.data) != 0 {
				t.Fatal("completed password MFA session did not survive custody", err)
			}
			want, _ := original.MFAAuthentication().Bindings()
			got, e := restored.MFAAuthentication().Bindings()
			if e != nil || got != want {
				t.Fatal("completed factor provenance was lost or changed")
			}
			before, _ := original.Bindings()
			after, _ := restored.Bindings()
			if before.Authentication != after.Authentication || !before.IssuedAt.Equal(after.IssuedAt) {
				t.Fatal("primary authentication was changed")
			}
			wc, we := original.CSRFState().Bindings()
			gc, ge := restored.CSRFState().Bindings()
			if (we == nil) != (ge == nil) || wc != gc {
				t.Fatal("synchronizer state was changed")
			}
			if !bytes.Equal(appendSessionRecord(nil, restored), plain) {
				t.Fatal("noncanonical session round trip")
			}
			for n := range len(plain) {
				r := &recordReader{data: plain[:n], ok: true}
				if _, err := readSessionRecord(r, csrf); err == nil {
					t.Fatal("truncated MFA session admitted")
				}
			}
		}
	}
}

func FuzzPasswordMFASessionCustody(f *testing.F) {
	for _, method := range []string{"otp", "totp", "recovery-code"} {
		for _, csrf := range []bool{false, true} {
			f.Add(appendSessionRecord(nil, passwordMFACustodyFixture(f, method, csrf)), csrf)
		}
	}
	f.Add([]byte("\xff\xff\x02"), true)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, data []byte, csrf bool) {
		if len(data) > 8192 {
			return
		}
		r := &recordReader{data: data, ok: true}
		record, err := readSessionRecord(r, csrf)
		if err != nil || !r.ok || len(r.data) != 0 {
			return
		}
		if !bytes.Equal(appendSessionRecord(nil, record), data) {
			t.Fatal("accepted noncanonical session custody")
		}
	})
}
