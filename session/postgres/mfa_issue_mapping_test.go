package postgres

import (
	"bytes"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func mfaCompletionMappingFixture(t testing.TB, csrf bool) (identity.FeatureCommandSpec, session.Session) {
	return mfaCompletionMappingProfile(t, csrf, false)
}

func mfaCompletionMappingProfile(t testing.TB, csrf, password bool) (identity.FeatureCommandSpec, session.Session) {
	return mfaCompletionMappingMethod(t, csrf, password, "totp")
}

func mfaCompletionMappingMethod(t testing.TB, csrf, password bool, method string) (identity.FeatureCommandSpec, session.Session) {
	t.Helper()
	spec, record := magicLinkSigninMappingFixture(t, csrf)
	s, _ := record.Bindings()
	primary := record.MagicLinkAuthentication()
	p, _ := primary.Bindings()
	if password {
		s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, ProofVersion: 1, CredentialID: "password", CredentialVersion: 3, Proof: auth.Proof{ID: auth.ProofID(p.CommandID), Tenant: string(s.TenantID), Subject: string(s.UserID), Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: s.Audience, IssuedAt: p.AuthenticatedAt, ExpiresAt: p.ValidUntil}}
		s.Authentication.Proof.Purpose = "identity.password.mfa-primary"
	}
	a, _ := s.Authority.Bindings()
	a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor/user", Version: 7}}
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	remember, _ := s.Remember.Bindings()
	m, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: p.CommandID, ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1}, Method: "totp", FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 1, FactorAuthorityVersion: 7, ContinuationVersion: 1, Remember: remember, VerifiedAt: s.IssuedAt, ValidUntil: p.ValidUntil})
	if err != nil {
		t.Fatal(err)
	}
	if method == "recovery-code" {
		p, _ := m.Bindings()
		p.Method, p.RecoverySetID, p.RecoverySetVersion = method, "BwcHBwcHBwcHBwcHBwcHBw", 2
		m, err = session.NewMFAAuthentication(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	if method == "otp" {
		p, _ := m.Bindings()
		p.Method = method
		m, err = session.NewMFAAuthentication(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	if password && csrf {
		record, err = session.NewSessionWithPasswordMFAAndCSRF(s, m, record.CSRFState())
	} else if password {
		record, err = session.NewSessionWithPasswordMFA(s, m)
	} else if csrf {
		record, err = session.NewSessionWithMagicLinkMFAAndCSRF(s, primary, m, record.CSRFState())
	} else {
		record, err = session.NewSessionWithMagicLinkMFA(s, primary, m)
	}
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.CommandID, spec.Binding.OperationID, spec.Binding.SchemaID = "BAQEBAQEBAQEBAQEBAQEBA", "identity.mfa.totp-verify", "mfa-totp-verify"
	spec.Operation = identity.FeatureOperation{Owner: "identity/mfa", OperationID: spec.Binding.OperationID, SchemaID: spec.Binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if method == "recovery-code" {
		spec.Binding.OperationID, spec.Binding.SchemaID = "identity.mfa.recovery-use", "mfa-recovery-use"
		spec.Operation.OperationID, spec.Operation.SchemaID = spec.Binding.OperationID, spec.Binding.SchemaID
		spec.Fields, err = MFARecoveryCompletionSessionFields(record)
	} else if method == "otp" {
		spec.Binding.OperationID, spec.Binding.SchemaID = "identity.mfa.otp-verify", "mfa-otp-verify"
		spec.Operation.OperationID, spec.Operation.SchemaID = spec.Binding.OperationID, spec.Binding.SchemaID
		spec.Fields, err = MFAOTPCompletionSessionFields(record)
	} else {
		spec.Fields, err = MFATOTPCompletionSessionFields(record)
	}
	if err != nil {
		t.Fatal(err)
	}
	return spec, record
}

func TestMFAOTPCompletionMappingPreservesExactPasswordAndBrowserProfile(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		spec, expected := mfaCompletionMappingMethod(t, csrf, true, "otp")
		command, err := identity.NewFeatureCommand(spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := MFAOTPCompletionSession(command)
		if err != nil {
			t.Fatal("OTP mapping unavailable", err)
		}
		a, _, _ := encodeRecord(expected)
		b, _, _ := encodeRecord(got)
		if !bytes.Equal(a, b) {
			t.Fatal("OTP mapping replaced original primary, factor, remember or synchronizer")
		}
		if _, err := MFATOTPCompletionSession(command); err == nil {
			t.Fatal("OTP entered TOTP completion")
		}
		if _, err := MFARecoveryCompletionSession(command); err == nil {
			t.Fatal("OTP entered recovery-code completion")
		}
	}
}

func TestMFARecoveryCompletionMappingPreservesMethodAndSet(t *testing.T) {
	for _, profile := range []struct{ csrf, password bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		spec, expected := mfaCompletionMappingMethod(t, profile.csrf, profile.password, "recovery-code")
		command, err := identity.NewFeatureCommand(spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := MFARecoveryCompletionSession(command)
		if err != nil {
			t.Fatal("recovery session mapping unavailable", err)
		}
		a, _, _ := encodeRecord(expected)
		b, _, _ := encodeRecord(got)
		if !bytes.Equal(a, b) {
			t.Fatal("recovery mapping changed primary, set or factor")
		}
		if _, err := MFATOTPCompletionSession(command); err == nil {
			t.Fatal("recovery entered TOTP mapping")
		}
		if _, err := MFATOTPCompletionSessionFields(expected); err == nil {
			t.Fatal("recovery record entered TOTP fields")
		}
		for i := range spec.Fields {
			partial := spec
			partial.Fields = append(spec.Fields[:i:i], spec.Fields[i+1:]...)
			command, err := identity.NewFeatureCommand(partial)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := MFARecoveryCompletionSession(command); err == nil {
				t.Fatal("partial recovery provenance accepted")
			}
		}
	}
}

func TestMFATOTPCompletionMappingRetainsAllOriginalFields(t *testing.T) {
	for _, profile := range []struct{ csrf, password bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		spec, expected := mfaCompletionMappingProfile(t, profile.csrf, profile.password)
		command, err := identity.NewFeatureCommand(spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := MFATOTPCompletionSession(command)
		if err != nil {
			t.Fatal("native completion projection lost", err)
		}
		a, _, _ := encodeRecord(expected)
		b, _, _ := encodeRecord(got)
		if !bytes.Equal(a, b) {
			t.Fatal("factor, primary, remember or synchronizer changed")
		}
		for i := range spec.Fields {
			partial := spec
			partial.Fields = append(spec.Fields[:i:i], spec.Fields[i+1:]...)
			command, err := identity.NewFeatureCommand(partial)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := MFATOTPCompletionSession(command); err == nil {
				t.Fatal("partial original session accepted")
			}
		}
		changed := spec
		changed.Binding.CommandID = "BwcHBwcHBwcHBwcHBwcHBw"
		foreign, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := MFATOTPCompletionSession(foreign); err == nil {
			t.Fatal("completion command identity substituted")
		}
		if _, err := MagicLinkSigninSession(command); err == nil {
			t.Fatal("MFA entered primary-only consume mapping")
		}
	}
	for _, record := range []session.Session{{}, magicLinkRecordFixture(t, false), otpRecordFixture(t, false)} {
		if _, err := MFATOTPCompletionSessionFields(record); err == nil {
			t.Fatal("non-completed profile accepted")
		}
	}
}

func FuzzMFATOTPCompletionMapping(f *testing.F) {
	f.Add(uint8(0), "invalid")
	f.Add(uint8(25), "2026-10-11T00:00:00.000000000Z")
	f.Add(uint8(128), "invalid")
	f.Add(uint8(153), "2026-10-11T00:00:00.000000000Z")
	spec, _ := mfaCompletionMappingFixture(f, true)
	passwordSpec, _ := mfaCompletionMappingProfile(f, true, true)
	f.Fuzz(func(t *testing.T, index uint8, input string) {
		if len(input) > 8192 {
			return
		}
		changed := spec
		if index&128 != 0 {
			changed = passwordSpec
		}
		changed.Fields = append([]identity.FeatureField{}, changed.Fields...)
		i := int(index&127) % len(changed.Fields)
		changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: input}
		command, err := identity.NewFeatureCommand(changed)
		if err != nil {
			return
		}
		record, err := MFATOTPCompletionSession(command)
		if err != nil {
			return
		}
		changed.Fields, err = MFATOTPCompletionSessionFields(record)
		if err != nil {
			t.Fatal("accepted record cannot be remapped", err)
		}
		canonical, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		again, err := MFATOTPCompletionSession(canonical)
		a, _, _ := encodeRecord(record)
		b, _, _ := encodeRecord(again)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("accepted completion mapping is not stable", err)
		}
	})
}
