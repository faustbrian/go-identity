package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func mfaCompletionMappingFixture(t testing.TB, csrf bool) (identity.FeatureCommandSpec, session.Session) {
	t.Helper()
	spec, record := magicLinkSigninMappingFixture(t, csrf)
	s, _ := record.Bindings()
	primary := record.MagicLinkAuthentication()
	p, _ := primary.Bindings()
	a, _ := s.Authority.Bindings()
	a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor/user", Version: 7}}
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	remember, _ := s.Remember.Bindings()
	m, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: p.CommandID, ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1}, Method: "totp", FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 1, FactorAuthorityVersion: 7, ContinuationVersion: 1, Remember: remember, VerifiedAt: s.IssuedAt, ValidUntil: p.ValidUntil})
	if err != nil {
		t.Fatal(err)
	}
	if csrf {
		record, err = session.NewSessionWithMagicLinkMFAAndCSRF(s, primary, m, record.CSRFState())
	} else {
		record, err = session.NewSessionWithMagicLinkMFA(s, primary, m)
	}
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.CommandID, spec.Binding.OperationID, spec.Binding.SchemaID = "BAQEBAQEBAQEBAQEBAQEBA", "identity.mfa.totp-verify", "mfa-totp-verify"
	spec.Operation = identity.FeatureOperation{Owner: "identity/mfa", OperationID: spec.Binding.OperationID, SchemaID: spec.Binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	spec.Fields, err = MFATOTPCompletionSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	return spec, record
}

func TestMFATOTPCompletionMappingRetainsAllOriginalFields(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		spec, expected := mfaCompletionMappingFixture(t, csrf)
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
	spec, _ := mfaCompletionMappingFixture(f, true)
	f.Fuzz(func(t *testing.T, index uint8, input string) {
		if len(input) > 8192 {
			return
		}
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
		i := int(index) % len(changed.Fields)
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
