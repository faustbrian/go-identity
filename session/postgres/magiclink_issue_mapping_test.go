package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func magicLinkSigninMappingFixture(t testing.TB, csrf bool) (identity.FeatureCommandSpec, session.Session) {
	t.Helper()
	record := magicLinkRecordFixture(t, csrf)
	s, _ := record.Bindings()
	s.Version, s.FamilyVersion = 1, 1
	a, _ := s.Authority.Bindings()
	a.Session.Version, a.SessionFamily.Version = 1, 1
	var err error
	s.Authority, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	if csrf {
		state, _ := record.CSRFState().Bindings()
		state.Binding.SessionVersion = 1
		owned, e := session.NewCSRFState(state)
		if e != nil {
			t.Fatal(e)
		}
		record, err = session.NewSessionWithMagicLinkAndCSRF(s, record.MagicLinkAuthentication(), owned)
	} else {
		record, err = session.NewSessionWithMagicLink(s, record.MagicLinkAuthentication())
	}
	if err != nil {
		t.Fatal(err)
	}
	p, _ := record.MagicLinkAuthentication().Bindings()
	b := revokeBinding()
	b.CommandID, b.TenantID, b.UserID, b.RecordID = p.CommandID, s.TenantID, "", ""
	b.AnonymousFlowID, b.OperationID, b.SchemaID = "original-flow", "identity.magic-link.consume", "magic-link-consume"
	fields, err := MagicLinkSigninSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	return identity.FeatureCommandSpec{Binding: b, Operation: identity.FeatureOperation{Owner: "identity/magiclink", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}, Fields: fields}, record
}

func FuzzMagicLinkSigninMapping(f *testing.F) {
	f.Add(uint8(0), "invalid")
	f.Add(uint8(23), "2026-10-11T00:00:00Z")
	spec, _ := magicLinkSigninMappingFixture(f, true)
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
		record, err := MagicLinkSigninSession(command)
		if err != nil {
			return
		}
		fields, err := MagicLinkSigninSessionFields(record)
		if err != nil {
			t.Fatal("accepted record cannot be remapped", err)
		}
		changed.Fields = fields
		canonical, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		again, err := MagicLinkSigninSession(canonical)
		a, _, _ := encodeRecord(record)
		b, _, _ := encodeRecord(again)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("accepted projection is not canonically stable", err)
		}
	})
}

func TestMagicLinkSigninMappingPreservesOriginalSession(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		spec, original := magicLinkSigninMappingFixture(t, csrf)
		spec.Fields = append(spec.Fields, identity.FeatureField{Name: "magiclink.custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{1}}})
		command, err := identity.NewFeatureCommand(spec)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := MagicLinkSigninSession(command)
		if err != nil {
			t.Fatal("original consuming session denied", err)
		}
		want, _, _ := encodeRecord(original)
		got, _, _ := encodeRecord(restored)
		if !bytes.Equal(want, got) {
			t.Fatal("grant, remember, authority or CSRF changed")
		}
		bound, _ := command.Feature()
		if bound.Binding.UserID != "" || bound.Binding.AnonymousFlowID != "original-flow" {
			t.Fatal("selected user retargeted original anonymous command")
		}
		for i := range spec.Fields[:len(spec.Fields)-1] {
			changed := spec
			changed.Fields = append([]identity.FeatureField{}, spec.Fields[:i]...)
			changed.Fields = append(changed.Fields, spec.Fields[i+1:]...)
			cmd, err := identity.NewFeatureCommand(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := MagicLinkSigninSession(cmd); err == nil {
				t.Fatal("missing original field admitted", spec.Fields[i].Name)
			}
		}
	}
}

func TestMagicLinkSigninMappingRejectsForeignProfiles(t *testing.T) {
	spec, _ := magicLinkSigninMappingFixture(t, true)
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.CommandID = "BAQEBAQEBAQEBAQEBAQEBA" },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/otp" },
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion = 2; s.Binding.SchemaVersion = 2 },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "session.result.otp.challenge", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "inactive"}})
		},
	} {
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
		change(&changed)
		command, err := identity.NewFeatureCommand(changed)
		if err != nil {
			continue
		}
		if _, err := MagicLinkSigninSession(command); err == nil {
			t.Fatal("foreign/mixed profile admitted")
		}
	}
	for _, record := range []session.Session{{}, testSession(t), otpRecordFixture(t, false)} {
		if _, err := MagicLinkSigninSessionFields(record); err == nil {
			t.Fatal("non-magic-link session admitted")
		}
	}
}
