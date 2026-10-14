package postgres

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

func passwordSigninMappingFixture(t testing.TB, anonymous, csrf bool) (identity.FeatureCommandSpec, session.Session, primitive.Secret, auth.BearerCredential) {
	t.Helper()
	record, _, _ := identifierSessionFixture(t)
	s, _ := record.Bindings()
	s.Version = 1
	a, _ := s.Authority.Bindings()
	a.Session.Version = 1
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	var err error
	record, err = session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	if csrf {
		record = withCSRFState(t, record, 23)
	}
	b := revokeBinding()
	b.TenantID, b.UserID = s.TenantID, s.UserID
	b.OperationID, b.SchemaID, b.RecordID = "identity.password.signin", "password-signin", ""
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if anonymous {
		b.UserID, b.AnonymousFlowID = "", "original-password-flow"
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	p, err := primitive.NewSecret([]byte("synthetic-mapping-password"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Destroy)
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{21}, 32)))
	fields, err := PasswordSigninSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	return identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, record, p, cookie
}

func TestPasswordSigninMappingPreservesOriginalSession(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for _, csrf := range []bool{false, true} {
			spec, original, p, cookie := passwordSigninMappingFixture(t, anonymous, csrf)
			spec.Fields = append(spec.Fields, identity.FeatureField{Name: "password.native-intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "owned-by-password"}})
			command, err := identity.NewFeaturePasswordSigninCommand(spec, p, cookie)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := PasswordSigninSession(command)
			if err != nil {
				t.Fatal("original password session rejected", err)
			}
			want, _, _ := encodeRecord(original)
			got, _, _ := encodeRecord(restored)
			if !bytes.Equal(want, got) {
				t.Fatal("original user/authentication/authority/remember/CSRF changed")
			}
			f, _ := command.PasswordSigninFeature()
			if f.Binding != spec.Binding {
				t.Fatal("mapping changed anonymous command scope")
			}
			for i := range spec.Fields[:len(spec.Fields)-1] {
				changed := spec
				changed.Fields = append([]identity.FeatureField{}, spec.Fields[:i]...)
				changed.Fields = append(changed.Fields, spec.Fields[i+1:]...)
				cmd, err := identity.NewFeaturePasswordSigninCommand(changed, p, cookie)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := PasswordSigninSession(cmd); err == nil {
					t.Fatalf("omitted %s admitted", spec.Fields[i].Name)
				}
				changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
				changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureBool}
				if spec.Fields[i].Value.Kind == identity.FeatureBool {
					changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureText}
				}
				cmd, err = identity.NewFeaturePasswordSigninCommand(changed, p, cookie)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := PasswordSigninSession(cmd); err == nil {
					t.Fatalf("wrong scalar kind for %s admitted", spec.Fields[i].Name)
				}
			}
			plain, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := PasswordSigninSession(plain); !errors.Is(err, session.ErrInvalidSessionCommand) {
				t.Fatal("plain metadata substituted for paired command")
			}
		}
	}
}

func TestPasswordSigninMappingRejectsForeignAndUnsupportedProfiles(t *testing.T) {
	spec, _, p, cookie := passwordSigninMappingFixture(t, true, false)
	for _, name := range []string{"session.result.tenant.id", "session.result.user.id", "session.result.proof.method", "session.result.proof.assurance", "session.result.unknown"} {
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
		found := false
		for i := range changed.Fields {
			if changed.Fields[i].Name == name {
				changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: "foreign"}
				found = true
			}
		}
		if !found {
			changed.Fields = append(changed.Fields, identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "foreign"}})
		}
		cmd, err := identity.NewFeaturePasswordSigninCommand(changed, p, cookie)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PasswordSigninSession(cmd); err == nil {
			t.Fatalf("foreign/unknown %s admitted", name)
		}
	}
	for _, record := range []session.Session{session.Session{}, testSession(t), otpRecordFixture(t, false), continuedRecordFixture(t, false)} {
		if _, err := PasswordSigninSessionFields(record); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("unsupported issuance profile mapped", err)
		}
	}
	cmd, err := identity.NewFeaturePasswordSigninCommand(spec, p, cookie)
	if err != nil {
		t.Fatal(err)
	}
	p.Destroy()
	if _, err := PasswordSigninSession(cmd); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("destroyed input reconstructed")
	}
}

func TestPasswordSigninMappingRejectsNoncanonicalValues(t *testing.T) {
	spec, _, p, cookie := passwordSigninMappingFixture(t, true, true)
	for name, value := range map[string]identity.FeatureValue{
		"lookup.version":   {Kind: identity.FeatureUint64, Uint64: 1 << 32},
		"lookup.digest":    {Kind: identity.FeatureBytes, Bytes: []byte{1}},
		"remember.choice":  {Kind: identity.FeatureUint64, Uint64: 256},
		"proof.method":     {Kind: identity.FeatureText, Text: "passkey"},
		"proof.assurance":  {Kind: identity.FeatureUint64, Uint64: uint64(auth.AssuranceMultiFactor)},
		"proof.expires":    {Kind: identity.FeatureText, Text: "2020-01-01T00:00:00Z"},
		"session.issued":   {Kind: identity.FeatureText, Text: "2026-10-03T00:00:00+00:00"},
		"session.activity": {Kind: identity.FeatureText, Text: "2026-10-03T00:01:00.123456789Z"},
		"csrf.key-version": {Kind: identity.FeatureUint64, Uint64: 1 << 32},
		"csrf.digest":      {Kind: identity.FeatureBytes, Bytes: []byte{1}},
		"tenant.id":        {Kind: identity.FeatureText, Text: "tenant-a", Uint64: 1},
	} {
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
		found := false
		for i := range changed.Fields {
			if changed.Fields[i].Name == passwordSessionPrefix+name {
				changed.Fields[i].Value, found = value, true
			}
		}
		if !found {
			t.Fatalf("missing fixture field %s", name)
		}
		cmd, err := identity.NewFeaturePasswordSigninCommand(changed, p, cookie)
		// Root command validation may itself reject inactive tagged data.
		if err != nil {
			continue
		}
		if _, err := PasswordSigninSession(cmd); err == nil {
			t.Fatalf("noncanonical %s admitted", name)
		}
	}
}

func FuzzPasswordSigninSessionMapping(f *testing.F) {
	f.Add(uint8(0), "invalid")
	f.Add(uint8(12), "password")
	f.Add(uint8(32), "2026-10-03T00:00:00Z")
	spec, _, p, cookie := passwordSigninMappingFixture(f, true, true)
	f.Fuzz(func(t *testing.T, index uint8, raw string) {
		if len(raw) > 4096 {
			return
		}
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
		i := int(index) % len(changed.Fields)
		changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: raw}
		cmd, err := identity.NewFeaturePasswordSigninCommand(changed, p, cookie)
		if err != nil {
			return
		}
		restored, err := PasswordSigninSession(cmd)
		if err != nil {
			return
		}
		fields, err := PasswordSigninSessionFields(restored)
		if err != nil {
			t.Fatal("accepted record cannot remap", err)
		}
		changed.Fields = fields
		again, err := identity.NewFeaturePasswordSigninCommand(changed, p, cookie)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PasswordSigninSession(again); err != nil {
			t.Fatal("canonical accepted record rejected", err)
		}
	})
}
