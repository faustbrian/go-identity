package postgres

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOriginalSessionFieldsRejectAbsentExpectedUser(t *testing.T) {
	for _, original := range []session.Session{otpRecordFixture(t, false), otpRecordFixture(t, true)} {
		spec, _ := original.Bindings()
		fields, err := OriginalSessionFields(original)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := OriginalSessionFromFields(spec.TenantID, "", fields)
		if !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("absent expected user accepted", err)
		}
		if _, err := restored.Bindings(); err == nil {
			t.Fatal("denied mapping returned an authenticated session")
		}
	}
}

func TestOriginalSessionFieldsPreserveOTPAndOptionalAuthority(t *testing.T) {
	for _, original := range []session.Session{testSession(t), csrfSessionFixture(t), otpRecordFixture(t, false), otpRecordFixture(t, true)} {
		spec, _ := original.Bindings()
		fields, err := OriginalSessionFields(original)
		if err != nil {
			t.Fatal("valid original profile denied", err)
		}
		restored, err := OriginalSessionFromFields(spec.TenantID, spec.UserID, fields)
		if err != nil {
			t.Fatal(err)
		}
		want, _, _ := encodeRecord(original)
		got, _, err := encodeRecord(restored)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("complete original profile changed")
		}
	}
}

func TestOriginalSessionFieldsPreserveMagicLinkProvenance(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		original := magicLinkRecordFixture(t, csrf)
		spec, _ := original.Bindings()
		fields, err := OriginalSessionFields(original)
		if err != nil {
			t.Fatal("native workflows cannot bind original magic-link session", err)
		}
		restored, err := OriginalSessionFromFields(spec.TenantID, spec.UserID, fields)
		if err != nil {
			t.Fatal("native workflow lost original magic-link session", err)
		}
		want, _, _ := encodeRecord(original)
		got, _, err := encodeRecord(restored)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("original magic-link provenance or CSRF changed")
		}
		if _, err := mapSessionRecord(identity.CommandBinding{TenantID: spec.TenantID, UserID: spec.UserID}, session.IssueOperation(), original); err == nil {
			t.Fatal("metadata bypassed generic proof-only issuance")
		}
		for _, binding := range [][2]string{{"foreign", string(spec.UserID)}, {string(spec.TenantID), "foreign"}} {
			if _, err := OriginalSessionFromFields(identity.TenantID(binding[0]), identity.UserID(binding[1]), fields); err == nil {
				t.Fatal("original session crossed scope")
			}
		}
		for i := range fields {
			wrong := append([]identity.FeatureField(nil), fields...)
			wrong = append(wrong[:i:i], wrong[i+1:]...)
			if _, err := OriginalSessionFromFields(spec.TenantID, spec.UserID, wrong); err == nil {
				t.Fatal("incomplete original magic-link accepted", fields[i].Name)
			}
		}
		for _, field := range []identity.FeatureField{
			{Name: "source-session.authentication.kind", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(session.AuthenticationOTP)}},
			{Name: "source-session.magiclink.request", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "foreign"}},
			{Name: "source-session.credential.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "inactive"}},
		} {
			wrong := append([]identity.FeatureField(nil), fields...)
			found := false
			for i := range wrong {
				if wrong[i].Name == field.Name {
					wrong[i] = field
					found = true
				}
			}
			if !found {
				wrong = append(wrong, field)
			}
			if _, err := OriginalSessionFromFields(spec.TenantID, spec.UserID, wrong); err == nil {
				t.Fatal("foreign/inactive provenance accepted", field.Name)
			}
		}
	}
}

func TestOriginalSessionFieldsPreserveCompleteOwnedRecord(t *testing.T) {
	original, _, _ := identifierSessionFixture(t)
	original = withCSRFState(t, original, 9)
	spec, _ := original.Bindings()
	fields, err := OriginalSessionFields(original)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OriginalSessionFromFields(spec.TenantID, spec.UserID, fields)
	if err != nil {
		t.Fatal(err)
	}
	want, _, err := encodeRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := encodeRecord(restored)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("original session state lost")
	}
	for _, f := range fields {
		if !strings.HasPrefix(f.Name, "source-session.") {
			t.Fatal("mapping escaped its namespace")
		}
	}
	if _, err := OriginalSessionFromFields("foreign", spec.UserID, fields); err == nil {
		t.Fatal("cross-tenant reconstruction accepted")
	}
	for _, field := range fields {
		if field.Value.Bytes != nil {
			field.Value.Bytes[0] ^= 1
		}
	}
	after, _, _ := encodeRecord(original)
	if !bytes.Equal(after, want) {
		t.Fatal("projection changed immutable original")
	}
	after, _, _ = encodeRecord(restored)
	if !bytes.Equal(after, want) {
		t.Fatal("decoder retained caller-owned byte slices")
	}
}

func FuzzOriginalSessionFields(f *testing.F) {
	f.Add(uint8(0), "source-session.audience", "service-a")
	f.Add(uint8(17), "source-session.unknown", "other")
	f.Add(uint8(2), "source-session.magiclink.capability", "other")
	f.Fuzz(func(t *testing.T, index uint8, name, text string) {
		original := csrfSessionFixture(t)
		if index%3 == 1 {
			original = otpRecordFixture(t, true)
		}
		if index%3 == 2 {
			original = magicLinkRecordFixture(t, true)
		}
		spec, _ := original.Bindings()
		fields, err := OriginalSessionFields(original)
		if err != nil {
			t.Fatal(err)
		}
		i := int(index) % len(fields)
		fields[i].Name, fields[i].Value.Text = name, text
		restored, err := OriginalSessionFromFields(spec.TenantID, spec.UserID, fields)
		if err == nil {
			canonical, err := OriginalSessionFields(restored)
			if err != nil || len(canonical) != len(fields) {
				t.Fatal("accepted input lacked complete canonical profile")
			}
		}
	})
}

func TestOriginalSessionFieldsRejectMissingDuplicateUnknownAndInactiveData(t *testing.T) {
	original, _, _ := identifierSessionFixture(t)
	spec, _ := original.Bindings()
	for _, scenario := range []string{"missing", "duplicate", "unknown", "inactive", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			fields, err := OriginalSessionFields(original)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing":
				fields = fields[1:]
			case "duplicate":
				fields = append(fields, fields[0])
			case "unknown":
				fields = append(fields, identity.FeatureField{Name: "source-session.unknown", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}})
			case "inactive":
				fields[0].Value.Uint64 = 99
			case "oversize":
				fields[0].Value.Text = strings.Repeat("x", 4097)
			}
			if _, err := OriginalSessionFromFields(spec.TenantID, spec.UserID, fields); err == nil {
				t.Fatal("noncanonical original accepted")
			}
		})
	}
}
