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
	f.Fuzz(func(t *testing.T, index uint8, name, text string) {
		original := csrfSessionFixture(t)
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
