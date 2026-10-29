package postgres

import (
	"bytes"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
)

func TestLegacyNoExpiryRecordRoundtripPreservesAbsenceAndOriginalBinding(t *testing.T) {
	x := legacyInput(t)
	spec := x.Configuration.Spec()
	spec.AllowLegacyNoExpiry = true
	var err error
	x.Configuration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	x.Record.ExpiresAt = time.Time{}
	wire, err := encodeRecord(x.Record, x.Configuration)
	if err != nil {
		t.Fatal("selected no-expiry legacy record could not be persisted", err)
	}
	restored, err := decodeRecord(wire, x.Configuration)
	if err != nil || !restored.ExpiresAt.IsZero() || !restored.CreatedAt.Equal(x.Record.CreatedAt) || restored.Owner != x.Record.Owner {
		t.Fatal("legacy roundtrip invented expiry or changed metadata", err)
	}
	again, err := encodeRecord(restored, x.Configuration)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("no-expiry record did not retain canonical bytes", err)
	}
	original, err := x.commitment()
	if err != nil {
		t.Fatal("no-expiry import lost prepared command binding", err)
	}
	x.Record.ExpiresAt = x.VerifiedAt.Add(time.Hour)
	changed, err := x.commitment()
	if err != nil || changed == original {
		t.Fatal("import intent dropped the difference between absent and present expiry", err)
	}
	spec.AllowLegacyNoExpiry = false
	finite, _ := apikey.NewConfiguration(spec)
	if _, err := decodeRecord(wire, finite); err == nil {
		t.Fatal("unselected native profile admitted absent expiry")
	}
}

func TestLegacyNoExpiryRotationRequiresFiniteModernSuccessor(t *testing.T) {
	x := creationFixture(t)
	prior := legacyInput(t)
	spec := prior.Configuration.Spec()
	spec.AllowLegacyNoExpiry = true
	var err error
	prior.Configuration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	prior.Record.ExpiresAt = time.Time{}
	x.Binding.OperationID, x.Binding.SchemaID, x.Binding.SchemaVersion = rotateOperation().OperationID, rotateOperation().SchemaID, rotateOperation().SchemaVersion
	x.PreviousRecord, x.PreviousConfiguration, x.PreviousConfigurationAuthority = &prior.Record, &prior.Configuration, &prior.ConfigurationAuthority
	x.Record.ID, x.Record.RootID, x.Binding.RecordID = "01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAW"
	x.Record.PreviousID = prior.Record.ID
	x.Record.Grant = append([]string(nil), prior.Record.Grant...)
	x.Record.ExpiresAt = x.Record.CreatedAt.Add(x.Configuration.Spec().MaximumLifetime).Truncate(time.Microsecond)
	if err := x.validate(); err != nil {
		t.Fatal("no-expiry predecessor cannot rotate under modern policy", err)
	}
	for _, expiry := range []time.Time{time.Time{}, x.Record.ExpiresAt.Add(time.Microsecond)} {
		bad := x
		bad.Record.ExpiresAt = expiry
		if err := bad.validate(); err == nil {
			t.Fatal("legacy rotation enabled an unbounded or overlong modern successor")
		}
	}
}

func FuzzLegacyNoExpiryRecordCanonicalBound(f *testing.F) {
	c, record := recordFixture(f)
	spec := c.Spec()
	spec.Algorithm, spec.State, spec.AllowLegacyNoExpiry = apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly, true
	c, err := apikey.NewConfiguration(spec)
	if err != nil {
		f.Fatal(err)
	}
	for _, absent := range []bool{true, false} {
		if absent {
			record.ExpiresAt = time.Time{}
		} else {
			record.ExpiresAt = record.CreatedAt.Add(time.Hour)
		}
		wire, err := encodeRecord(record, c)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	record.ExpiresAt = time.Time{}
	record.Owner, err = apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "organization-a", Version: 2})
	if err != nil {
		f.Fatal(err)
	}
	wire, err := encodeRecord(record, c)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add(bytes.Replace(wire, []byte(`"Schema":1`), []byte(`"Schema":1,"Secret":"forbidden"`), 1))
	f.Add(bytes.Repeat([]byte("x"), maximumRecordBytes+1))
	f.Fuzz(func(t *testing.T, input []byte) {
		r, err := decodeRecord(input, c)
		if err != nil {
			return
		}
		canonical, err := encodeRecord(r, c)
		if err != nil || len(input) > maximumRecordBytes || !bytes.Equal(input, canonical) || r.Validate(c) != nil {
			t.Fatal("legacy codec accepted noncanonical or invalid no-expiry metadata")
		}
	})
}
