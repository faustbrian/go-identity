package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestPasswordRegistrationBindsNormalizationPolicy(t *testing.T) {
	intent := registrationIntentFixture()
	legacy, err := PasswordRegistrationFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(fields []identity.FeatureField) []byte {
		t.Helper()
		value, err := encodeFeature(identity.FeatureCommandSpec{Fields: fields}, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		return cborMap(value)
	}
	intent.Identifier.NormalizationProfile, intent.Identifier.NormalizationVersion = "identity.email-v1", 1
	bound, err := PasswordRegistrationFields(intent)
	if err != nil || bytes.Equal(encode(legacy), encode(bound)) {
		t.Fatal("registration command omitted normalization binding", err)
	}
	intent.Identifier.NormalizationVersion++
	revised, err := PasswordRegistrationFields(intent)
	if err != nil || bytes.Equal(encode(bound), encode(revised)) {
		t.Fatal("registration command omitted normalization revision", err)
	}
}

func TestIdentifierStoragePreservesExactNormalizationBinding(t *testing.T) {
	text := func(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }
	q := identity.IdentifierQuery{TenantID: "tenant", UserID: "user", MaximumIdentifiers: 128}
	row := identifierStorageRow{tenant: "tenant", user: "user", status: "active", userVersion: "1", authority: "1", now: time.Unix(100, 0).UTC(),
		id: text("name"), kind: text("username"), canonical: text("strasse"), display: text("Straße"), version: text("1"), verificationVersion: text("1"),
		verified: pgtype.Bool{Valid: true}, primary: pgtype.Bool{Valid: true}, verificationState: pgtype.Int2{Int16: 1, Valid: true},
		normalizationProfile: text("identity.username.latin-v1"), normalizationVersion: text("4294967295")}
	_, _, got, _, present, err := decodeIdentifierRow(q, row)
	if err != nil || !present || got.NormalizationProfile != row.normalizationProfile.String || got.NormalizationVersion != ^uint32(0) || got.CanonicalValue != "strasse" || got.DisplayValue != "Straße" {
		t.Fatal("storage projection lost canonical policy identity", err)
	}
	for _, alter := range []func(*identifierStorageRow){
		func(r *identifierStorageRow) { r.normalizationProfile.Valid = false },
		func(r *identifierStorageRow) { r.normalizationVersion.Valid = false },
		func(r *identifierStorageRow) { r.normalizationProfile = text("Uppercase") },
		func(r *identifierStorageRow) { r.normalizationVersion = text("4294967296") },
		func(r *identifierStorageRow) { r.normalizationVersion = text("01") },
		func(r *identifierStorageRow) { r.normalizationVersion = text("0") },
		func(r *identifierStorageRow) { r.normalizationVersion = text("1.0") },
		func(r *identifierStorageRow) { r.id.Valid = false },
	} {
		bad := row
		alter(&bad)
		user, authority, got, _, present, err := decodeIdentifierRow(q, bad)
		if err == nil || present || user.ID != "" || authority != 0 || got.ID != "" {
			t.Fatal("malformed normalization binding disclosed partial identity")
		}
	}
	row.normalizationProfile, row.normalizationVersion = pgtype.Text{}, pgtype.Text{}
	if _, _, got, _, _, err := decodeIdentifierRow(q, row); err != nil || got.NormalizationProfile != "" || got.NormalizationVersion != 0 {
		t.Fatal("legacy schema was reinterpreted or rejected", err)
	}
	row.normalizationProfile, row.normalizationVersion = text(""), text("0")
	if _, _, got, _, _, err := decodeIdentifierRow(q, row); err != nil || got.NormalizationProfile != "" || got.NormalizationVersion != 0 {
		t.Fatal("explicit unbound migrated row was reinterpreted", err)
	}
}
