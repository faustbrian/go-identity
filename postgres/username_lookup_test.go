package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

func usernameLookupFixture() (UsernameQuery, identifierStorageRow) {
	q := UsernameQuery{TenantID: "tenant", CanonicalValue: "strasse", NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1}
	r := recipientRowFixture()
	r.kind.String, r.canonical.String, r.display.String = "username", "strasse", "Straße"
	r.verified.Bool, r.primary.Bool, r.verificationState.Int16, r.verifiedAt.Valid = false, false, 1, false
	r.normalizationProfile = pgtype.Text{String: q.NormalizationProfile, Valid: true}
	r.normalizationVersion = pgtype.Text{String: "1", Valid: true}
	return q, r
}

func TestUsernameLookupRequiresExactStoredComparisonIdentity(t *testing.T) {
	q, row := usernameLookupFixture()
	selected, err := decodeUsername(q, row, "19", "23")
	if err != nil || selected.Suppressed || selected.User.ID != "user" || selected.Identifier.Kind != identity.IdentifierUsername || selected.Identifier.CanonicalValue != "strasse" || selected.Identifier.DisplayValue != "Straße" || selected.Identifier.NormalizationProfile != q.NormalizationProfile || selected.Identifier.NormalizationVersion != 1 || selected.Verification.State != identity.VerificationPending || selected.UserAuthorityVersion != 19 || selected.IdentifierAuthorityVersion != 13 || selected.CredentialAuthorityVersion != 23 {
		t.Fatal("username discovery lost its exact primary normalization/authority snapshot", err)
	}
	for _, mode := range []string{"foreign-user", "foreign-profile", "foreign-version", "unbound", "suspended", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			q, row := usernameLookupFixture()
			switch mode {
			case "foreign-user":
				q.UserID = "other-user"
			case "foreign-profile":
				q.NormalizationProfile = "identity.username.future-v1"
			case "foreign-version":
				q.NormalizationVersion++
			case "unbound":
				row.normalizationProfile, row.normalizationVersion = pgtype.Text{}, pgtype.Text{}
			case "suspended":
				row.status = "suspended"
			case "revoked":
				row.verificationState.Int16 = 3
			}
			got, err := decodeUsername(q, row, "19", "23")
			if err != nil || !got.Suppressed || got.User != (identity.User{}) || got.Identifier != (identity.Identifier{}) || got.UserAuthorityVersion != 0 || got.IdentifierAuthorityVersion != 0 || got.CredentialAuthorityVersion != 0 || !got.ObservedAt.IsZero() {
				t.Fatal("ineligible username disclosed selected identity or authority", err)
			}
		})
	}
}

func TestUsernameLookupRejectsCorruptionAndUnownedAdmission(t *testing.T) {
	q, _ := usernameLookupFixture()
	for _, mutate := range []func(*identifierStorageRow){
		func(r *identifierStorageRow) { r.kind.String = "email" },
		func(r *identifierStorageRow) { r.canonical.String = "Straße" },
		func(r *identifierStorageRow) { r.tenant = "other" },
		func(r *identifierStorageRow) { r.normalizationVersion.String = "01" },
	} {
		_, row := usernameLookupFixture()
		mutate(&row)
		got, err := decodeUsername(q, row, "19", "23")
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || got.Query.TenantID != "" || got.User.ID != "" {
			t.Fatal("corrupt primary username became absence or authority", err)
		}
	}
	for _, invalid := range []UsernameQuery{{}, {TenantID: "tenant", CanonicalValue: "strasse"}, {TenantID: "tenant", CanonicalValue: strings.Repeat("a", 513), NormalizationProfile: q.NormalizationProfile, NormalizationVersion: 1}} {
		if invalid.Validate() == nil {
			t.Fatal("unbounded or comparison-unbound lookup accepted")
		}
	}
	for _, repo := range []*Repository{nil, {}} {
		if _, err := repo.ResolveUsername(context.Background(), q); err == nil {
			t.Fatal("unconfigured username reader admitted")
		}
	}
	_, row := usernameLookupFixture()
	record, _ := decodeUsername(q, row, "19", "23")
	if err := (Work{}).RequireUsername(context.Background(), nil, record); err == nil {
		t.Fatal("unowned username admission accepted")
	}
	if strings.Contains(fmt.Sprintf("%+v", record), q.CanonicalValue) {
		t.Fatal("username snapshot disclosed correlated identifiers")
	}
	if _, err := json.Marshal(record); err == nil {
		t.Fatal("username snapshot implicitly serialized")
	}
}
