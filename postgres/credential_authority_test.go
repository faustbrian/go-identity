package postgres

import (
	"context"
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5/pgtype"
)

func credentialStoredFixture() credentialStorageRow {
	return credentialStorageRow{tenant: "tenant", user: "user", status: "active", userVersion: "7", authority: "11", id: "credential", kind: 1, owner: "identity/password", version: "13", enabled: true}
}

func TestCredentialPrimaryDecodeKeepsIndependentVersions(t *testing.T) {
	q := identity.CredentialAuthorityQuery{TenantID: "tenant", UserID: "user", CredentialID: "credential"}
	for _, v := range []uint64{1, 1<<53 + 1, 1 << 63, math.MaxUint64} {
		row := credentialStoredFixture()
		row.authority = strconv.FormatUint(v, 10)
		got, err := decodeCredentialAuthority(q, row)
		if err != nil || got.AuthorityVersion != v || got.User.Version != 7 || got.Credential.Version != 13 || !got.Enabled || !got.ExpiresAt.IsZero() {
			t.Fatal("independent primary dimensions changed", err)
		}
		row.userVersion, row.version = row.authority, row.authority
		got, err = decodeCredentialAuthority(q, row)
		if err != nil || got.User.Version != v || got.Credential.Version != v {
			t.Fatal("full unsigned precision changed", err)
		}
	}
	for _, status := range []string{"suspended", "banned", "deleted", "anonymized"} {
		row := credentialStoredFixture()
		row.status, row.enabled = status, false
		row.expires = pgtype.Timestamptz{Time: time.Date(2026, 1, 1, 0, 0, 0, 123000, time.UTC), Valid: true}
		got, err := decodeCredentialAuthority(q, row)
		if err != nil || got.User.Status != identity.Status(status) || got.Enabled || got.ExpiresAt != row.expires.Time {
			t.Fatal("terminal/expiry state was replaced", err)
		}
	}
}

func TestCredentialPrimaryDecodeRejectsCorruptOrForeign(t *testing.T) {
	q := identity.CredentialAuthorityQuery{TenantID: "tenant", UserID: "user", CredentialID: "credential"}
	mutations := []func(*credentialStorageRow){
		func(r *credentialStorageRow) { r.tenant = "foreign" },
		func(r *credentialStorageRow) { r.user = "foreign" },
		func(r *credentialStorageRow) { r.id = "foreign" },
		func(r *credentialStorageRow) { r.status = "unknown" },
		func(r *credentialStorageRow) { r.owner = "passkey" },
		func(r *credentialStorageRow) { r.kind = 257 },
		func(r *credentialStorageRow) {
			r.expires = pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.Infinity}
		},
		func(r *credentialStorageRow) { r.expires = pgtype.Timestamptz{Valid: true} },
		func(r *credentialStorageRow) {
			r.expires = pgtype.Timestamptz{Valid: true, Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
		},
		func(r *credentialStorageRow) {
			r.expires = pgtype.Timestamptz{Valid: true, Time: time.Date(2026, 1, 1, 0, 0, 0, 1, time.UTC)}
		},
	}
	for _, column := range []string{"user", "authority", "credential"} {
		for _, value := range []string{"0", "01", "+1", "1.0", "-1", "18446744073709551616", "private-invalid"} {
			mutations = append(mutations, func(r *credentialStorageRow) {
				switch column {
				case "user":
					r.userVersion = value
				case "authority":
					r.authority = value
				default:
					r.version = value
				}
			})
		}
	}
	for _, mutate := range mutations {
		row := credentialStoredFixture()
		mutate(&row)
		got, err := decodeCredentialAuthority(q, row)
		if err == nil || got != (identity.CredentialAuthorityRecord{}) {
			t.Fatal("corrupt/foreign row produced partial authority")
		}
		if _, ok := err.(identity.UnavailableError); !ok {
			t.Fatal("storage corruption leaked classification", err)
		}
	}
}

func TestCredentialPrimaryInvalidRuntime(t *testing.T) {
	for _, repo := range []*Repository{nil, {}} {
		got, err := repo.GetCredentialAuthority(context.Background(), identity.CredentialAuthorityQuery{})
		if err == nil || got != (identity.CredentialAuthorityRecord{}) {
			t.Fatal("invalid repository produced authority")
		}
	}
}

func TestCredentialMigrationPreservesInstalledHistory(t *testing.T) {
	base := StatusMigrationSource{Base: MigrationSource{}, Version: 12}
	history, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := CredentialMigrationSource{Base: base, Version: 13}
	got, err := source.Load(context.Background())
	if err != nil || len(got) != len(history)+1 {
		t.Fatal("credential history missing", err)
	}
	for i := range history {
		if got[i].Checksum() != history[i].Checksum() {
			t.Fatal("installed migration bytes changed")
		}
	}
	for _, invalid := range []CredentialMigrationSource{{}, {Base: base}, {Base: base, Version: 9}, {Base: base, Version: 12}, {Base: base, Version: migrations.Version(math.MaxUint64)}} {
		if rows, e := invalid.Load(context.Background()); e == nil || rows != nil {
			t.Fatal("invalid migration composition returned history")
		}
	}
	if rows, e := source.Load(nil); e == nil || rows != nil {
		t.Fatal("nil migration context accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, e := source.Load(canceled); !errors.Is(e, context.Canceled) || rows != nil {
		t.Fatal("migration cancellation changed", e)
	}
}
