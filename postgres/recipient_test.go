package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

func recipientRowFixture() identifierStorageRow {
	now := time.Unix(100, 0).UTC()
	text := func(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }
	return identifierStorageRow{tenant: "tenant", user: "user", status: "active", userVersion: "7", authority: "13", now: now,
		id: text("identifier"), kind: text("email"), canonical: text("Canonical@example.test"), display: text("display@example.test"), version: text("11"), verificationVersion: text("17"),
		verified: pgtype.Bool{Bool: true, Valid: true}, primary: pgtype.Bool{Bool: true, Valid: true}, verificationState: pgtype.Int2{Int16: 2, Valid: true}, verifiedAt: pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true}}
}

func TestRecipientSnapshotUsesCanonicalDatabaseInstants(t *testing.T) {
	q := RecipientQuery{TenantID: "tenant", Kind: identity.IdentifierEmail, CanonicalValue: "Canonical@example.test", Eligibility: RecipientVerified}
	row := recipientRowFixture()
	original, err := decodeRecipient(q, row, "19", "23")
	if err != nil {
		t.Fatal(err)
	}
	row.verifiedAt.Time = row.verifiedAt.Time.In(time.FixedZone("database-client", 3600))
	row.now = row.now.In(time.FixedZone("database-client", 3600))
	current, err := decodeRecipient(q, row, "19", "23")
	if err != nil || current.Verification != original.Verification || current.ObservedAt != original.ObservedAt {
		t.Fatal("equal database instants changed recipient custody", err)
	}
}

func TestRecipientResolutionPreservesCanonicalAndSuppressesIneligible(t *testing.T) {
	query := RecipientQuery{TenantID: "tenant", Kind: identity.IdentifierEmail, CanonicalValue: "Canonical@example.test", Eligibility: RecipientVerified}
	record, err := decodeRecipient(query, recipientRowFixture(), "19", "23")
	if err != nil || record.Suppressed || record.Identifier.CanonicalValue != query.CanonicalValue || record.Identifier.DisplayValue != "display@example.test" || record.IdentifierAuthorityVersion != 13 || record.UserAuthorityVersion != 19 || record.CredentialAuthorityVersion != 23 {
		t.Fatal("canonical recipient lost original primary state", err)
	}
	for _, mode := range []string{"foreign-subject", "banned", "pending", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			q, row := query, recipientRowFixture()
			switch mode {
			case "foreign-subject":
				q.UserID = "another-user"
			case "banned":
				row.status = "banned"
			case "pending":
				row.verified.Bool, row.primary.Bool, row.verificationState.Int16, row.verifiedAt.Valid = false, false, 1, false
			case "revoked":
				row.verified.Bool, row.primary.Bool, row.verificationState.Int16 = false, false, 3
			}
			got, err := decodeRecipient(q, row, "19", "23")
			if err != nil || !got.Suppressed || got.User.ID != "" || got.Identifier.ID != "" || got.Verification.IdentifierID != "" || got.UserAuthorityVersion != 0 {
				t.Fatal("ineligible recipient leaked selected identity", err)
			}
		})
	}
	row := recipientRowFixture()
	row.verified.Bool, row.primary.Bool, row.verificationState.Int16, row.verifiedAt.Valid = false, false, 1, false
	query.Eligibility = RecipientPendingOrVerified
	if got, err := decodeRecipient(query, row, "19", "23"); err != nil || got.Suppressed || got.Verification.State != identity.VerificationPending {
		t.Fatal("pending verification recipient was treated as signin eligibility", err)
	}
}

func TestRecipientRejectsCorruptionAndInvalidInvocation(t *testing.T) {
	q := RecipientQuery{TenantID: "tenant", Kind: identity.IdentifierEmail, CanonicalValue: "Canonical@example.test", Eligibility: RecipientVerified}
	for _, change := range []func(*identifierStorageRow){
		func(r *identifierStorageRow) { r.tenant = "other" },
		func(r *identifierStorageRow) { r.canonical.String = "canonical@example.test" },
		func(r *identifierStorageRow) { r.kind.String = "phone" },
		func(r *identifierStorageRow) { r.verificationVersion.String = "01" },
		func(r *identifierStorageRow) { r.verifiedAt.Time = r.now.Add(time.Second) },
	} {
		row := recipientRowFixture()
		change(&row)
		got, err := decodeRecipient(q, row, "19", "23")
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || got.Query.TenantID != "" || got.Identifier.ID != "" {
			t.Fatal("corrupt primary row became absence or recipient", err)
		}
	}
	for _, version := range []string{"0", "01", "18446744073709551616"} {
		if _, err := decodeRecipient(q, recipientRowFixture(), version, "23"); err == nil {
			t.Fatal("corrupt user authority accepted")
		}
	}
	for _, invalid := range []RecipientQuery{{}, {TenantID: "tenant", Kind: identity.IdentifierEmail, CanonicalValue: strings.Repeat("x", 513), Eligibility: RecipientVerified}, {TenantID: "tenant", Kind: identity.IdentifierUsername, CanonicalValue: "name", Eligibility: RecipientVerified}} {
		if err := invalid.Validate(); err == nil {
			t.Fatal("invalid recipient query accepted")
		}
	}
	for _, repo := range []*Repository{nil, {}} {
		if _, err := repo.ResolveRecipient(context.Background(), q); err == nil {
			t.Fatal("unconfigured recipient reader admitted")
		}
	}
	record, _ := decodeRecipient(q, recipientRowFixture(), "19", "23")
	if strings.Contains(fmt.Sprintf("%+v", record), q.CanonicalValue) {
		t.Fatal("recipient entered diagnostics")
	}
	if _, err := json.Marshal(record); err == nil {
		t.Fatal("recipient serialized correlated custody")
	}
	if err := (Work{}).RequireRecipient(context.Background(), nil, record); err == nil {
		t.Fatal("unowned recipient fence admitted")
	}
}
