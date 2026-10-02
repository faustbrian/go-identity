package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestIdentifierReadInvalidComposition(t *testing.T) {
	for _, repo := range []*Repository{nil, {}} {
		state, err := repo.GetIdentifierState(context.Background(), identity.IdentifierQuery{TenantID: "tenant", UserID: "user", MaximumIdentifiers: 128})
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) || state.User.ID != "" {
			t.Fatal("invalid directory configuration admitted")
		}
	}
}

func TestIdentifierStorageDecodeRejectsInvalidState(t *testing.T) {
	q := identity.IdentifierQuery{TenantID: "tenant", UserID: "user", MaximumIdentifiers: 128}
	now := time.Unix(100, 0).UTC()
	text := func(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }
	base := identifierStorageRow{tenant: "tenant", user: "user", status: "active", userVersion: "18446744073709551615", authority: "18446744073709551615", now: now,
		id: text("identifier"), kind: text("email"), canonical: text("synthetic@example.test"), display: text(""), version: text("1"), verificationVersion: text("1"),
		verified: pgtype.Bool{Bool: true, Valid: true}, primary: pgtype.Bool{Bool: true, Valid: true}, verificationState: pgtype.Int2{Int16: 2, Valid: true}, verifiedAt: pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true}}
	if user, authority, identifier, verification, present, err := decodeIdentifierRow(q, base); err != nil || !present || user.Version != ^uint64(0) || authority != ^uint64(0) || !identifier.Primary || verification.State != identity.VerificationVerified {
		t.Fatal("valid full-width directory row rejected", err)
	}
	for _, alter := range []func(*identifierStorageRow){
		func(r *identifierStorageRow) { r.user = "foreign" },
		func(r *identifierStorageRow) { r.tenant = "foreign" },
		func(r *identifierStorageRow) { r.userVersion = "01" },
		func(r *identifierStorageRow) { r.status = "invalid" },
		func(r *identifierStorageRow) { r.authority = "0" },
		func(r *identifierStorageRow) { r.authority = "18446744073709551616" },
		func(r *identifierStorageRow) { r.authority = "01" },
		func(r *identifierStorageRow) { r.now = time.Time{} },
		func(r *identifierStorageRow) { r.id.Valid = false },
		func(r *identifierStorageRow) { r.kind.Valid = false },
		func(r *identifierStorageRow) { r.kind = text("unknown") },
		func(r *identifierStorageRow) { r.canonical = text("bad\u0085@example.test") },
		func(r *identifierStorageRow) { r.version = text("01") },
		func(r *identifierStorageRow) { r.version = text("0") },
		func(r *identifierStorageRow) { r.verificationVersion = text("01") },
		func(r *identifierStorageRow) { r.verificationState.Int16 = 257 },
		func(r *identifierStorageRow) { r.verified.Bool = false },
		func(r *identifierStorageRow) { r.verifiedAt.Valid = false },
		func(r *identifierStorageRow) { r.verifiedAt.Time = now.Add(time.Second) },
		func(r *identifierStorageRow) { r.verifiedAt.InfinityModifier = pgtype.Infinity },
	} {
		row := base
		alter(&row)
		user, authority, identifier, verification, present, err := decodeIdentifierRow(q, row)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || user.ID != "" || authority != 0 || identifier.ID != "" || verification.IdentifierID != "" || present {
			t.Fatal("invalid storage disclosed partial directory state")
		}
	}
	empty := identifierStorageRow{tenant: "tenant", user: "user", status: "active", userVersion: "1", authority: "1", now: now}
	if user, authority, _, _, present, err := decodeIdentifierRow(q, empty); err != nil || user.ID != "user" || authority != 1 || present {
		t.Fatal("empty partition fabricated or lost authority", err)
	}
}
