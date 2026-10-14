//go:build integration

package postgres

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testIdentifierReads(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	q := identity.IdentifierQuery{TenantID: "directory-a", UserID: "directory-user", MaximumIdentifiers: 128}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('directory-a','directory-user','active',18446744073709551615),('directory-b','directory-user','banned',1)`); err != nil {
		t.Fatal(err)
	}
	state, err := repo.GetIdentifierState(ctx, q)
	if err != nil || state.User.Version != math.MaxUint64 || state.AuthorityVersion != 1 || len(state.Identifiers) != 0 || len(state.Verifications) != 0 {
		t.Fatal("empty authoritative identifier partition", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
	insert := func(tenant, id, value string, verified, primary bool, status int16, at any) error {
		_, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,'directory-user',$2,'email',$3,'Display@example.test',$4,$5,18446744073709551615,$6,18446744073709551615,$7)`, tenant, id, value, verified, primary, status, at)
		return err
	}
	if err := insert("directory-a", "z", "second@example.test", false, false, 1, nil); err != nil {
		t.Fatal(err)
	}
	if err := insert("directory-a", "a", "first@example.test", true, true, 2, now); err != nil {
		t.Fatal(err)
	}
	if err := insert("directory-b", "a", "first@example.test", false, false, 3, now); err != nil {
		t.Fatal("tenant-local value and ID uniqueness", err)
	}
	state, err = repo.GetIdentifierState(ctx, q)
	if err != nil || len(state.Identifiers) != 2 || state.Identifiers[0].ID != "a" || state.Identifiers[1].ID != "z" || state.Identifiers[0].Version != math.MaxUint64 || !state.Identifiers[0].Primary || state.Verifications[0].Version != math.MaxUint64 || !state.Verifications[0].VerifiedAt.Equal(now) || state.Verifications[1].State != identity.VerificationPending {
		t.Fatal("complete ordered identifier/verification read", err)
	}
	state.Identifiers[0].CanonicalValue = "caller mutation"
	again, err := repo.GetIdentifierState(ctx, q)
	if err != nil || again.Identifiers[0].CanonicalValue != "first@example.test" {
		t.Fatal("caller modified retained directory state", err)
	}
	foreign := q
	foreign.TenantID = "directory-b"
	other, err := repo.GetIdentifierState(ctx, foreign)
	if err != nil || other.User.Status != identity.StatusBanned || len(other.Identifiers) != 1 || other.Identifiers[0].Verified || other.Verifications[0].State != identity.VerificationRevoked {
		t.Fatal("foreign tenant directory crossed scope", err)
	}
	q.MaximumIdentifiers = 1
	partial, err := repo.GetIdentifierState(ctx, q)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || partial.User.ID != "" || len(partial.Identifiers) != 0 {
		t.Fatal("oversized partition silently truncated", err)
	}
	q.MaximumIdentifiers = 128
	for _, maximum := range []uint16{0, 129} {
		invalid := q
		invalid.MaximumIdentifiers = maximum
		var input identity.InvalidInputError
		if state, err := repo.GetIdentifierState(ctx, invalid); !errors.As(err, &input) || state.User.ID != "" {
			t.Fatal("unbounded directory query admitted", err)
		}
	}
	for _, candidate := range []struct {
		id, value         string
		verified, primary bool
		status            int16
		at                any
	}{
		{"duplicate-value", "first@example.test", false, false, 1, nil},
		{"second-primary", "primary@example.test", true, true, 2, now},
		{"unverified-primary", "invalid@example.test", false, true, 1, nil},
		{"missing-time", "time@example.test", true, false, 2, nil},
		{"pending-time", "pending@example.test", false, false, 1, now},
		{"control", "bad\u0085@example.test", false, false, 1, nil},
	} {
		if err := insert("directory-a", candidate.id, candidate.value, candidate.verified, candidate.primary, candidate.status, candidate.at); err == nil {
			t.Fatal("invalid durable directory state accepted", candidate.id)
		}
	}
	missing := q
	missing.TenantID = "directory-absent"
	if state, err := repo.GetIdentifierState(ctx, missing); !errors.Is(err, identity.ErrUserAbsent) || state.User.ID != "" {
		t.Fatal("missing directory fabricated state", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if state, err := repo.GetIdentifierState(cancelled, q); !errors.Is(err, context.Canceled) || state.User.ID != "" {
		t.Fatal("cancelled directory leaked partial state", err)
	}
	if err := insert("directory-a", "future", "future@example.test", true, false, 2, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if state, err := repo.GetIdentifierState(ctx, q); !errors.As(err, &unavailable) || state.User.ID != "" || len(state.Identifiers) != 0 {
		t.Fatal("future verification time returned partial partition", err)
	}
}
