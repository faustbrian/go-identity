package email

import (
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestChangePolicyRejectsDuplicateCanonicalPartition(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	state := identity.IdentifierState{
		User: identity.User{ID: "user", TenantID: "tenant", Status: identity.StatusActive, Version: 9}, AuthorityVersion: 4,
		Identifiers: []identity.Identifier{
			{ID: "old", UserID: "user", Kind: identity.IdentifierEmail, CanonicalValue: "old@example.test", Verified: true, Primary: true, Version: 2},
			{ID: "other", UserID: "user", Kind: identity.IdentifierEmail, CanonicalValue: "old@example.test", Verified: true, Version: 7},
		},
		Verifications: []identity.Verification{
			{IdentifierID: "old", State: identity.VerificationVerified, Version: 2, VerifiedAt: now.Add(-time.Hour)},
			{IdentifierID: "other", State: identity.VerificationVerified, Version: 6, VerifiedAt: now.Add(-time.Minute)},
		},
	}
	for _, policy := range []CurrentAddressPolicy{RequirePrimaryAddress, PrimaryOrSoleVerifiedAddress} {
		got, err := (ChangeProfile{CurrentAddress: policy, Sessions: InvalidateIdentifierSessions}).SelectPrevious(state, "candidate", now)
		if !errors.Is(err, ErrInvalidVerification) || got != (PreviousAddress{}) {
			t.Fatal("inconsistent canonical partition selected a previous address")
		}
	}
}

func TestChangePolicySelectsOriginalAddressWithoutInventingPrimary(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	state := identity.IdentifierState{User: identity.User{ID: "user", TenantID: "tenant", Status: identity.StatusActive, Version: 9}, AuthorityVersion: 4, Identifiers: []identity.Identifier{{ID: "old", UserID: "user", Kind: identity.IdentifierEmail, CanonicalValue: "old@example.test", Verified: true, Version: 2}}, Verifications: []identity.Verification{{IdentifierID: "old", State: identity.VerificationVerified, Version: 2, VerifiedAt: now.Add(-time.Hour)}}}
	strict := ChangeProfile{CurrentAddress: RequirePrimaryAddress, Sessions: InvalidateIdentifierSessions}
	if _, err := strict.SelectPrevious(state, "candidate", now); err == nil {
		t.Fatal("strict primary policy inferred an original primary")
	}
	selected := ChangeProfile{CurrentAddress: PrimaryOrSoleVerifiedAddress, Sessions: InvalidateIdentifierSessions}
	old, err := selected.SelectPrevious(state, "candidate", now)
	if err != nil || old.ID != "old" || old.Primary || old.IdentifierVersion != 2 || old.VerificationVersion != 2 || state.Identifiers[0].Primary {
		t.Fatal("explicit initial-primary policy lost original identity", err)
	}
	state.Identifiers = append(state.Identifiers, identity.Identifier{ID: "other", UserID: "user", Kind: identity.IdentifierEmail, CanonicalValue: "other@example.test", Verified: true, Version: 7})
	state.Verifications = append(state.Verifications, identity.Verification{IdentifierID: "other", State: identity.VerificationVerified, Version: 6, VerifiedAt: now.Add(-time.Minute)})
	if _, err := selected.SelectPrevious(state, "candidate", now); err == nil {
		t.Fatal("ambiguous original address was picked by ordering")
	}
	state.Identifiers[1].Primary = true
	old, err = strict.SelectPrevious(state, "candidate", now)
	if err != nil || old.ID != "other" || !old.Primary || old.IdentifierVersion != 7 || old.VerificationVersion != 6 {
		t.Fatal("true primary selection lost independent versions", err)
	}
	state.Identifiers[0].Primary = true
	if _, err := strict.SelectPrevious(state, "candidate", now); err == nil {
		t.Fatal("multiple primaries admitted")
	}
	if _, err := (ChangeProfile{}).SelectPrevious(state, "candidate", now); err == nil {
		t.Fatal("zero change policy enabled mutation")
	}
}
