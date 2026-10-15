package identity

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestIdentifierRemovalPromotesExactVerifiedPrimaryAtomically(t *testing.T) {
	state, _, now := identifierFixture()
	state.Identifiers = append(state.Identifiers, Identifier{ID: "b", UserID: state.User.ID, Kind: IdentifierEmail, CanonicalValue: "two@example.test", Verified: true, Version: 5})
	state.Verifications = append(state.Verifications, Verification{IdentifierID: "b", State: VerificationVerified, Version: 7, VerifiedAt: now})
	before := state
	before.Identifiers, before.Verifications = slices.Clone(state.Identifiers), slices.Clone(state.Verifications)
	change := IdentifierChange{TenantID: state.User.TenantID, UserID: state.User.ID, ID: "a", Action: IdentifierRemove, ExpectedUserVersion: 4, ExpectedAuthorityVersion: 2, ExpectedIdentifierVersion: 3, ExpectedVerificationVersion: 2}
	selection := IdentifierPrimarySelection{ID: "b", ExpectedIdentifierVersion: 5, ExpectedVerificationVersion: 7}
	got, err := ApplyIdentifierRemovalWithPrimary(state, change, selection, now)
	if err != nil || got.Retired == nil || got.Retired.ID != "a" || len(got.State.Identifiers) != 1 || got.State.Identifiers[0].ID != "b" || !got.State.Identifiers[0].Primary || got.State.Identifiers[0].Version != 6 || got.State.Verifications[0] != state.Verifications[1] || got.State.User.Version != 5 || got.State.AuthorityVersion != 3 || !reflect.DeepEqual(before, state) {
		t.Fatal("removal did not conserve one atomic versioned primary transition", err)
	}
	for _, mode := range []string{"same", "absent", "stale-identifier", "stale-verification", "zero", "overflow", "pending", "wrong-kind", "nonprimary-target"} {
		t.Run(mode, func(t *testing.T) {
			s, p := state, selection
			s.Identifiers, s.Verifications = slices.Clone(state.Identifiers), slices.Clone(state.Verifications)
			switch mode {
			case "same":
				p.ID = "a"
			case "absent":
				p.ID = "c"
			case "stale-identifier":
				p.ExpectedIdentifierVersion++
			case "stale-verification":
				p.ExpectedVerificationVersion++
			case "zero":
				p.ExpectedIdentifierVersion = 0
			case "overflow":
				p.ExpectedIdentifierVersion = ^uint64(0)
				s.Identifiers[1].Version = ^uint64(0)
			case "pending":
				s.Identifiers[1].Verified = false
				s.Verifications[1].State = VerificationPending
				s.Verifications[1].VerifiedAt = time.Time{}
			case "wrong-kind":
				s.Identifiers[1].Kind = IdentifierUsername
			case "nonprimary-target":
				s.Identifiers[0].Primary = false
			}
			if result, err := ApplyIdentifierRemovalWithPrimary(s, change, p, now); err == nil || !reflect.DeepEqual(result, IdentifierMutation{}) {
				t.Fatal("unsafe replacement admitted", mode)
			}
		})
	}
}

func TestIdentifierRemovalDoesNotInferReplacementFromOrder(t *testing.T) {
	state, _, now := identifierFixture()
	for _, id := range []IdentifierID{"b", "c"} {
		state.Identifiers = append(state.Identifiers, Identifier{ID: id, UserID: state.User.ID, Kind: IdentifierEmail, CanonicalValue: string(id) + "@example.test", Verified: true, Version: 5})
		state.Verifications = append(state.Verifications, Verification{IdentifierID: id, State: VerificationVerified, Version: 7, VerifiedAt: now})
	}
	change := IdentifierChange{TenantID: state.User.TenantID, UserID: state.User.ID, ID: "a", Action: IdentifierRemove, ExpectedUserVersion: 4, ExpectedAuthorityVersion: 2, ExpectedIdentifierVersion: 3, ExpectedVerificationVersion: 2}
	got, err := ApplyIdentifierRemovalWithPrimary(state, change, IdentifierPrimarySelection{ID: "c", ExpectedIdentifierVersion: 5, ExpectedVerificationVersion: 7}, now)
	if err != nil || len(got.State.Identifiers) != 2 || got.State.Identifiers[0] != state.Identifiers[1] || !got.State.Identifiers[1].Primary || got.State.Identifiers[1].ID != "c" || got.State.Identifiers[1].Version != 6 || got.State.Verifications[1] != state.Verifications[2] {
		t.Fatal("removal promoted an inferred or unrelated replacement", err)
	}
}
