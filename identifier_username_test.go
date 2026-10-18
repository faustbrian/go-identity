package identity

import (
	"reflect"
	"slices"
	"testing"
)

func TestIdentifierUsernameRenamePreservesDisplayOnlyVerification(t *testing.T) {
	state, change, now := identifierFixture()
	state.Identifiers[0].Kind = IdentifierUsername
	state.Identifiers[0].CanonicalValue, state.Identifiers[0].DisplayValue = "strasse", "Straße"
	state.Identifiers[0].NormalizationProfile, state.Identifiers[0].NormalizationVersion = "identity.username.latin-v1", 1
	before := state
	before.Identifiers, before.Verifications = slices.Clone(state.Identifiers), slices.Clone(state.Verifications)
	change.Action, change.ID, change.Kind = IdentifierRename, "a", IdentifierUsername
	change.CanonicalValue, change.DisplayValue = "strasse", "STRASSE"
	change.NormalizationProfile, change.NormalizationVersion = "identity.username.latin-v1", 1
	change.ExpectedIdentifierVersion, change.ExpectedVerificationVersion = 3, 2
	got, err := ApplyIdentifierChange(state, change, now)
	if err != nil {
		t.Fatal("native username display edit has no identifier transition", err)
	}
	want := state.Identifiers[0]
	want.DisplayValue, want.Version = "STRASSE", want.Version+1
	if got.State.Identifiers[0] != want || got.State.Verifications[0] != state.Verifications[0] || got.Retired != nil || got.RetiredVerification != nil || got.State.User.Version != state.User.Version+1 || got.State.AuthorityVersion != state.AuthorityVersion+1 {
		t.Fatal("display-only username rename changed ownership, possession, time or retirement")
	}
	if !reflect.DeepEqual(before, state) {
		t.Fatal("rename mutated caller-owned state")
	}
	if _, err := IdentifierIntentDigest(change); err != nil {
		t.Fatal("native username rename cannot bind original intent", err)
	}
	if identifierOperation(change.Action) != "" {
		t.Fatal("generic identifier command exposed username workflow policy")
	}
	if out, err := ApplyIdentifierChange(got.State, change, now); err == nil || !reflect.DeepEqual(out, IdentifierMutation{}) {
		t.Fatal("stale username rename remained usable")
	}
}

func TestIdentifierUsernameRenameRetiresOnlyChangedCanonicalValue(t *testing.T) {
	state, change, now := identifierFixture()
	state.Identifiers[0].Kind = IdentifierUsername
	state.Identifiers[0].CanonicalValue, state.Identifiers[0].DisplayValue = "original", "Original"
	state.Identifiers[0].NormalizationProfile, state.Identifiers[0].NormalizationVersion = "identity.username.latin-v1", 1
	change.Action, change.ID, change.Kind = IdentifierRename, "a", IdentifierUsername
	change.CanonicalValue, change.DisplayValue = "successor", "Successor"
	change.NormalizationProfile, change.NormalizationVersion = "identity.username.latin-v1", 1
	change.ExpectedIdentifierVersion, change.ExpectedVerificationVersion = 3, 2
	got, err := ApplyIdentifierChange(state, change, now)
	if err != nil {
		t.Fatal("native username rename has no identifier transition", err)
	}
	if got.Retired == nil || *got.Retired != state.Identifiers[0] || got.RetiredVerification == nil || *got.RetiredVerification != state.Verifications[0] || got.State.Identifiers[0].ID != "a" || got.State.Identifiers[0].CanonicalValue != "successor" || got.State.Identifiers[0].DisplayValue != "Successor" || got.State.Identifiers[0].Version != 4 || got.State.Identifiers[0].Verified || got.State.Identifiers[0].Primary || got.State.Verifications[0].State != VerificationPending || got.State.Verifications[0].Version != 3 || !got.State.Verifications[0].VerifiedAt.IsZero() {
		t.Fatal("changed username retained predecessor possession or lost exact retirement")
	}
	for _, mode := range []string{"same-display", "foreign-kind", "changed-profile", "unbound", "revoked", "stale-verification"} {
		t.Run(mode, func(t *testing.T) {
			current, request := state, change
			current.Identifiers, current.Verifications = slices.Clone(state.Identifiers), slices.Clone(state.Verifications)
			switch mode {
			case "same-display":
				request.CanonicalValue, request.DisplayValue = "original", "Original"
			case "foreign-kind":
				request.Kind = IdentifierEmail
			case "changed-profile":
				request.NormalizationVersion++
			case "unbound":
				request.NormalizationProfile, request.NormalizationVersion = "", 0
			case "revoked":
				current.Identifiers[0].Verified, current.Identifiers[0].Primary = false, false
				current.Verifications[0].State = VerificationRevoked
			case "stale-verification":
				request.ExpectedVerificationVersion++
			}
			if out, err := ApplyIdentifierChange(current, request, now); err == nil || !reflect.DeepEqual(out, IdentifierMutation{}) {
				t.Fatal("invalid username rename admitted partial state")
			}
		})
	}
}
