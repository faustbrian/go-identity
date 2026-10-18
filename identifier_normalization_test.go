package identity

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestIdentifierLegacyJSONRemainsCanonicalWithoutNormalizationBinding(t *testing.T) {
	name := Identifier{ID: "email", UserID: "user", Kind: IdentifierEmail, CanonicalValue: "synthetic@example.test", Version: 1}
	wire, err := json.Marshal(name)
	if err != nil || string(wire) != `{"ID":"email","UserID":"user","Kind":"email","CanonicalValue":"synthetic@example.test","DisplayValue":"","Verified":false,"Primary":false,"Version":1}` {
		t.Fatal("unbound identifier changed legacy canonical JSON used by retained signup custody")
	}
	name.NormalizationProfile, name.NormalizationVersion = "identity.username.latin-v1", 1
	bound, err := json.Marshal(name)
	var restored Identifier
	if err != nil || json.Unmarshal(bound, &restored) != nil || restored != name {
		t.Fatal("explicit normalization binding did not round-trip")
	}
}

func TestIdentifierNormalizationBindingSurvivesOwnedTransitions(t *testing.T) {
	state, change, now := identifierFixture()
	change.Kind, change.CanonicalValue, change.DisplayValue = IdentifierUsername, "strasse", "Straße"
	change.NormalizationProfile, change.NormalizationVersion = "identity.username.latin-v1", 1
	got, err := ApplyIdentifierChange(state, change, now)
	if err != nil {
		t.Fatal(err)
	}
	name := got.State.Identifiers[1]
	if name.NormalizationProfile != change.NormalizationProfile || name.NormalizationVersion != 1 || name.CanonicalValue != "strasse" || name.DisplayValue != "Straße" {
		t.Fatal("attach discarded canonical policy identity")
	}
	if strings.Contains(fmt.Sprintf("%+v", name), "strasse") || strings.Contains(fmt.Sprintf("%#v", name), "latin-v1") {
		t.Fatal("normalization metadata escaped redacted identifier")
	}
	legacy := state.Identifiers[0]
	if legacy.Validate(legacy.UserID) != nil || legacy.NormalizationProfile != "" || legacy.NormalizationVersion != 0 {
		t.Fatal("existing unbound email was reinterpreted")
	}
	first, err := IdentifierIntentDigest(change)
	if err != nil {
		t.Fatal(err)
	}
	change.NormalizationVersion++
	second, err := IdentifierIntentDigest(change)
	if err != nil || first == second {
		t.Fatal("intent omitted normalization revision")
	}
}

func TestIdentifierNormalizationBindingRejectsIncompleteOrMalformedIdentity(t *testing.T) {
	state, change, now := identifierFixture()
	for _, pair := range []struct {
		id      string
		version uint32
	}{
		{"identity.username", 0}, {"", 1}, {"Uppercase", 1}, {".profile", 1},
		{"profile with space", 1}, {strings.Repeat("a", 129), 1}, {"profile\x00", 1},
	} {
		name := state.Identifiers[0]
		name.NormalizationProfile, name.NormalizationVersion = pair.id, pair.version
		if name.Validate(name.UserID) == nil {
			t.Fatal("identifier accepted incomplete or malformed profile")
		}
		change.NormalizationProfile, change.NormalizationVersion = pair.id, pair.version
		if _, err := ApplyIdentifierChange(state, change, now); err == nil {
			t.Fatal("mutation accepted incomplete or malformed profile")
		}
		if _, err := IdentifierIntentDigest(change); err == nil {
			t.Fatal("intent accepted incomplete or malformed profile")
		}
	}
}

func TestIdentifierReplacementCannotSilentlyDropBoundPolicy(t *testing.T) {
	state, attach, now := identifierFixture()
	attach.Kind, attach.CanonicalValue = IdentifierUsername, "original"
	attach.NormalizationProfile, attach.NormalizationVersion = "identity.username.latin-v1", 1
	bound, err := ApplyIdentifierChange(state, attach, now)
	if err != nil {
		t.Fatal(err)
	}
	change := IdentifierChange{TenantID: attach.TenantID, UserID: attach.UserID, ID: attach.ID,
		Action: IdentifierReplace, Kind: IdentifierUsername, CanonicalValue: "replacement",
		ExpectedUserVersion: 5, ExpectedAuthorityVersion: 3, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}
	if _, err := ApplyIdentifierChange(bound.State, change, now); err == nil {
		t.Fatal("replacement silently dropped stored comparison policy")
	}
	change.NormalizationProfile, change.NormalizationVersion = attach.NormalizationProfile, attach.NormalizationVersion
	got, err := ApplyIdentifierChange(bound.State, change, now)
	if err != nil || got.State.Identifiers[1].NormalizationProfile != attach.NormalizationProfile || got.Retired.NormalizationVersion != 1 {
		t.Fatal("explicit bound replacement lost current or retired policy", err)
	}
}
