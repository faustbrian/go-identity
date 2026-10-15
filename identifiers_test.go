package identity

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func identifierFixture() (IdentifierState, IdentifierChange, time.Time) {
	now := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	state := IdentifierState{
		User: User{ID: "user-1", TenantID: "tenant-1", Status: StatusActive, Version: 4}, AuthorityVersion: 2,
		Identifiers:   []Identifier{{ID: "a", UserID: "user-1", Kind: IdentifierEmail, CanonicalValue: "one@example.test", DisplayValue: "One@example.test", Verified: true, Primary: true, Version: 3}},
		Verifications: []Verification{{IdentifierID: "a", State: VerificationVerified, VerifiedAt: now.Add(-time.Hour), Version: 2}},
	}
	change := IdentifierChange{TenantID: "tenant-1", UserID: "user-1", Action: IdentifierAttach, ID: "b", Kind: IdentifierEmail, CanonicalValue: "two@example.test", ExpectedUserVersion: 4, ExpectedAuthorityVersion: 2}
	return state, change, now
}

func TestIdentifierVerifyPrimaryIsOneAtomicTransition(t *testing.T) {
	state, attach, now := identifierFixture()
	pending, err := ApplyIdentifierChange(state, attach, now)
	if err != nil {
		t.Fatal(err)
	}
	before := pending.State
	before.Identifiers = slices.Clone(before.Identifiers)
	before.Verifications = slices.Clone(before.Verifications)
	change := IdentifierChange{TenantID: attach.TenantID, UserID: attach.UserID, ID: attach.ID, Action: IdentifierVerifyPrimary, ExpectedUserVersion: 5, ExpectedAuthorityVersion: 3, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}
	got, err := ApplyIdentifierChange(pending.State, change, now.Add(time.Minute))
	if err != nil {
		t.Fatal("pending email has no atomic verified-primary transition", err)
	}
	if got.State.User.Version != 6 || got.State.AuthorityVersion != 4 || got.State.Identifiers[0].Primary || !got.State.Identifiers[0].Verified || got.State.Identifiers[0].Version != 4 || got.State.Verifications[0] != before.Verifications[0] || !got.State.Identifiers[1].Primary || !got.State.Identifiers[1].Verified || got.State.Identifiers[1].Version != 2 || got.State.Verifications[1].Version != 2 || !got.State.Verifications[1].VerifiedAt.Equal(now.Add(time.Minute)) {
		t.Fatal("verification and primary effects were not conserved atomically")
	}
	if !reflect.DeepEqual(before, pending.State) || got.Retired != nil || got.RetiredVerification != nil {
		t.Fatal("input or unrelated identifier history changed")
	}
	if _, err := IdentifierIntentDigest(change); err != nil {
		t.Fatal("native compound intent cannot be committed", err)
	}
	if identifierOperation(change.Action) != "" {
		t.Fatal("generic identifier operation exposed native verification policy")
	}
	change.ExpectedUserVersion, change.ExpectedAuthorityVersion = 6, 4
	change.ExpectedIdentifierVersion, change.ExpectedVerificationVersion = 2, 2
	if _, err := ApplyIdentifierChange(got.State, change, now.Add(2*time.Minute)); err == nil {
		t.Fatal("verified-primary action replayed without its native command owner")
	}
}

func TestIdentifierRestartVerificationPreservesPendingIdentityAndFencesHistory(t *testing.T) {
	state, attach, now := identifierFixture()
	pending, err := ApplyIdentifierChange(state, attach, now)
	if err != nil {
		t.Fatal(err)
	}
	change := IdentifierChange{TenantID: attach.TenantID, UserID: attach.UserID, ID: attach.ID, Action: IdentifierRestartVerification, ExpectedUserVersion: 5, ExpectedAuthorityVersion: 3, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}
	before := pending.State
	before.Identifiers = slices.Clone(before.Identifiers)
	before.Verifications = slices.Clone(before.Verifications)
	got, err := ApplyIdentifierChange(pending.State, change, now.Add(time.Minute))
	if err != nil {
		t.Fatal("pending verification has no restart transition", err)
	}
	if got.State.User.Version != 6 || got.State.AuthorityVersion != 4 || got.Retired != nil || got.RetiredVerification != nil || got.State.Identifiers[0] != pending.State.Identifiers[0] || got.State.Verifications[0] != pending.State.Verifications[0] {
		t.Fatal("restart changed primary, retirement or unrelated verification")
	}
	i, v := got.State.Identifiers[1], got.State.Verifications[1]
	if i.ID != attach.ID || i.CanonicalValue != attach.CanonicalValue || i.Verified || i.Primary || i.Version != 2 || v.State != VerificationPending || v.Version != 2 || !v.VerifiedAt.IsZero() || !reflect.DeepEqual(pending.State, before) {
		t.Fatal("restart granted possession, changed identity or mutated input")
	}
	if digest, err := IdentifierIntentDigest(change); err != nil || digest == ([32]byte{}) {
		t.Fatal("restart intent has no complete native binding", err)
	}
	if result, err := ApplyIdentifierChange(got.State, change, now.Add(time.Minute)); err == nil || !reflect.DeepEqual(result, IdentifierMutation{}) {
		t.Fatal("stale restart retained authority")
	}
	for _, action := range []IdentifierAction{IdentifierVerify, IdentifierMakePrimary} {
		invalid := pending.State
		if action == IdentifierVerify {
			verified := change
			verified.Action = IdentifierVerify
			result, err := ApplyIdentifierChange(invalid, verified, now)
			if err != nil {
				t.Fatal(err)
			}
			invalid = result.State
		}
		if action == IdentifierMakePrimary {
			invalid = state
			change.ID, change.ExpectedIdentifierVersion, change.ExpectedVerificationVersion = "a", 3, 2
		}
		change.ExpectedUserVersion, change.ExpectedAuthorityVersion = invalid.User.Version, invalid.AuthorityVersion
		if action == IdentifierVerify {
			change.ExpectedIdentifierVersion, change.ExpectedVerificationVersion = 2, 2
		}
		if result, err := ApplyIdentifierChange(invalid, change, now); err == nil || !reflect.DeepEqual(result, IdentifierMutation{}) {
			t.Fatal("verified/primary identity was downgraded to pending")
		}
	}
}

func TestIdentifierLifecycle(t *testing.T) {
	state, change, now := identifierFixture()
	attached, err := ApplyIdentifierChange(state, change, now)
	if err != nil {
		t.Fatal(err)
	}
	if attached.State.User.Version != 5 || attached.State.AuthorityVersion != 3 || len(attached.State.Identifiers) != 2 || attached.State.Identifiers[1].Verified || attached.State.Identifiers[1].Primary || attached.State.Verifications[1].State != VerificationPending {
		t.Fatal("attach granted verification or lost version")
	}
	change = IdentifierChange{TenantID: change.TenantID, UserID: change.UserID, Action: IdentifierVerify, ID: "b", ExpectedUserVersion: 5, ExpectedAuthorityVersion: 3, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}
	verified, err := ApplyIdentifierChange(attached.State, change, now)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.State.Identifiers[1].Verified || verified.State.Identifiers[1].Primary || verified.State.Verifications[1].State != VerificationVerified || !verified.State.Verifications[1].VerifiedAt.Equal(now) {
		t.Fatal("verification did not preserve separate primary decision")
	}
	change.Action = IdentifierMakePrimary
	change.ExpectedUserVersion, change.ExpectedAuthorityVersion = 6, 4
	change.ExpectedIdentifierVersion, change.ExpectedVerificationVersion = 2, 2
	primary, err := ApplyIdentifierChange(verified.State, change, now)
	if err != nil {
		t.Fatal(err)
	}
	if primary.State.Identifiers[0].Primary || !primary.State.Identifiers[1].Primary || primary.State.Identifiers[0].Version != 4 || primary.State.Identifiers[1].Version != 3 {
		t.Fatal("primary switch not atomic")
	}
	change.Action, change.Kind, change.CanonicalValue = IdentifierReplace, IdentifierEmail, "replacement@example.test"
	change.ExpectedUserVersion, change.ExpectedAuthorityVersion = 7, 5
	change.ExpectedIdentifierVersion = 3
	replaced, err := ApplyIdentifierChange(primary.State, change, now)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Retired == nil || replaced.Retired.CanonicalValue != "two@example.test" || replaced.State.Identifiers[1].Verified || replaced.State.Identifiers[1].Primary || replaced.State.Identifiers[1].Version != 4 || replaced.State.Verifications[1].State != VerificationPending || !replaced.State.Verifications[1].VerifiedAt.IsZero() {
		t.Fatal("replacement retained old authority")
	}
	change.Action, change.Kind, change.CanonicalValue = IdentifierRemove, "", ""
	change.ExpectedUserVersion, change.ExpectedAuthorityVersion = 8, 6
	change.ExpectedIdentifierVersion, change.ExpectedVerificationVersion = 4, 3
	removed, err := ApplyIdentifierChange(replaced.State, change, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.State.Identifiers) != 1 || removed.Retired == nil || removed.Retired.Version != 5 || removed.Retired.Verified || removed.Retired.Primary || removed.RetiredVerification.State != VerificationRevoked || removed.RetiredVerification.Version != 4 {
		t.Fatal("removal lost terminal verification/version")
	}
	if !reflect.DeepEqual(state.Identifiers, []Identifier{{ID: "a", UserID: "user-1", Kind: IdentifierEmail, CanonicalValue: "one@example.test", DisplayValue: "One@example.test", Verified: true, Primary: true, Version: 3}}) {
		t.Fatal("mutated source")
	}
	attached.State.Identifiers[0].CanonicalValue = "mutated"
	if state.Identifiers[0].CanonicalValue != "one@example.test" || verified.State.Identifiers[0].CanonicalValue != "one@example.test" {
		t.Fatal("output shares input or another output")
	}
}

func TestIdentifierChangeDenials(t *testing.T) {
	for name, alter := range map[string]func(*IdentifierState, *IdentifierChange){
		"foreign tenant":  func(_ *IdentifierState, c *IdentifierChange) { c.TenantID = "other" },
		"foreign user":    func(_ *IdentifierState, c *IdentifierChange) { c.UserID = "other" },
		"blocked":         func(s *IdentifierState, _ *IdentifierChange) { s.User.Status = StatusBanned },
		"aggregate fence": func(_ *IdentifierState, c *IdentifierChange) { c.ExpectedUserVersion-- },
		"authority fence": func(_ *IdentifierState, c *IdentifierChange) { c.ExpectedAuthorityVersion++ },
		"overflow": func(s *IdentifierState, c *IdentifierChange) {
			s.AuthorityVersion = ^uint64(0)
			c.ExpectedAuthorityVersion = s.AuthorityVersion
		},
		"duplicate value":       func(_ *IdentifierState, c *IdentifierChange) { c.CanonicalValue = "one@example.test" },
		"duplicate record":      func(_ *IdentifierState, c *IdentifierChange) { c.ID = "a" },
		"unknown kind":          func(_ *IdentifierState, c *IdentifierChange) { c.Kind = "unknown" },
		"unknown action":        func(_ *IdentifierState, c *IdentifierChange) { c.Action = 99 },
		"control":               func(_ *IdentifierState, c *IdentifierChange) { c.CanonicalValue = "hidden\nvalue" },
		"oversized":             func(_ *IdentifierState, c *IdentifierChange) { c.CanonicalValue = strings.Repeat("x", 513) },
		"invalid utf8":          func(_ *IdentifierState, c *IdentifierChange) { c.CanonicalValue = "\xff" },
		"missing verification":  func(s *IdentifierState, _ *IdentifierChange) { s.Verifications = nil },
		"verification mismatch": func(s *IdentifierState, _ *IdentifierChange) { s.Identifiers[0].Verified = false },
		"future verified timestamp": func(s *IdentifierState, _ *IdentifierChange) {
			s.Verifications[0].VerifiedAt = s.Verifications[0].VerifiedAt.Add(2 * time.Hour)
		},
		"primary unverified": func(s *IdentifierState, _ *IdentifierChange) {
			s.Identifiers[0].Verified = false
			s.Verifications[0].State = VerificationPending
			s.Verifications[0].VerifiedAt = time.Time{}
		},
		"ignored fence": func(_ *IdentifierState, c *IdentifierChange) { c.ExpectedIdentifierVersion = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			s, c, now := identifierFixture()
			alter(&s, &c)
			before := s
			before.Identifiers = slices.Clone(s.Identifiers)
			before.Verifications = slices.Clone(s.Verifications)
			mutation, err := ApplyIdentifierChange(s, c, now)
			if err == nil || !reflect.DeepEqual(mutation, IdentifierMutation{}) {
				t.Fatal("invalid change produced partial state")
			}
			if strings.Contains(err.Error(), "example") || !reflect.DeepEqual(before, s) {
				t.Fatal("leak or mutation")
			}
		})
	}
}

func TestIdentifierRoundedZeroTimeDenies(t *testing.T) {
	s, c, now := identifierFixture()
	m, err := ApplyIdentifierChange(s, c, now)
	if err != nil {
		t.Fatal(err)
	}
	m.State.Identifiers, m.State.Verifications = m.State.Identifiers[1:], m.State.Verifications[1:]
	c = IdentifierChange{TenantID: c.TenantID, UserID: c.UserID, ID: "b", Action: IdentifierVerify, ExpectedUserVersion: 5, ExpectedAuthorityVersion: 3, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}
	if out, err := ApplyIdentifierChange(m.State, c, time.Time{}.Add(time.Nanosecond)); err == nil || !reflect.DeepEqual(out, IdentifierMutation{}) {
		t.Fatal("verification persisted an absent time after precision conversion")
	}
}

func TestVerificationRejectsInvalidIdentifier(t *testing.T) {
	s, _, now := identifierFixture()
	i := s.Identifiers[0]
	i.Kind = "unsupported"
	if err := s.Verifications[0].Validate(i, now); err == nil {
		t.Fatal("verification accepted malformed identifier record")
	}
}

func TestIdentifierUTCYearBounds(t *testing.T) {
	s, c, now := identifierFixture()
	for _, outside := range []time.Time{
		time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("west", -2*3600)),
		time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 2*3600)),
	} {
		if out, err := ApplyIdentifierChange(s, c, outside); err == nil || !reflect.DeepEqual(out, IdentifierMutation{}) {
			t.Fatal("accepted unsupported persisted UTC year")
		}
	}
	s.Verifications[0].VerifiedAt = time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 2*3600))
	if err := s.Verifications[0].Validate(s.Identifiers[0], now); err == nil {
		t.Fatal("accepted unsupported historical UTC year")
	}
}

func TestIdentifierTransitionBoundsAndConsistency(t *testing.T) {
	for name, alter := range map[string]func(*IdentifierState, *IdentifierChange){
		"zero state authority":    func(s *IdentifierState, _ *IdentifierChange) { s.AuthorityVersion = 0 },
		"zero expected authority": func(_ *IdentifierState, c *IdentifierChange) { c.ExpectedAuthorityVersion = 0 },
		"zero id":                 func(_ *IdentifierState, c *IdentifierChange) { c.ID = "" },
		"display controls":        func(_ *IdentifierState, c *IdentifierChange) { c.DisplayValue = "bad\x85" },
		"foreign verification":    func(s *IdentifierState, _ *IdentifierChange) { s.Verifications[0].IdentifierID = "other" },
		"zero verification":       func(s *IdentifierState, _ *IdentifierChange) { s.Verifications[0].Version = 0 },
		"unknown verification":    func(s *IdentifierState, _ *IdentifierChange) { s.Verifications[0].State = 99 },
		"missing verified time":   func(s *IdentifierState, _ *IdentifierChange) { s.Verifications[0].VerifiedAt = time.Time{} },
		"precision": func(s *IdentifierState, _ *IdentifierChange) {
			s.Verifications[0].VerifiedAt = s.Verifications[0].VerifiedAt.Add(time.Nanosecond)
		},
		"foreign identifier owner": func(s *IdentifierState, _ *IdentifierChange) { s.Identifiers[0].UserID = "other" },
		"zero record version":      func(s *IdentifierState, _ *IdentifierChange) { s.Identifiers[0].Version = 0 },
		"duplicate primary": func(s *IdentifierState, _ *IdentifierChange) {
			i, v := s.Identifiers[0], s.Verifications[0]
			i.ID = "b"
			i.CanonicalValue = "other@example.test"
			v.IdentifierID = "b"
			s.Identifiers = append(s.Identifiers, i)
			s.Verifications = append(s.Verifications, v)
		},
		"unsorted": func(s *IdentifierState, _ *IdentifierChange) {
			i, v := s.Identifiers[0], s.Verifications[0]
			i.ID = "0"
			i.Primary = false
			i.CanonicalValue = "other@example.test"
			v.IdentifierID = "0"
			s.Identifiers = append(s.Identifiers, i)
			s.Verifications = append(s.Verifications, v)
		},
		"pending historical time": func(s *IdentifierState, _ *IdentifierChange) {
			s.Identifiers[0].Verified = false
			s.Identifiers[0].Primary = false
			s.Verifications[0].State = VerificationPending
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, c, now := identifierFixture()
			alter(&s, &c)
			if out, err := ApplyIdentifierChange(s, c, now); err == nil || !reflect.DeepEqual(out, IdentifierMutation{}) {
				t.Fatal("malformed primary state produced transition")
			}
		})
	}
	state, change, now := identifierFixture()
	for len(state.Identifiers) < 128 {
		i := Identifier{ID: IdentifierID(fmt.Sprintf("b%03d", len(state.Identifiers))), UserID: state.User.ID, Kind: IdentifierUsername, CanonicalValue: fmt.Sprintf("user%d", len(state.Identifiers)), Version: 1}
		state.Identifiers = append(state.Identifiers, i)
		state.Verifications = append(state.Verifications, Verification{IdentifierID: i.ID, State: VerificationPending, Version: 1})
	}
	if _, err := ApplyIdentifierChange(state, change, now); err == nil {
		t.Fatal("unbounded attach")
	}
}

func TestIdentifierTargetChangeValidation(t *testing.T) {
	for name, alter := range map[string]func(*IdentifierChange){
		"missing target":     func(c *IdentifierChange) { c.ID = "missing" },
		"zero target fence":  func(c *IdentifierChange) { c.ExpectedIdentifierVersion = 0 },
		"stale verification": func(c *IdentifierChange) { c.ExpectedVerificationVersion = 1 },
		"overflow target":    func(c *IdentifierChange) { c.ExpectedIdentifierVersion = ^uint64(0) },
		"ignored candidate":  func(c *IdentifierChange) { c.DisplayValue = "ignored" },
		"wrong replacement kind": func(c *IdentifierChange) {
			c.Action = IdentifierReplace
			c.Kind = IdentifierPhone
			c.CanonicalValue = "+12025550123"
		},
		"same replacement value": func(c *IdentifierChange) {
			c.Action = IdentifierReplace
			c.Kind = IdentifierEmail
			c.CanonicalValue = "one@example.test"
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, now := identifierFixture()
			c := IdentifierChange{TenantID: s.User.TenantID, UserID: s.User.ID, ID: "a", Action: IdentifierRemove, ExpectedUserVersion: 4, ExpectedAuthorityVersion: 2, ExpectedIdentifierVersion: 3, ExpectedVerificationVersion: 2}
			alter(&c)
			if out, err := ApplyIdentifierChange(s, c, now); err == nil || !reflect.DeepEqual(out, IdentifierMutation{}) {
				t.Fatal("invalid target produced transition")
			}
		})
	}
}

func FuzzIdentifierRecord(f *testing.F) {
	for _, seed := range []string{"owner", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "", "bad\x00", "\xff"} {
		f.Add(seed, "provider subject", "provider-subject")
	}
	f.Fuzz(func(t *testing.T, id, canonical, kind string) {
		i := Identifier{ID: IdentifierID(id), UserID: "user", Kind: IdentifierKind(kind), CanonicalValue: canonical, Version: 1}
		err := i.Validate("user")
		if err != nil {
			if err.Error() != "identity: invalid input" {
				t.Fatal("unclassified diagnostic")
			}
			return
		}
		if len(id) > 128 || len(canonical) > 512 || i.ID != IdentifierID(id) || i.CanonicalValue != canonical {
			t.Fatal("unbounded or rewritten record")
		}
		parsed, e := ParseIdentifierID(id)
		if e != nil || parsed != i.ID {
			t.Fatal("validation/parser disagreement")
		}
	})
}

func TestIdentifierPrimaryAndVerificationFences(t *testing.T) {
	s, c, now := identifierFixture()
	m, err := ApplyIdentifierChange(s, c, now)
	if err != nil {
		t.Fatal(err)
	}
	c = IdentifierChange{TenantID: c.TenantID, UserID: c.UserID, ID: "b", Action: IdentifierMakePrimary, ExpectedUserVersion: 5, ExpectedAuthorityVersion: 3, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}
	if _, err = ApplyIdentifierChange(m.State, c, now); err == nil {
		t.Fatal("unverified became primary")
	}
	c.ID = "a"
	c.ExpectedIdentifierVersion, c.ExpectedVerificationVersion = 3, 2
	c.Action = IdentifierVerify
	if _, err = ApplyIdentifierChange(m.State, c, now); err == nil {
		t.Fatal("verified challenge reused")
	}
	c.Action = IdentifierRemove
	c.ExpectedIdentifierVersion = 2
	var conflict ConflictError
	if _, err = ApplyIdentifierChange(m.State, c, now); !errors.As(err, &conflict) {
		t.Fatal("stale record not fenced")
	}
}

func TestIdentifierValidationAndRedaction(t *testing.T) {
	s, _, now := identifierFixture()
	if s.Identifiers[0].Validate("user-1") != nil || s.Verifications[0].Validate(s.Identifiers[0], now) != nil {
		t.Fatal("valid metadata rejected")
	}
	for _, value := range []any{s, s.Identifiers[0], s.Verifications[0]} {
		if strings.Contains(fmt.Sprintf("%+v %#v %s", value, value, value), "example") {
			t.Fatal("diagnostic disclosed identifier")
		}
	}
	if _, err := ParseIdentifierID("01ARZ3NDEKTSV4RRFFQ69G5FAV"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseIdentifierID(" bad"); err == nil {
		t.Fatal("noncanonical ID accepted")
	}
}
