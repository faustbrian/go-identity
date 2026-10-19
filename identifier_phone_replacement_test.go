package identity

import (
	"testing"
	"time"
)

func verifiedPhoneReplacementFixture() (IdentifierState, IdentifierChange, time.Time) {
	now := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	state := IdentifierState{User: User{TenantID: "tenant", ID: "user", Status: StatusActive, Version: 5}, AuthorityVersion: 4,
		Identifiers:   []Identifier{{ID: "phone", UserID: "user", Kind: IdentifierPhone, CanonicalValue: "+12025550123", Verified: true, Primary: true, Version: 2, NormalizationProfile: "phone-e164-v1", NormalizationVersion: 1}},
		Verifications: []Verification{{IdentifierID: "phone", State: VerificationVerified, VerifiedAt: now.Add(-time.Hour), Version: 2}}}
	change := IdentifierChange{TenantID: "tenant", UserID: "user", ID: "phone", Action: IdentifierReplaceVerifiedPhone,
		Kind: IdentifierPhone, CanonicalValue: "+12025550124", DisplayValue: "+12025550124", NormalizationProfile: "phone-e164-v1", NormalizationVersion: 1,
		ExpectedUserVersion: 5, ExpectedAuthorityVersion: 4, ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 2}
	return state, change, now
}

func TestVerifiedPhoneReplacementIsOneVersionedVerifiedTransition(t *testing.T) {
	state, change, now := verifiedPhoneReplacementFixture()
	if _, err := IdentifierIntentDigest(change); err != nil {
		t.Fatal("compound phone replacement intent rejected", err)
	}
	mutation, err := ApplyIdentifierChange(state, change, now)
	if err != nil {
		t.Fatal(err)
	}
	next, verification := mutation.State.Identifiers[0], mutation.State.Verifications[0]
	if mutation.State.User.Version != 6 || mutation.State.AuthorityVersion != 5 || next.Version != 3 || verification.Version != 3 ||
		next.CanonicalValue != change.CanonicalValue || !next.Verified || !next.Primary || verification.State != VerificationVerified || verification.VerifiedAt != now ||
		mutation.Retired == nil || *mutation.Retired != state.Identifiers[0] || mutation.RetiredVerification == nil || *mutation.RetiredVerification != state.Verifications[0] ||
		state.Identifiers[0].CanonicalValue != "+12025550123" {
		t.Fatal("compound replacement lost original retirement, primary or exact one-step successor")
	}
	if identifierOperation(change.Action) != "" {
		t.Fatal("compound transition escaped into generic proof-only identifier commands")
	}
	// Existing generic replacement still resets possession and primary state.
	change.Action = IdentifierReplace
	ordinary, err := ApplyIdentifierChange(state, change, now)
	if err != nil || ordinary.State.Identifiers[0].Verified || ordinary.State.Identifiers[0].Primary || ordinary.State.Verifications[0].State != VerificationPending {
		t.Fatal("compound workflow changed existing replacement semantics", err)
	}
}

func TestVerifiedPhoneReplacementRejectsUnverifiedAndUnboundScope(t *testing.T) {
	for name, mutate := range map[string]func(*IdentifierState, *IdentifierChange){
		"email": func(s *IdentifierState, c *IdentifierChange) {
			s.Identifiers[0].Kind = IdentifierEmail
			c.Kind = IdentifierEmail
		},
		"pending": func(s *IdentifierState, _ *IdentifierChange) {
			s.Identifiers[0].Verified = false
			s.Identifiers[0].Primary = false
			s.Verifications[0].State = VerificationPending
			s.Verifications[0].VerifiedAt = time.Time{}
		},
		"unbound": func(s *IdentifierState, c *IdentifierChange) {
			s.Identifiers[0].NormalizationProfile = ""
			s.Identifiers[0].NormalizationVersion = 0
			c.NormalizationProfile = ""
			c.NormalizationVersion = 0
		},
		"metadata-change": func(_ *IdentifierState, c *IdentifierChange) { c.NormalizationVersion++ },
		"same-number":     func(s *IdentifierState, c *IdentifierChange) { c.CanonicalValue = s.Identifiers[0].CanonicalValue },
		"stale":           func(_ *IdentifierState, c *IdentifierChange) { c.ExpectedVerificationVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			state, change, now := verifiedPhoneReplacementFixture()
			mutate(&state, &change)
			if _, err := ApplyIdentifierChange(state, change, now); err == nil {
				t.Fatal("compound replacement admitted wrong predecessor or unsupported policy")
			}
		})
	}
}
