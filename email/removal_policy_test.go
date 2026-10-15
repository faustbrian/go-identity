package email

import (
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestRemovalPolicyConservesVerifiedSigninAndRecoveryAddress(t *testing.T) {
	now := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	state := identity.IdentifierState{User: identity.User{ID: "user", TenantID: "tenant", Status: identity.StatusActive, Version: 9}, AuthorityVersion: 4, Identifiers: []identity.Identifier{{ID: "a", UserID: "user", Kind: identity.IdentifierEmail, CanonicalValue: "old@example.test", Verified: true, Primary: true, Version: 2}, {ID: "b", UserID: "user", Kind: identity.IdentifierEmail, CanonicalValue: "other@example.test", Version: 5}}, Verifications: []identity.Verification{{IdentifierID: "a", State: identity.VerificationVerified, Version: 2, VerifiedAt: now.Add(-time.Hour)}, {IdentifierID: "b", State: identity.VerificationPending, Version: 3}}}
	change := identity.IdentifierChange{TenantID: "tenant", UserID: "user", ID: "a", Action: identity.IdentifierRemove, ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4, ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 2}
	policy := RemovalProfile{Sessions: InvalidateIdentifierSessions, Recovery: PreserveVerifiedEmailRecovery}
	if _, err := policy.PlanRemoval(state, change, now); err == nil {
		t.Fatal("pending address substituted for verified signin/recovery")
	}
	state.Identifiers[1].Verified = true
	state.Verifications[1].State, state.Verifications[1].VerifiedAt = identity.VerificationVerified, now.Add(-time.Minute)
	removed, err := policy.PlanRemoval(state, change, now)
	if err != nil || removed.Retired == nil || removed.Retired.ID != "a" || len(removed.State.Identifiers) != 1 || removed.State.Identifiers[0].ID != "b" || !removed.State.Identifiers[0].Verified || removed.State.Identifiers[0].Primary || removed.State.Identifiers[0].Version != 5 || removed.State.Verifications[0].Version != 3 || removed.State.User.Version != 10 || removed.State.AuthorityVersion != 5 {
		t.Fatal("safe removal lost original alternative or invented primary", err)
	}
	if !state.Identifiers[0].Primary || len(state.Identifiers) != 2 || state.User.Version != 9 {
		t.Fatal("policy mutated caller partition")
	}
	if _, err := (RemovalProfile{}).PlanRemoval(state, change, now); err == nil {
		t.Fatal("zero removal policy enabled mutation")
	}
	change.Action = identity.IdentifierMakePrimary
	if _, err := policy.PlanRemoval(state, change, now); err == nil {
		t.Fatal("removal policy admitted another action")
	}
}
