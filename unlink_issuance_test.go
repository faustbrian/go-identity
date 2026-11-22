package identity

import (
	"errors"
	"testing"
	"time"
)

func TestAccountUnlinkProofPayloadBindsOriginalIntentAndLifetime(t *testing.T) {
	preparation, bearer := unlinkPreparationFixture(t)
	original, err := NewAccountUnlinkPreparationCommand(preparation, bearer)
	if err != nil {
		t.Fatal(err)
	}
	now := queryClock{}.Now()
	spec := AccountUnlinkProofSpec{
		Preparation: original,
		Issuer:      "https://identity.example",
		Audience:    "identity-backend",
		ID:          "generated-unlink-child",
		IssuedAt:    now,
		ExpiresAt:   now.Add(30 * time.Second),
	}
	payload, err := BuildAccountUnlinkProofPayload(spec)
	if err != nil {
		t.Fatal("canonical original cannot produce its child payload:", err)
	}
	if payload.Bearer || payload.MaxUses != 1 || payload.NotBefore != spec.IssuedAt || payload.ExpiresAt != spec.ExpiresAt {
		t.Fatal("child can be reused or gained a different validity interval")
	}
	_, _, _, issuer, _ := unlinkCommandFixture(t)
	token, _, err := issuer.Issue(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := issuer.Verify(t.Context(), token, "identity.account.unlink", spec.Audience)
	if err != nil {
		t.Fatal(err)
	}
	typed := AccountUnlinkCommand{
		Binding: preparation.Binding, Change: preparation.Change, SessionID: preparation.SessionID,
		SessionVersion: preparation.SessionVersion, RevokeProvider: preparation.RevokeProvider, Proof: grant,
	}
	if _, err := NewAccountUnlinkCommand(typed); err != nil {
		t.Fatal("real signed child does not match the existing unlink command contract:", err)
	}
	typed.RevokeProvider = !typed.RevokeProvider
	if _, err := NewAccountUnlinkCommand(typed); err == nil {
		t.Fatal("signed child permits a different provider revocation choice")
	}

	for name, change := range map[string]func(*AccountUnlinkProofSpec){
		"issued before parent": func(s *AccountUnlinkProofSpec) { s.IssuedAt = preparation.Primary.Proof.IssuedAt.Add(-time.Second) },
		"expires after parent": func(s *AccountUnlinkProofSpec) { s.ExpiresAt = preparation.Primary.Proof.ExpiresAt.Add(time.Second) },
		"subsecond issue":      func(s *AccountUnlinkProofSpec) { s.IssuedAt = s.IssuedAt.Add(time.Microsecond) },
		"expiry at issue":      func(s *AccountUnlinkProofSpec) { s.ExpiresAt = s.IssuedAt },
		"missing preparation":  func(s *AccountUnlinkProofSpec) { s.Preparation = Command{} },
		"wrong issuer shape":   func(s *AccountUnlinkProofSpec) { s.Issuer = "not an issuer" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := spec
			change(&candidate)
			rejected, err := BuildAccountUnlinkProofPayload(candidate)
			var invalid InvalidInputError
			if !errors.As(err, &invalid) || rejected.ID != "" || len(rejected.Caveats) != 0 {
				t.Fatal("invalid parent or lifetime manufactured a child:", err)
			}
		})
	}
}
