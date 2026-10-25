package mfapostgres

import (
	"context"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// This is only the original-profile gate used after protected Work admission;
// constructing these projections authenticates neither a primary nor a factor.
func TestLegacyContinuationOwnersRejectExplicitNewPrimaryOrigins(t *testing.T) {
	legacy, _ := continuationFixture(t).Bindings()
	for _, profile := range []string{"legacy", "verification", "passkey"} {
		t.Run(profile, func(t *testing.T) {
			s := legacy
			switch profile {
			case "verification":
				s.VerificationCommandID = "AwMDAwMDAwMDAwMDAwMDAw"
			case "passkey":
				s.PasskeyCommandID = "AQEBAQEBAQEBAQEBAQEBAQ"
				s.PrimaryProofID = auth.ProofID(s.PasskeyCommandID)
				s.AllowedMethods = []string{"totp"}
			}
			c, err := mfa.NewPartialAuthContinuation(s)
			if err != nil {
				t.Fatal("invalid origin partition fixture", err)
			}
			stored, _ := c.Bindings()
			if legacyPrimaryContinuationOrigin(stored) != (profile == "legacy") {
				t.Fatal("legacy owner adopted another primary origin")
			}
		})
	}
}

func TestPasskeyContinuationRetainsExactProtectedOriginal(t *testing.T) {
	prior := continuationFixture(t)
	s, _ := prior.Bindings()
	b := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: s.TenantID, UserID: identity.UserID(s.SubjectID)}
	s.PrimaryProofID = "AQEBAQEBAQEBAQEBAQEBAQ"
	s.PasskeyCommandID = b.CommandID
	s.AllowedMethods = []string{"totp"}
	c, err := mfa.NewPartialAuthContinuation(s)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := c.ScopeDigest()
	challenge := kernel.MFAContinuationPlan{ID: identity.CommandID(s.ID), UserID: b.UserID, ScopeDigest: digest, PolicyVersion: s.PolicyVersion, FactorVersion: s.FactorVersion, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt}
	if !passkeyContinuationMatches(c, b, challenge) {
		t.Fatal("original passkey continuation denied")
	}
	withoutOrigin := s
	withoutOrigin.PasskeyCommandID = ""
	unmarked, err := mfa.NewPartialAuthContinuation(withoutOrigin)
	if err != nil {
		t.Fatal(err)
	}
	unmarkedChallenge := challenge
	unmarkedChallenge.ScopeDigest, err = unmarked.ScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	if passkeyContinuationMatches(unmarked, b, unmarkedChallenge) {
		t.Fatal("legacy primary acquired passkey continuation ownership")
	}
	encoded, err := encodeContinuationScope(c)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	restored, err := decodeContinuationScope(encoded, digest, mfa.Challenged, 2, s.MaxAttempts-1)
	if err != nil {
		t.Fatal("stored passkey original cannot be restored", err)
	}
	payload, err := restored.CapabilityPayload("https://issuer.test")
	if err != nil || payload.CorrelationID != string(b.CommandID) || !payload.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("storage lost original signed correlation or renewed expiry", err)
	}
	for name, change := range map[string]func(*kernel.MFAContinuationPlan){
		"child":   func(v *kernel.MFAContinuationPlan) { v.ID = b.CommandID },
		"subject": func(v *kernel.MFAContinuationPlan) { v.UserID = "another-user" },
		"scope":   func(v *kernel.MFAContinuationPlan) { v.ScopeDigest[0] ^= 1 },
		"policy":  func(v *kernel.MFAContinuationPlan) { v.PolicyVersion++ },
		"factor":  func(v *kernel.MFAContinuationPlan) { v.FactorVersion++ },
		"time":    func(v *kernel.MFAContinuationPlan) { v.IssuedAt = v.IssuedAt.Add(1) },
		"expiry":  func(v *kernel.MFAContinuationPlan) { v.ExpiresAt = v.ExpiresAt.Add(1) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := challenge
			change(&bad)
			if passkeyContinuationMatches(c, b, bad) {
				t.Fatal("substituted declaration retained original continuation")
			}
		})
	}
	for _, bad := range []identity.CommandBinding{
		{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: b.TenantID, UserID: b.UserID},
		{CommandID: b.CommandID, TenantID: "another-tenant", UserID: b.UserID},
		{CommandID: b.CommandID, TenantID: b.TenantID, UserID: "another-user"},
	} {
		if passkeyContinuationMatches(c, bad, challenge) {
			t.Fatal("substituted primary retained continuation")
		}
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if err := PersistPasskeyContinuation(ctx, kernel.Work{}, nil, identity.Command{}, c); err == nil {
			t.Fatal("unowned Work persisted continuation")
		}
	}
}
