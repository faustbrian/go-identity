package mfapostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestPasskeyContinuationRetainsExactProtectedOriginal(t *testing.T) {
	prior := continuationFixture(t)
	s, _ := prior.Bindings()
	b := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: s.TenantID, UserID: identity.UserID(s.SubjectID)}
	s.PrimaryProofID = "AQEBAQEBAQEBAQEBAQEBAQ"
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
