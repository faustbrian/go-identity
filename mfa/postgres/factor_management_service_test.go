package mfapostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestFactorManagementRequiresNativePrimaryProofAndSessionOwners(t *testing.T) {
	if service, err := NewFactorUpdateService(nil, nil, FactorUpdateConfig{}); err == nil || service != nil {
		t.Fatal("missing factor-management owners admitted a mutation")
	}
	for _, service := range []*FactorUpdateService{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			out, err := service.FactorUpdate(ctx, mfa.FactorUpdateRequest{})
			if err == nil || out.Outcome != 0 || out.CommandID != "" || out.Factor.ID != "" {
				t.Fatal("unconfigured factor management fabricated a mutation outcome")
			}
		}
	}
}

func TestFactorMutationWithheldRecoveryCustodyIsDestroyed(t *testing.T) {
	for _, mode := range []string{"fresh", "cancel", "error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			first, err := primitive.NewSecret([]byte("AAAAAAAAAAAAAAAAAAAAAQ"))
			if err != nil {
				t.Fatal(err)
			}
			defer first.Destroy()
			second, err := primitive.NewSecret([]byte("AAAAAAAAAAAAAAAAAAAAAg"))
			if err != nil {
				t.Fatal(err)
			}
			defer second.Destroy()
			pending := &mfa.TOTPReplacementEnrollment{RecoveryMaterial: mfa.RevealOnceCodes{Codes: []primitive.Secret{first, second}}}
			command := identity.CommandID("AAAAAAAAAAAAAAAAAAAABA")
			out := mfa.FactorUpdateResult{CommandID: command, Outcome: identity.CommitOutcomeCommitted, Factor: mfa.FactorProjection{ID: "AAAAAAAAAAAAAAAAAAAABQ"}, Replacement: pending}
			var failure error
			func() {
				// The exact production defer runs after copies have been allocated,
				// reproducing cancellation without timing races or fixture hooks.
				defer finishFactorMutation(ctx, &out, &failure)
				switch mode {
				case "cancel":
					cancel()
				case "error":
					failure = identity.UnavailableError{}
				case "panic":
					panic("synthetic final-delivery failure")
				}
			}()
			if mode == "fresh" {
				if failure != nil || out.CommandID != command || out.Outcome != identity.CommitOutcomeCommitted || out.Replacement != pending || len(pending.RecoveryMaterial.Codes) != 2 || first.Use(func([]byte) error { return nil }) != nil || second.Use(func([]byte) error { return nil }) != nil {
					t.Fatal("fresh native delivery lost usable ownership or committed observation")
				}
				return
			}
			if failure == nil || out.CommandID != command || out.Outcome != identity.CommitOutcomeCommitted || out.Factor.ID != "" || out.Replacement != nil {
				t.Fatal("failed native delivery disclosed custody or lost committed observation")
			}
			for _, owner := range []primitive.Secret{first, second} {
				if owner.Use(func([]byte) error { return nil }) == nil {
					t.Fatal("withheld native recovery-code copy was not destroyed")
				}
			}
			if len(pending.RecoveryMaterial.Codes) != 0 {
				t.Fatal("withheld recovery delivery retained its ownership slice")
			}
		})
	}
}
