package passwordpostgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestPasswordResetOriginalMaterialBindsSignedPredecessors(t *testing.T) {
	spec, previous, encoded, policy := replacementFixture(t)
	spec.Operation, spec.Binding.OperationID, spec.Binding.SchemaID = resetOperation(), "identity.password.reset-complete", "password-reset-complete"
	origin, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	profile, err := password.NewResetProfile(password.ResetProfileConfig{Issuer: "https://identity.test", Audience: "reset", MaximumLifetime: time.Minute, Callbacks: []string{"https://identity.test/reset"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {31}}})
	if err != nil {
		t.Fatal(err)
	}
	original := password.ResetGrantSpec{TenantID: "tenant", UserID: "user", CredentialID: "password", CredentialVersion: 7, CredentialAuthorityVersion: 5, UserAuthorityVersion: 3, IdentifierID: "original-email", IdentifierVersion: 11, OriginCommandID: origin, RecoveryPath: auth.RecoveryPathEmail, CallbackURL: "https://identity.test/reset", IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
	key := []byte(strings.Repeat("x", 32))
	signer, err := capability.NewHMACSHA256Signer("synthetic-reset", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{ID: "synthetic-reset", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := capability.NewService(capability.ServiceConfig{Signer: signer, Resolver: resolver, Clock: func() time.Time { return at }, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := profile.Payload(original)
	if err != nil {
		t.Fatal(err)
	}
	payload.ID = "synthetic-original-reset"
	proof, _, err := engine.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	grant, err := engine.Verify(context.Background(), proof, "identity.password.reset-complete", "reset")
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		intent := kernel.CredentialResetIntent{Replacement: previous, ExpectedEnabled: enabled}
		// Aggregate CAS and security authority are independent. A harmless
		// aggregate update must not be mistaken for a different signed epoch.
		intent.Replacement.ExpectedUserVersion = 101
		spec.Fields, err = kernel.CredentialResetFields(intent)
		if err != nil {
			t.Fatal(err)
		}
		command, err := identity.NewFeaturePasswordResetCommand(spec, encoded, proof)
		if err != nil {
			t.Fatal(err)
		}
		// This is independently specified consumption metadata, not durable
		// issuance proof. The native owner must obtain it from the real issuer.
		plan := kernel.CapabilityPlan{CapabilityID: payload.ID, Purpose: "identity.password.reset-complete", ReplayDigest: [32]byte{19}, ReplayKeyVersion: 2, ProofFingerprint: grant.EnvelopeDigest(), ExpiresAt: original.ExpiresAt, MaxUses: 1}
		got, hash, err := passwordResetOriginalMaterial(command, policy, profile, original, grant, plan, at)
		if err != nil || got != intent || hash.String() != encoded {
			t.Fatal("original signed reset predecessors denied")
		}
		for _, change := range []func(*kernel.CredentialResetIntent){
			func(i *kernel.CredentialResetIntent) { i.Replacement.Credential.Version++ },
			func(i *kernel.CredentialResetIntent) { i.Replacement.ExpectedAuthorityVersion++ },
		} {
			changed := intent
			change(&changed)
			changedSpec := spec
			changedSpec.Fields, err = kernel.CredentialResetFields(changed)
			if err != nil {
				t.Fatal(err)
			}
			changedCommand, err := identity.NewFeaturePasswordResetCommand(changedSpec, encoded, proof)
			if err != nil {
				t.Fatal(err)
			}
			if i, h, e := passwordResetOriginalMaterial(changedCommand, policy, profile, original, grant, plan, at); !errors.Is(e, identity.ForbiddenError{}) || i != (kernel.CredentialResetIntent{}) || h.String() != "" {
				t.Fatal("command predecessor substituted for original signed version")
			}
		}
		for name, change := range map[string]func(*password.ResetGrantSpec){
			"tenant":             func(s *password.ResetGrantSpec) { s.TenantID = "foreign" },
			"user":               func(s *password.ResetGrantSpec) { s.UserID = "foreign" },
			"credential":         func(s *password.ResetGrantSpec) { s.CredentialID = "foreign" },
			"credential-version": func(s *password.ResetGrantSpec) { s.CredentialVersion++ },
			"authority-version":  func(s *password.ResetGrantSpec) { s.CredentialAuthorityVersion++ },
			"user-version":       func(s *password.ResetGrantSpec) { s.UserAuthorityVersion++ },
			"identifier":         func(s *password.ResetGrantSpec) { s.IdentifierID = "foreign" },
			"identifier-version": func(s *password.ResetGrantSpec) { s.IdentifierVersion++ },
			"origin":             func(s *password.ResetGrantSpec) { s.OriginCommandID = spec.Binding.CommandID },
			"callback":           func(s *password.ResetGrantSpec) { s.CallbackURL += "?changed=1" },
			"expiry":             func(s *password.ResetGrantSpec) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) },
		} {
			t.Run(name, func(t *testing.T) {
				changed := original
				change(&changed)
				if i, h, e := passwordResetOriginalMaterial(command, policy, profile, changed, grant, plan, at); !errors.Is(e, identity.ForbiddenError{}) || i != (kernel.CredentialResetIntent{}) || h.String() != "" {
					t.Fatal("substituted original reset intent admitted")
				}
			})
		}
		for name, change := range map[string]func(*kernel.CapabilityPlan){
			"id":       func(p *kernel.CapabilityPlan) { p.CapabilityID = "foreign" },
			"purpose":  func(p *kernel.CapabilityPlan) { p.Purpose = "identity.password.change" },
			"envelope": func(p *kernel.CapabilityPlan) { p.ProofFingerprint = [32]byte{7} },
			"expiry":   func(p *kernel.CapabilityPlan) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
			"uses":     func(p *kernel.CapabilityPlan) { p.MaxUses = 2 },
			"key":      func(p *kernel.CapabilityPlan) { p.ReplayKeyVersion = 0 },
			"digest":   func(p *kernel.CapabilityPlan) { p.ReplayDigest = [32]byte{} },
		} {
			t.Run(name, func(t *testing.T) {
				changed := plan
				change(&changed)
				if i, h, e := passwordResetOriginalMaterial(command, policy, profile, original, grant, changed, at); !errors.Is(e, identity.ForbiddenError{}) || i != (kernel.CredentialResetIntent{}) || h.String() != "" {
					t.Fatal("foreign consumption metadata admitted")
				}
			})
		}
		for _, now := range []time.Time{at.Add(-time.Second), original.ExpiresAt, time.Time{}} {
			if _, _, e := passwordResetOriginalMaterial(command, policy, profile, original, grant, plan, now); !errors.Is(e, identity.ForbiddenError{}) {
				t.Fatal("expired or invalid reset time admitted")
			}
		}
		if _, _, e := passwordResetOriginalMaterial(command, policy, profile, original, capability.Grant{}, plan, at); !errors.Is(e, identity.ForbiddenError{}) {
			t.Fatal("unverified zero grant admitted")
		}
	}
}
