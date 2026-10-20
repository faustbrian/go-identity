package passwordpostgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestPasswordResetOriginalMaterialBindsSignedPredecessors(t *testing.T) {
	for _, phoneReset := range []bool{false, true} {
		t.Run(map[bool]string{false: "email", true: "phone"}[phoneReset], func(t *testing.T) {
			testPasswordResetOriginalMaterial(t, phoneReset)
		})
	}
}

func testPasswordResetOriginalMaterial(t *testing.T, phoneReset bool) {
	t.Helper()
	spec, previous, encoded, policy := replacementFixture(t)
	spec.Operation, spec.Binding.OperationID, spec.Binding.SchemaID = resetOperation(), "identity.password.reset-complete", "password-reset-complete"
	if phoneReset {
		spec.Operation = phonePasswordResetOperation()
		spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	}
	origin, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	configuration := password.ResetProfileConfig{Issuer: "https://identity.test", Audience: "reset", MaximumLifetime: time.Minute, Callbacks: []string{"https://identity.test/reset"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {31}}}
	constructor := password.NewResetProfile
	if phoneReset {
		constructor = password.NewPhoneResetProfile
	}
	profile, err := constructor(configuration)
	if err != nil {
		t.Fatal(err)
	}
	original := password.ResetGrantSpec{TenantID: "tenant", UserID: "user", CredentialID: "password", CredentialVersion: 7, CredentialAuthorityVersion: 5, UserAuthorityVersion: 3, IdentifierID: "original-email", IdentifierVersion: 11, OriginCommandID: origin, RecoveryPath: auth.RecoveryPathEmail, CallbackURL: "https://identity.test/reset", IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
	if phoneReset {
		original.IdentifierID = "original-phone"
		original.RecoveryPath = auth.RecoveryPathPhone
		original.FactorVersion = 4
		original.Phone = password.PhoneResetBinding{PreAuthTransaction: "original-phone-browser", OTPChallengeID: "original-phone-challenge", AttemptID: origin, NumberDigest: [32]byte{91}, NumberKeyVersion: 1, VerificationVersion: 3, FactorID: "independent-confirmed-totp", FactorVersion: 5, RiskPolicyVersion: 3}
	}
	key := []byte(strings.Repeat("x", 32))
	signer, err := capability.NewHMACSHA256Signer("synthetic-reset", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.test", ID: "synthetic-reset", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := capability.NewService(capability.ServiceConfig{Issuer: "https://identity.test", Signer: signer, Resolver: resolver, Clock: func() time.Time { return at }, Limits: capability.DefaultLimits()})
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
	grant, err := engine.Verify(context.Background(), proof, capability.Purpose(spec.Operation.OperationID), "reset")
	if err != nil {
		t.Fatal(err)
	}
	newCommand := func(s identity.FeatureCommandSpec) (identity.Command, error) {
		if !phoneReset {
			return identity.NewFeaturePasswordResetCommand(s, encoded, proof)
		}
		sms, _ := auth.NewOneTimeCode("123456")
		totp, _ := auth.NewOneTimeCode("654321")
		return identity.NewFeaturePhonePasswordResetCommand(s, encoded, proof, sms, totp)
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
		command, err := newCommand(spec)
		if err != nil {
			t.Fatal(err)
		}
		// This is independently specified consumption metadata, not durable
		// issuance proof. The native owner must obtain it from the real issuer.
		plan := kernel.CapabilityPlan{CapabilityID: payload.ID, Purpose: capability.Purpose(spec.Operation.OperationID), ReplayDigest: [32]byte{19}, ReplayKeyVersion: 2, ProofFingerprint: grant.EnvelopeDigest(), ExpiresAt: original.ExpiresAt, MaxUses: 1}
		got, hash, err := passwordResetOriginalMaterial(command, policy, profile, original, grant, plan, at)
		if err != nil || got != intent || hash.String() != encoded {
			t.Fatal("original signed reset predecessors denied")
		}
		if phoneReset {
			// A genuinely signed phone grant cannot authorize the weaker email
			// command, even when all password predecessors happen to match.
			email := spec
			email.Operation = resetOperation()
			email.Binding.OperationID, email.Binding.SchemaID = email.Operation.OperationID, email.Operation.SchemaID
			weaker, e := identity.NewFeaturePasswordResetCommand(email, encoded, proof)
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e := passwordResetOriginalMaterial(weaker, policy, profile, original, grant, plan, at); !errors.Is(e, identity.ForbiddenError{}) {
				t.Fatal("signed phone grant acquired email command material", e)
			}
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
			changedCommand, err := newCommand(changedSpec)
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
