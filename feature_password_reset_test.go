package identity_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func passwordResetSpec() identity.FeatureCommandSpec {
	s := passwordHashFeatureSpec()
	s.Operation.OperationID, s.Operation.SchemaID = "identity.password.reset-complete", "password-reset-complete"
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	return s
}

func passwordResetProof(t testing.TB, padding int) (capability.Proof, string) {
	t.Helper()
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	signer, err := capability.NewHMACSHA256Signer("synthetic", []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	limits := capability.DefaultLimits()
	limits.MaxCaveatBytes = 8192
	p := capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"identity"}, Subject: "user", Resource: "identity.password/credential", Operation: "identity.password.reset-complete", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "synthetic-reset", Tenant: "tenant", MaxUses: 1}
	if padding > 0 {
		p.Caveats = map[string]string{"padding": strings.Repeat("x", padding)}
	}
	wire, err := capability.Issue(context.Background(), p, signer, limits)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, limits)
	if err != nil {
		t.Fatal(err)
	}
	return proof, wire
}

func TestFeaturePasswordResetOriginalCustodyAndLifetime(t *testing.T) {
	proof, wire := passwordResetProof(t, 0)
	s := passwordResetSpec()
	hash := "$synthetic$replacement-verifier"
	c, err := identity.NewFeaturePasswordResetCommand(s, hash, proof)
	if err != nil {
		t.Fatal(err)
	}
	s.Fields[2].Value.Bytes[0] = 99
	metadata, ok := c.PasswordResetFeature()
	if !ok || metadata.Binding != passwordResetSpec().Binding {
		t.Fatal("reset scope lost")
	}
	metadata.Fields[0].Name = "changed"
	again, _ := c.PasswordResetFeature()
	if again.Fields[0].Name == "changed" {
		t.Fatal("projection aliases command")
	}
	for _, field := range again.Fields {
		if field.Value.Kind == identity.FeatureBytes && field.Value.Bytes[0] != 1 {
			t.Fatal("input aliases command")
		}
	}
	got, original, ok := c.PasswordResetCustody()
	if !ok || got != hash {
		t.Fatal("replacement verifier lost")
	}
	if err := original.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if string(raw) != wire {
			t.Fatal("original proof reconstructed or changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Upstream proof copies share lifetime. Construction must not resurrect it.
	if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { t.Fatal("proof cloned"); return nil }); err == nil {
		t.Fatal("original alias survived transfer")
	}
	_, retained, ok := c.PasswordResetCustody()
	if !ok {
		t.Fatal("structural custody changed after transfer")
	}
	if err := retained.Transfer(context.Background(), func(context.Context, []byte) error { t.Fatal("command cloned proof"); return nil }); err == nil {
		t.Fatal("command resurrected transferred proof")
	}
}

func TestFeaturePasswordResetClosedBoundsAndVariants(t *testing.T) {
	proof, _ := passwordResetProof(t, 0)
	s := passwordResetSpec()
	for _, h := range []string{"!", "~", strings.Repeat("x", 16384)} {
		if _, err := identity.NewFeaturePasswordResetCommand(s, h, proof); err != nil {
			t.Fatal("valid verifier transport denied", err)
		}
	}
	for _, h := range []string{"", strings.Repeat("x", 16385), "a b", "a\n", "a\x00", "a\x7f", "é"} {
		c, err := identity.NewFeaturePasswordResetCommand(s, h, proof)
		if err == nil {
			t.Fatal("invalid verifier accepted")
		}
		if _, _, ok := c.PasswordResetCustody(); ok {
			t.Fatal("failed construction retained custody")
		}
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/phone" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID = "identity.password.change"
			s.Binding.OperationID = s.Operation.OperationID
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID = "password-change"
			s.Binding.SchemaID = s.Operation.SchemaID
		},
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion = 2; s.Binding.SchemaVersion = 2 },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.RecordRequirement = identity.FeatureRecordOmitted
			s.Binding.RecordID = ""
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
			s.Binding.UserID = ""
			s.Binding.AnonymousFlowID = "AQEBAQEBAQEBAQEBAQEBAQ"
		},
		func(s *identity.FeatureCommandSpec) { s.Binding.CommandID = "invalid" },
	} {
		copy := s
		mutate(&copy)
		if _, err := identity.NewFeaturePasswordResetCommand(copy, "synthetic", proof); err == nil {
			t.Fatal("foreign reset descriptor accepted")
		}
	}
	if _, err := identity.NewFeaturePasswordResetCommand(s, "synthetic", capability.Proof{}); err == nil {
		t.Fatal("zero proof accepted")
	}
	large, _ := passwordResetProof(t, 4000)
	if _, err := identity.NewFeaturePasswordResetCommand(s, "synthetic", large); err == nil {
		t.Fatal("oversized proof accepted")
	}
	if err := large.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal("denial consumed proof", err)
	}
	c, _ := identity.NewFeaturePasswordResetCommand(s, "synthetic", proof)
	if _, ok := c.Feature(); ok {
		t.Fatal("legacy path dropped reset custody")
	}
	if _, ok := c.PasswordHashFeature(); ok {
		t.Fatal("hash-only path accepted reset")
	}
	if _, ok := c.PasswordChangeFeature(); ok {
		t.Fatal("authenticated change accepted reset")
	}
	if _, ok := c.PasswordSigninFeature(); ok {
		t.Fatal("signin accepted reset")
	}
	if _, ok := c.PasswordSignupFeature(); ok {
		t.Fatal("signup accepted reset")
	}
	if _, ok := c.PasswordSignupInputFeature(); ok {
		t.Fatal("signup input accepted reset")
	}
	if _, ok := c.OneTimeCode(); ok {
		t.Fatal("OTP accepted reset")
	}
	if _, ok := c.SessionToken(); ok {
		t.Fatal("session accepted reset")
	}
	if _, ok := c.PreAuthCookie(); ok {
		t.Fatal("cookie accepted reset")
	}
	plain, _ := identity.NewFeatureCommand(s)
	hashOnly, _ := identity.NewFeaturePasswordHashCommand(passwordHashFeatureSpec(), "synthetic")
	for _, other := range []identity.Command{{}, plain, hashOnly} {
		if _, ok := other.PasswordResetFeature(); ok {
			t.Fatal("other variant selected reset")
		}
		if _, _, ok := other.PasswordResetCustody(); ok {
			t.Fatal("other variant acquired proof")
		}
	}
	_ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	if _, err := identity.NewFeaturePasswordResetCommand(s, "synthetic", proof); err == nil {
		t.Fatal("transferred proof accepted")
	}
}

func TestFeaturePasswordResetRedactionAndConcurrentReads(t *testing.T) {
	proof, wire := passwordResetProof(t, 0)
	hash := "$synthetic$private-reset-verifier"
	c, err := identity.NewFeaturePasswordResetCommand(passwordResetSpec(), hash, proof)
	if err != nil {
		t.Fatal(err)
	}
	type wrapper struct{ command identity.Command }
	for _, value := range []any{c, &c, wrapper{c}, &wrapper{c}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
			got := fmt.Sprintf(verb, value)
			if strings.Contains(got, hash) || strings.Contains(got, wire) {
				t.Fatal("secret disclosed")
			}
		}
	}
	if raw, err := json.Marshal(c); err == nil || strings.Contains(string(raw), hash) || strings.Contains(string(raw), wire) {
		t.Fatal("reset command serialized")
	}
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			got, _, ok := c.PasswordResetCustody()
			if !ok || got != hash {
				t.Error("concurrent custody changed")
			}
			if _, ok := c.PasswordResetFeature(); !ok {
				t.Error("concurrent scope changed")
			}
		})
	}
	wg.Wait()
}

func TestFeaturePasswordResetCustodyDoesNotAuthenticate(t *testing.T) {
	_, wire := passwordResetProof(t, 0)
	parts := strings.Split(wire, ".")
	signature := parts[len(parts)-1]
	replacement := byte('A')
	if signature[0] == replacement {
		replacement = 'B'
	}
	parts[len(parts)-1] = string(replacement) + signature[1:]
	forged, err := capability.ParseProof(strings.Join(parts, "."), capability.DefaultLimits())
	if err != nil {
		t.Fatal("forged control is not structural", err)
	}
	c, err := identity.NewFeaturePasswordResetCommand(passwordResetSpec(), "synthetic", forged)
	if err != nil {
		t.Fatal("custody inferred signature policy", err)
	}
	verifier, err := capability.NewHMACSHA256Verifier([]byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://issuer.example", ID: "synthetic", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := capability.NewHMACSHA256Signer("synthetic", []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	service, err := capability.NewService(capability.ServiceConfig{Issuer: "https://issuer.example", Signer: signer, Resolver: keys, Clock: func() time.Time { return time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC) }, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	_, retained, ok := c.PasswordResetCustody()
	if !ok {
		t.Fatal("structural custody lost")
	}
	if _, err := service.Verify(context.Background(), retained, "identity.password.reset-complete", "identity"); !errors.Is(err, capability.ErrInvalidSignature) {
		t.Fatal("upstream verification did not deny forgery", err)
	}
}

func FuzzFeaturePasswordResetVerifier(f *testing.F) {
	f.Add("synthetic")
	f.Add("")
	f.Add("not\ncanonical")
	proof, _ := passwordResetProof(f, 0)
	f.Fuzz(func(t *testing.T, hash string) {
		if len(hash) > 16385 {
			return
		}
		c, err := identity.NewFeaturePasswordResetCommand(passwordResetSpec(), hash, proof)
		if err != nil {
			if _, _, ok := c.PasswordResetCustody(); ok {
				t.Fatal("denied input retained custody")
			}
			return
		}
		got, original, ok := c.PasswordResetCustody()
		if !ok || got != hash || original.ValidateBounds(32, 4096) != nil {
			t.Fatal("accepted input changed custody")
		}
		if _, ok := c.Feature(); ok {
			t.Fatal("reset lost custody through legacy mapping")
		}
	})
}
