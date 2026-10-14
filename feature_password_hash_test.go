package identity_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func passwordHashFeatureSpec() identity.FeatureCommandSpec {
	s := featureCommandSpec()
	s.Operation = identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	return s
}

func TestFeaturePasswordHashCustodyIsExactAndLegacyClosed(t *testing.T) {
	s := passwordHashFeatureSpec()
	hash := "$synthetic-only$not-a-validated-hash"
	c, err := identity.NewFeaturePasswordHashCommand(s, hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Feature(); ok {
		t.Fatal("legacy feature admission could discard hash custody")
	}
	if _, ok := c.OneTimeCode(); ok {
		t.Fatal("hash variant gained OTP custody")
	}
	if _, ok := c.SessionToken(); ok {
		t.Fatal("hash variant gained session custody")
	}
	if _, ok := c.PreAuthCookie(); ok {
		t.Fatal("hash variant gained pre-auth custody")
	}
	got, ok := c.PasswordHash()
	if !ok || got != hash {
		t.Fatal("exact hash bytes lost")
	}
	s.Fields[0].Name = "changed"
	metadata, ok := c.PasswordHashFeature()
	if !ok || metadata.Binding != passwordHashFeatureSpec().Binding {
		t.Fatal("original hash-command scope lost")
	}
	metadata.Binding.UserID = "other"
	metadata.Fields[0].Name = "other"
	again, ok := c.PasswordHashFeature()
	if !ok || again.Binding.UserID == "other" || again.Fields[0].Name == "other" {
		t.Fatal("metadata projection changed retained command")
	}
	plain, _ := identity.NewFeatureCommand(passwordHashFeatureSpec())
	for _, other := range []identity.Command{{}, plain} {
		if raw, ok := other.PasswordHash(); ok || raw != "" {
			t.Fatal("ordinary command acquired hash")
		}
		if _, ok := other.PasswordHashFeature(); ok {
			t.Fatal("ordinary command acquired hash projection")
		}
	}
}

func TestFeaturePasswordHashBoundsAndScope(t *testing.T) {
	s := passwordHashFeatureSpec()
	if _, err := identity.NewFeaturePasswordHashCommand(s, strings.Repeat("x", 16384)); err != nil {
		t.Fatal("exact transport limit rejected", err)
	}
	for _, hash := range []string{"", strings.Repeat("x", 16385), "a b", "a\n", "a\x00", "a\x7f", "a\xff", "é"} {
		c, err := identity.NewFeaturePasswordHashCommand(s, hash)
		if err == nil {
			t.Fatal("ambiguous or oversized hash transport accepted")
		}
		if raw, ok := c.PasswordHash(); ok || raw != "" {
			t.Fatal("failed construction retained hash")
		}
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { *s = identity.FeatureCommandSpec{} },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "passkey" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID = "identity.password.reset-complete"
			s.Binding.OperationID = s.Operation.OperationID
		},
	} {
		copy := s
		mutate(&copy)
		if _, err := identity.NewFeaturePasswordHashCommand(copy, "synthetic"); err == nil {
			t.Fatal("unsupported hash command profile accepted")
		}
	}
}

func TestFeaturePasswordHashRedactsAndSupportsConcurrentReads(t *testing.T) {
	hash := "$synthetic-only$private-verifier-material"
	c, err := identity.NewFeaturePasswordHashCommand(passwordHashFeatureSpec(), hash)
	if err != nil {
		t.Fatal(err)
	}
	type privateWrapper struct{ command identity.Command }
	for _, value := range []any{c, &c, privateWrapper{c}, &privateWrapper{c}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
			if strings.Contains(fmt.Sprintf(format, value), hash) {
				t.Fatal("diagnostics disclosed verifier material")
			}
		}
	}
	if wire, err := json.Marshal(c); err == nil || strings.Contains(string(wire), hash) {
		t.Fatal("hash command serialized")
	}
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			got, ok := c.PasswordHash()
			if !ok || got != hash {
				t.Error("concurrent hash custody changed")
			}
			if _, ok := c.PasswordHashFeature(); !ok {
				t.Error("concurrent metadata custody changed")
			}
		})
	}
	wg.Wait()
}

func FuzzFeaturePasswordHashCustody(f *testing.F) {
	f.Add("$synthetic$profile")
	f.Add("")
	f.Add("not\ncanonical")
	f.Fuzz(func(t *testing.T, hash string) {
		if len(hash) > 16385 {
			return
		}
		c, err := identity.NewFeaturePasswordHashCommand(passwordHashFeatureSpec(), hash)
		if err != nil {
			if raw, ok := c.PasswordHash(); ok || raw != "" {
				t.Fatal("denied transport retained material")
			}
			return
		}
		got, ok := c.PasswordHash()
		if !ok || got != hash {
			t.Fatal("accepted transport altered hash bytes")
		}
		if _, ok := c.Feature(); ok {
			t.Fatal("legacy route admitted opaque material")
		}
	})
}
