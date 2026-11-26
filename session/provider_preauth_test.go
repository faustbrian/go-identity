package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestProviderPreAuthBindsOriginalProvenanceAndFencesLegacyPath(t *testing.T) {
	token, key, base := preAuthFixture(t)
	base.Binding.Intent.Action = "identity.oauth.onetap-start"
	base.Binding.Intent.CallbackURL = ""
	selected := PreAuthProviderBinding{
		ProviderID: "google-one-tap", ProviderVersion: 7,
		ClientID: "fixture-client.apps.googleusercontent.com", Mode: PreAuthProviderCallback,
	}
	legacyDigest, err := token.PreAuthDigest(key, base.Binding)
	if err != nil {
		t.Fatal(err)
	}
	base.Cookie, err = token.ProviderPreAuthDigest(key, base.Binding, selected)
	if err != nil || base.Cookie == legacyDigest {
		t.Fatal("provider-selected cookie reused the legacy authority domain", err)
	}
	bound, err := NewProviderPreAuthTransaction(ProviderPreAuthTransactionSpec{Transaction: base, Provider: selected})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := bound.ProviderBindings()
	if err != nil || projected.Transaction != base || projected.Provider != selected {
		t.Fatal("selected flow lost its original provider, timeline, cookie or Remember", err)
	}
	if err := bound.CheckProvider(base.Binding.IssuedAt, base.Binding, selected, base.Cookie); err != nil {
		t.Fatal("original callback binding was not admitted structurally", err)
	}
	if _, err := bound.Bindings(); !errors.Is(err, ErrInvalidPreAuthTransaction) {
		t.Fatal("legacy projection could silently strip provider authority", err)
	}
	if err := bound.Check(base.Binding.IssuedAt, base.Binding, base.Cookie); !errors.Is(err, ErrPreAuthDenied) {
		t.Fatal("legacy Check admitted a provider-owned record", err)
	}
	if err := bound.CheckProvider(base.Binding.ExpiresAt, base.Binding, selected, base.Cookie); !errors.Is(err, ErrPreAuthDenied) {
		t.Fatal("original expiration was not exclusive", err)
	}
	changedPolicy := base.Binding
	changedPolicy.Intent.PolicyVersion++
	if err := bound.CheckProvider(base.Binding.IssuedAt, changedPolicy, selected, base.Cookie); !errors.Is(err, ErrPreAuthDenied) {
		t.Fatal("provider selection bypassed the original session policy", err)
	}
	if err := bound.CheckProvider(base.Binding.IssuedAt, base.Binding, selected, legacyDigest); !errors.Is(err, ErrPreAuthDenied) {
		t.Fatal("legacy cookie admitted a provider-owned flow", err)
	}
	for _, variant := range []PreAuthProviderBinding{
		{ProviderID: "other", ProviderVersion: 7, ClientID: selected.ClientID, Mode: selected.Mode},
		{ProviderID: selected.ProviderID, ProviderVersion: 8, ClientID: selected.ClientID, Mode: selected.Mode},
		{ProviderID: selected.ProviderID, ProviderVersion: 7, ClientID: "other-client.apps.googleusercontent.com", Mode: selected.Mode},
	} {
		other, err := token.ProviderPreAuthDigest(key, base.Binding, variant)
		if err != nil || other == base.Cookie {
			t.Fatal("provider identity component was omitted from cookie framing", err)
		}
		if err := bound.CheckProvider(base.Binding.IssuedAt, base.Binding, variant, base.Cookie); !errors.Is(err, ErrPreAuthDenied) {
			t.Fatal("substituted provider was admitted with the original cookie", err)
		}
	}
	base.Cookie = legacyDigest
	ordinary, err := NewPreAuthTransaction(base)
	if err != nil || ordinary.Check(base.Binding.IssuedAt, base.Binding, legacyDigest) != nil {
		t.Fatal("ordinary transaction was changed by explicit provider selection", err)
	}
	if _, err := ordinary.ProviderBindings(); !errors.Is(err, ErrInvalidPreAuthTransaction) {
		t.Fatal("unbound flow appeared provider-bound", err)
	}
	if err := ordinary.CheckProvider(base.Binding.IssuedAt, base.Binding, selected, legacyDigest); !errors.Is(err, ErrPreAuthDenied) {
		t.Fatal("ordinary flow crossed into the provider-bound path", err)
	}
	for _, value := range []any{selected, projected} {
		if _, err := json.Marshal(value); err == nil || strings.Contains(fmt.Sprintf("%#v", value), selected.ClientID) {
			t.Fatal("private provider-flow configuration leaked through formatting/JSON")
		}
	}
}

func TestProviderPreAuthRejectsUnselectedModesAndPurpose(t *testing.T) {
	token, key, base := preAuthFixture(t)
	base.Binding.Intent.Action = "identity.oauth.onetap-start"
	base.Binding.Intent.CallbackURL = ""
	domain := PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 1, ClientID: "fixture-client", Mode: PreAuthProviderCallback}
	for _, scenario := range []struct {
		name   string
		change func(*PreAuthBinding, *PreAuthProviderBinding)
	}{
		{"redirect mode not selected", func(b *PreAuthBinding, p *PreAuthProviderBinding) { p.Mode = 2 }},
		{"redirect target not selected", func(b *PreAuthBinding, p *PreAuthProviderBinding) { b.Intent.CallbackURL = "https://app.test/callback" }},
		{"wrong operation", func(b *PreAuthBinding, p *PreAuthProviderBinding) { b.Intent.Action = "identity.otp.signin" }},
		{"wrong purpose", func(b *PreAuthBinding, _ *PreAuthProviderBinding) { b.Intent.Purpose = PreAuthPhonePasswordRecovery }},
		{"no identifier substitution", func(b *PreAuthBinding, p *PreAuthProviderBinding) { b.Intent.IdentifierBinding[0] = 1 }},
		{"noncanonical provider", func(b *PreAuthBinding, p *PreAuthProviderBinding) { p.ProviderID = "google browser" }},
		{"missing version", func(b *PreAuthBinding, p *PreAuthProviderBinding) { p.ProviderVersion = 0 }},
		{"missing client", func(b *PreAuthBinding, p *PreAuthProviderBinding) { p.ClientID = "" }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			candidate, selected := base, domain
			scenario.change(&candidate.Binding, &selected)
			if _, err := token.ProviderPreAuthDigest(key, candidate.Binding, selected); !errors.Is(err, ErrInvalidPreAuthTransaction) {
				t.Fatal("invalid binding derived a provider cookie", err)
			}
			if _, err := NewProviderPreAuthTransaction(ProviderPreAuthTransactionSpec{Transaction: candidate, Provider: selected}); !errors.Is(err, ErrInvalidPreAuthTransaction) {
				t.Fatal("invalid binding reconstructed an authoritative profile", err)
			}
		})
	}
}
