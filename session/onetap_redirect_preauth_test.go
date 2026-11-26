package session

import (
	"errors"
	"testing"
	"time"
)

func TestOneTapRedirectPreAuthKeepsTheOriginalModeTargetAndDeadline(t *testing.T) {
	token, key, original := preAuthFixture(t)
	original.Binding.Intent.Action = "identity.oauth.onetap-start"
	original.Binding.Intent.CallbackURL = original.Binding.Intent.Origin + "/v1/oauth/onetap-redirect"
	selected := PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "test-gis-client", Mode: PreAuthProviderRedirect}
	digest, err := token.ProviderPreAuthDigest(key, original.Binding, selected)
	if err != nil {
		t.Fatal("exact configured redirect failed to derive its original browser binding", err)
	}
	original.Cookie = digest
	bound, err := NewProviderPreAuthTransaction(ProviderPreAuthTransactionSpec{Transaction: original, Provider: selected})
	if err != nil {
		t.Fatal("exact redirect could not retain original authority", err)
	}
	got, err := bound.ProviderBindings()
	if err != nil || got.Transaction != original || got.Provider != selected {
		t.Fatal("redirect changed the original timeline, RememberPolicy or provider binding", err)
	}
	lastValid := original.Binding.ExpiresAt.Add(-time.Nanosecond)
	if bound.CheckProvider(lastValid, original.Binding, selected, digest) != nil ||
		!errors.Is(bound.CheckProvider(original.Binding.ExpiresAt, original.Binding, selected, digest), ErrPreAuthDenied) {
		t.Fatal("redirect did not retain the original exclusive deadline")
	}
	callback := selected
	callback.Mode = PreAuthProviderCallback
	popup := original.Binding
	popup.Intent.CallbackURL = ""
	popupCookie, err := token.ProviderPreAuthDigest(key, popup, callback)
	if err != nil || popupCookie == digest || !errors.Is(bound.CheckProvider(lastValid, popup, callback, popupCookie), ErrPreAuthDenied) {
		t.Fatal("an otherwise matching popup could cross the redirect boundary", err)
	}
	changedURL := original.Binding
	changedURL.Intent.CallbackURL = original.Binding.Intent.Origin + "/v1/oauth/another-endpoint"
	changedCookie, err := token.ProviderPreAuthDigest(key, changedURL, selected)
	if err != nil || changedCookie == digest || !errors.Is(bound.CheckProvider(lastValid, changedURL, selected, changedCookie), ErrPreAuthDenied) {
		t.Fatal("a different valid endpoint replaced original redirect custody", err)
	}
	for _, substitution := range []struct{ name, url string }{
		{"empty", ""},
		{"foreign host", "https://foreign.example.test/v1/oauth/onetap-redirect"},
		{"host suffix", original.Binding.Intent.Origin + ".example.test/v1/oauth/onetap-redirect"},
		{"query", original.Binding.Intent.CallbackURL + "?continue=1"},
		{"fragment", original.Binding.Intent.CallbackURL + "#result"},
		{"escaped path", original.Binding.Intent.Origin + "/v1/oauth/%6fnetap-redirect"},
		{"browser-escaped path", original.Binding.Intent.Origin + "/v1/oauth/<redirect>"},
		{"unclean path", original.Binding.Intent.Origin + "/v1/../v1/oauth/onetap-redirect"},
	} {
		t.Run(substitution.name, func(t *testing.T) {
			candidate := original
			candidate.Binding.Intent.CallbackURL = substitution.url
			if _, err := token.ProviderPreAuthDigest(key, candidate.Binding, selected); !errors.Is(err, ErrInvalidPreAuthTransaction) {
				t.Fatal("substituted URL derived redirect cookie authority", err)
			}
			if _, err := NewProviderPreAuthTransaction(ProviderPreAuthTransactionSpec{Transaction: candidate, Provider: selected}); !errors.Is(err, ErrInvalidPreAuthTransaction) {
				t.Fatal("substituted URL became a provider transaction", err)
			}
		})
	}
	if _, err := bound.Bindings(); !errors.Is(err, ErrInvalidPreAuthTransaction) {
		t.Fatal("legacy projection dropped selected redirect authority", err)
	}
}

func TestOneTapRedirectPreAuthRejectsBrowserOriginAliases(t *testing.T) {
	token, key, original := preAuthFixture(t)
	original.Binding.Intent.Action = "identity.oauth.onetap-start"
	selected := PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "test-gis-client", Mode: PreAuthProviderRedirect}
	for _, test := range []struct {
		name, origin string
		allowed      bool
	}{
		{"configured port", "https://identity.test:9443", true},
		{"canonical IPv4", "https://127.0.0.1:9443", true},
		{"uppercase host", "https://Identity.test", false},
		{"default-port alias", "https://identity.test:443", false},
		{"zero-padded port", "https://identity.test:09443", false},
		{"invalid port", "https://identity.test:65536", false},
		{"empty port", "https://identity.test:", false},
		{"bracketed IPv4", "https://[127.0.0.1]:9443", false},
		{"hyphenated label boundary", "https://identity-.test", false},
		{"trailing domain dot", "https://identity.test.", false},
		{"short numeric IPv4", "https://127.1", false},
		{"hex numeric host", "https://0x7f000001", false},
		{"non-TLS", "http://127.0.0.1", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := original
			candidate.Binding.Intent.Origin = test.origin
			candidate.Binding.Intent.CallbackURL = test.origin + "/v1/oauth/onetap-redirect"
			digest, err := token.ProviderPreAuthDigest(key, candidate.Binding, selected)
			if test.allowed {
				if err != nil {
					t.Fatal("exact canonical browser origin was rejected", err)
				}
				candidate.Cookie = digest
			} else if !errors.Is(err, ErrInvalidPreAuthTransaction) {
				t.Fatal("noncanonical browser origin derived redirect authority", err)
			}
			_, err = NewProviderPreAuthTransaction(ProviderPreAuthTransactionSpec{Transaction: candidate, Provider: selected})
			if (err == nil) != test.allowed {
				t.Fatal("redirect profile accepted or rejected the wrong origin", err)
			}
		})
	}
}

func TestOneTapRedirectPreAuthCannotUseEitherCallbackIssuer(t *testing.T) {
	legacy, _, executor, _ := preAuthIssuerFixture(t)
	config := legacy.config
	config.Action = "identity.oauth.onetap-start"
	config.CallbackURL = config.Origin + "/v1/oauth/onetap-redirect"
	selected := PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "test-gis-client", Mode: PreAuthProviderRedirect}
	for _, factory := range []func(PreAuthIssuanceExecutor, PreAuthIssuerConfig, PreAuthProviderBinding) (*PreAuthIssuer, error){NewProviderPreAuthIssuer, NewOneTapStartPreAuthIssuer} {
		if got, err := factory(executor, config, selected); got != nil || !errors.Is(err, ErrInvalidIssuer) {
			t.Fatal("existing callback issuer silently opted into redirect", err)
		}
	}
}
