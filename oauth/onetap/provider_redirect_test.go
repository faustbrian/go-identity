package onetap_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

const redirectEndpoint = "https://app.test/oauth/onetap-redirect"

func newRedirectFixture(t *testing.T) providerFixture {
	t.Helper()
	f := newProviderFixture(t)
	f.original.Provider.Mode = session.PreAuthProviderRedirect
	f.original.Transaction.Binding.Intent.CallbackURL = redirectEndpoint
	f.binding = providerBinding(t, f.original)
	var err error
	f.original, err = f.binding.Transaction.ProviderBindings()
	if err != nil {
		t.Fatal(err)
	}
	f.validator, err = onetap.NewProviderBoundRedirectValidator(f.config, redirectEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	f.callback.Redirect = redirectEndpoint
	return f
}

func TestProviderBoundRedirectPreservesOriginalAndEquivalentIdentity(t *testing.T) {
	f := newRedirectFixture(t)
	popup := f.original
	popup.Provider.Mode = session.PreAuthProviderCallback
	popup.Transaction.Binding.Intent.CallbackURL = ""
	popupBinding := providerBinding(t, popup)
	popupValidator, err := onetap.NewProviderBoundValidator(f.config)
	if err != nil {
		t.Fatal(err)
	}
	popupCallback := f.callback
	popupCallback.Redirect = ""
	want, err := popupValidator.Validate(context.Background(), popupBinding, popupCallback)
	if err != nil {
		t.Fatal("equivalent popup credential denied", err)
	}
	credential := bytes.Clone(f.callback.Credential.IDToken)
	for range 2 {
		got, err := f.validator.Validate(context.Background(), f.binding, f.callback)
		if err != nil || !reflect.DeepEqual(got.Identity(), want.Identity()) {
			t.Fatal("redirect changed verified provider identity", err)
		}
		original, err := got.Original()
		if err != nil || original != f.original || original.Transaction.Binding.Intent.Remember != f.original.Transaction.Binding.Intent.Remember {
			t.Fatal("redirect changed original mode, URL, cookie, nonce, timeline or RememberPolicy", err)
		}
		if !bytes.Equal(credential, f.callback.Credential.IDToken) {
			t.Fatal("redirect changed borrowed credential")
		}
	}
	got, err := popupValidator.Validate(context.Background(), f.binding, f.callback)
	assertProviderFailure(t, got, err, onetap.Denied)
}

func TestProviderBoundRedirectRejectsContextBeforeCredentialWork(t *testing.T) {
	f := newRedirectFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*onetap.ProviderBoundAdapterBinding, *onetap.Callback)
	}{
		{"cookie", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) { b.Cookie.Sum[0]++ }},
		{"cookie version", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) { b.Cookie.KeyVersion++ }},
		{"nonce", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) { b.Expected.Intent.Nonce[0]++ }},
		{"remember", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.Remember = session.RememberPolicy{}
		}},
		{"origin", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.Origin = "https://foreign.test" }},
		{"absent redirect", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.Redirect = "" }},
		{"different redirect", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.Redirect = "https://app.test/other" }},
		{"redirect alias", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.Redirect = redirectEndpoint + "/" }},
		{"redirect bound", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) {
			c.Redirect = strings.Repeat("x", 2049)
		}},
		{"expected redirect", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.CallbackURL = "https://app.test/other"
		}},
		{"absent CSRF cookie", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.CSRFCookies = nil }},
		{"absent CSRF body", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.CSRFBody = nil }},
		{"duplicate CSRF cookie", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) {
			c.CSRFCookies = []string{"same", "same"}
		}},
		{"duplicate CSRF body", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.CSRFBody = []string{"same", "same"} }},
		{"CSRF mismatch", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.CSRFBody = []string{"different"} }},
		{"CSRF whitespace", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) {
			c.CSRFCookies, c.CSRFBody = []string{" token"}, []string{" token"}
		}},
		{"CSRF bound", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) {
			c.CSRFCookies, c.CSRFBody = []string{strings.Repeat("x", 1025)}, []string{strings.Repeat("x", 1025)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, c := f.binding, f.callback
			tc.change(&b, &c)
			c.Credential.IDToken = []byte("not a JWT")
			before := f.keys.calls.Load()
			got, err := f.validator.Validate(context.Background(), b, c)
			assertProviderFailure(t, got, err, onetap.Denied)
			if f.keys.calls.Load() != before {
				t.Fatal("rejected redirect context reached signature verification")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*session.ProviderPreAuthTransactionSpec)
	}{
		{"callback mode", func(s *session.ProviderPreAuthTransactionSpec) {
			s.Provider.Mode = session.PreAuthProviderCallback
			s.Transaction.Binding.Intent.CallbackURL = ""
		}},
		{"different original redirect", func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.Intent.CallbackURL = "https://app.test/other"
		}},
		{"provider", func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ProviderID = "other" }},
		{"provider version", func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ProviderVersion++ }},
		{"client", func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ClientID = "other-client" }},
		{"tenant", func(s *session.ProviderPreAuthTransactionSpec) { s.Transaction.Binding.Intent.TenantID = "other" }},
		{"policy", func(s *session.ProviderPreAuthTransactionSpec) { s.Transaction.Binding.Intent.PolicyID = "other" }},
		{"policy version", func(s *session.ProviderPreAuthTransactionSpec) { s.Transaction.Binding.Intent.PolicyVersion++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := f.original
			tc.change(&original)
			b := providerBinding(t, original)
			c := f.callback
			c.Redirect = original.Transaction.Binding.Intent.CallbackURL
			c.Credential.IDToken = []byte("not a JWT")
			got, err := f.validator.Validate(context.Background(), b, c)
			assertProviderFailure(t, got, err, onetap.Denied)
		})
	}
}

func TestProviderBoundRedirectChecksOriginalExpiryAndSignedNonce(t *testing.T) {
	f := newRedirectFixture(t)
	for _, tc := range []struct {
		name         string
		first, after time.Time
		wantKeys     int32
	}{
		{"already expired", f.binding.Expected.ExpiresAt, now, 0},
		{"not issued", f.binding.Expected.IssuedAt.Add(-time.Nanosecond), now, 0},
		{"expires during verification", now, f.binding.Expected.ExpiresAt, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := f.config
			clock := &advancingProviderClock{first: tc.first, after: tc.after}
			config.Clock = clock
			v, err := onetap.NewProviderBoundRedirectValidator(config, redirectEndpoint)
			if err != nil || clock.calls.Load() != 0 {
				t.Fatal("redirect constructor read clock or failed", err)
			}
			before := f.keys.calls.Load()
			got, err := v.Validate(context.Background(), f.binding, f.callback)
			assertProviderFailure(t, got, err, onetap.Denied)
			if f.keys.calls.Load()-before != tc.wantKeys {
				t.Fatal("wrong redirect signature-verification boundary")
			}
		})
	}
	claims := f.claims()
	claims["nonce"] = "different-signed-nonce"
	c := f.callback
	c.Credential.IDToken = sign(t, f.key, claims)
	got, err := f.validator.Validate(context.Background(), f.binding, c)
	assertProviderFailure(t, got, err, onetap.InvalidProof)
}

func TestProviderBoundRedirectConfigurationRejectsNonexactEndpoints(t *testing.T) {
	f := newProviderFixture(t)
	for _, endpoint := range []string{"", "https://app.test", "http://app.test/return", "https://foreign.test/return", "https://app.test.evil/return", "https://user@app.test/return", "https://APP.test/return", "https://app.test:443/return", "https://app.test//return", "https://app.test/a/../return", "https://app.test/%72eturn", "https://app.test/return?next=other", "https://app.test/return#fragment", "https://app.test/return;other", "https://app.test/" + strings.Repeat("x", 2048)} {
		t.Run(endpoint, func(t *testing.T) {
			v, err := onetap.NewProviderBoundRedirectValidator(f.config, endpoint)
			var rejected *onetap.Error
			if v != nil || !errors.As(err, &rejected) || rejected.Kind() != onetap.InvalidInput {
				t.Fatal("nonexact trusted redirect endpoint admitted", err)
			}
		})
	}
}
