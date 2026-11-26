package onetap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

type providerFixture struct {
	fixture
	config    onetap.ProviderBoundConfig
	validator *onetap.ProviderBoundValidator
	binding   onetap.ProviderBoundAdapterBinding
	original  session.ProviderPreAuthTransactionSpec
}

func newProviderFixture(t *testing.T) providerFixture {
	t.Helper()
	f := newFixture(t)
	c := onetap.ProviderBoundConfig{Provider: f.config.Provider, TenantID: f.config.TenantID, Origin: f.config.Origin, PolicyID: f.config.PolicyID, PolicyVersion: f.config.PolicyVersion, Clock: f.config.Clock}
	v, err := onetap.NewProviderBoundValidator(c)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := f.binding.Transaction.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	original := session.ProviderPreAuthTransactionSpec{Transaction: spec, Provider: session.PreAuthProviderBinding{ProviderID: f.binding.ProviderID, ProviderVersion: f.binding.ProviderVersion, ClientID: f.binding.ClientID, Mode: session.PreAuthProviderCallback}}
	b := providerBinding(t, original)
	original, err = b.Transaction.ProviderBindings()
	if err != nil {
		t.Fatal(err)
	}
	return providerFixture{fixture: f, config: c, validator: v, binding: b, original: original}
}

func providerBinding(t *testing.T, spec session.ProviderPreAuthTransactionSpec) onetap.ProviderBoundAdapterBinding {
	t.Helper()
	token, err := session.ParseToken("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB")
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := token.ProviderPreAuthDigest(key, spec.Transaction.Binding, spec.Provider)
	if err != nil {
		t.Fatal(err)
	}
	spec.Transaction.Cookie = cookie
	record, err := session.NewProviderPreAuthTransaction(spec)
	if err != nil {
		t.Fatal(err)
	}
	return onetap.ProviderBoundAdapterBinding{Transaction: record, Expected: spec.Transaction.Binding, Cookie: cookie}
}

func assertProviderFailure(t *testing.T, got onetap.ProviderBoundResult, err error, want onetap.ErrorKind) {
	t.Helper()
	var rejected *onetap.Error
	if !errors.As(err, &rejected) || rejected.Kind() != want {
		t.Fatalf("rejection = %v, want %s", err, want)
	}
	if got.Identity().Subject() != "" || got.Identity().ProviderID() != "" {
		t.Fatal("rejected callback returned provider identity")
	}
	if _, err := got.Original(); err == nil {
		t.Fatal("rejected callback returned original flow")
	}
}

func TestProviderBoundCallbackPreservesCompleteOriginalAuthority(t *testing.T) {
	f := newProviderFixture(t)
	credential := bytes.Clone(f.callback.Credential.IDToken)
	for range 2 {
		got, err := f.validator.Validate(context.Background(), f.binding, f.callback)
		if err != nil {
			t.Fatal(err)
		}
		original, err := got.Original()
		if err != nil || original != f.original {
			t.Fatal("provider/client/mode, binding, cookie, timeline, version or RememberPolicy changed", err)
		}
		if got.Identity().Subject() != "google-stable-subject" || got.Identity().ProviderID() != "google" || got.Identity().Issuer() != "https://accounts.google.com" {
			t.Fatal("lost verified generic provider identity")
		}
		if _, present := got.Identity().AuthenticationTime(); present {
			t.Fatal("iat became authentication freshness")
		}
		if !bytes.Equal(credential, f.callback.Credential.IDToken) {
			t.Fatal("borrowed credential changed")
		}
	}
	legacyBinding := f.fixture.binding
	legacyBinding.Transaction = f.binding.Transaction
	legacyBinding.Cookie = f.binding.Cookie
	got, err := f.fixture.validator.Validate(context.Background(), legacyBinding, f.callback)
	assertFailure(t, got, err, onetap.Denied)
}

func TestProviderBoundCallbackConcurrentReadOnlyValidation(t *testing.T) {
	f := newProviderFixture(t)
	f.config.HostedDomain = "workspace.test"
	v, err := onetap.NewProviderBoundValidator(f.config)
	if err != nil {
		t.Fatal(err)
	}
	claims := f.claims()
	claims["hd"] = f.config.HostedDomain
	f.callback.Credential.IDToken = sign(t, f.key, claims)
	for range 8 {
		t.Run("independent borrowed credential", func(t *testing.T) {
			t.Parallel()
			c := f.callback
			c.Credential.IDToken = bytes.Clone(c.Credential.IDToken)
			defer clear(c.Credential.IDToken)
			got, err := v.Validate(context.Background(), f.binding, c)
			if err != nil || got.Identity().Subject() != "google-stable-subject" {
				t.Fatal("concurrent signed callback lost identity", err)
			}
			original, err := got.Original()
			if err != nil || original != f.original {
				t.Fatal("concurrent callback changed original authority", err)
			}
		})
	}
}

func TestProviderBoundCallbackRejectsSubstitutionBeforeCredentialWork(t *testing.T) {
	f := newProviderFixture(t)
	cases := []struct {
		name   string
		change func(*onetap.ProviderBoundAdapterBinding, *onetap.Callback)
	}{
		{"legacy flow", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Transaction = f.fixture.binding.Transaction
		}},
		{"empty flow", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Transaction = session.PreAuthTransaction{}
		}},
		{"cookie", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) { b.Cookie.Sum[0]++ }},
		{"cookie key", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) { b.Cookie.KeyVersion++ }},
		{"legacy cookie domain", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) { b.Cookie = f.fixture.binding.Cookie }},
		{"nonce", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) { b.Expected.Intent.Nonce[0]++ }},
		{"remember", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.Remember = session.RememberPolicy{}
		}},
		{"wrong operation", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.Action = "identity.oauth.signin-start"
		}},
		{"wrong purpose", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.Purpose = session.PreAuthPhonePasswordRecovery
		}},
		{"stored redirect", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.CallbackURL = "https://app.test/return"
		}},
		{"identifier substitution", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.IdentifierBinding[0] = 1
		}},
		{"record id", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.ID = "AgICAgICAgICAgICAgICAg"
		}},
		{"issued at", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.IssuedAt = b.Expected.IssuedAt.Add(time.Second)
		}},
		{"expires at", func(b *onetap.ProviderBoundAdapterBinding, _ *onetap.Callback) {
			b.Expected.ExpiresAt = b.Expected.ExpiresAt.Add(time.Second)
		}},
		{"origin", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.Origin = "https://foreign.test" }},
		{"redirect", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) {
			c.Redirect = "https://app.test/return"
		}},
		{"absent cookie", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.CSRFCookies = nil }},
		{"absent body", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.CSRFBody = nil }},
		{"duplicate cookie", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) {
			c.CSRFCookies = []string{"same", "same"}
		}},
		{"duplicate body", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.CSRFBody = []string{"same", "same"} }},
		{"CSRF mismatch", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) { c.CSRFBody = []string{"different"} }},
		{"CSRF whitespace", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) {
			c.CSRFCookies, c.CSRFBody = []string{" value"}, []string{" value"}
		}},
		{"CSRF bound", func(_ *onetap.ProviderBoundAdapterBinding, c *onetap.Callback) {
			c.CSRFCookies, c.CSRFBody = []string{strings.Repeat("x", 1025)}, []string{strings.Repeat("x", 1025)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, c := f.binding, f.callback
			tc.change(&b, &c)
			c.Credential.IDToken = []byte("not a JWT")
			before := f.keys.calls.Load()
			got, err := f.validator.Validate(context.Background(), b, c)
			assertProviderFailure(t, got, err, onetap.Denied)
			if f.keys.calls.Load() != before {
				t.Fatal("substitution reached signature verification")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*session.ProviderPreAuthTransactionSpec)
	}{
		{"provider", func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ProviderID = "other" }},
		{"provider version", func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ProviderVersion++ }},
		{"client", func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ClientID = "another-client" }},
		{"tenant", func(s *session.ProviderPreAuthTransactionSpec) { s.Transaction.Binding.Intent.TenantID = "foreign" }},
		{"origin", func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.Intent.Origin = "https://foreign.test"
		}},
		{"policy", func(s *session.ProviderPreAuthTransactionSpec) { s.Transaction.Binding.Intent.PolicyID = "foreign" }},
		{"policy version", func(s *session.ProviderPreAuthTransactionSpec) { s.Transaction.Binding.Intent.PolicyVersion++ }},
	} {
		t.Run("self-consistent foreign "+tc.name, func(t *testing.T) {
			spec := f.original
			tc.change(&spec)
			b := providerBinding(t, spec)
			c := f.callback
			c.Credential.IDToken = []byte("not a JWT")
			got, err := f.validator.Validate(context.Background(), b, c)
			assertProviderFailure(t, got, err, onetap.Denied)
		})
	}
}

func TestProviderBoundCallbackConfigurationRejectsUnsupportedContext(t *testing.T) {
	f := newProviderFixture(t)
	for _, change := range []func(*onetap.ProviderBoundConfig){
		func(c *onetap.ProviderBoundConfig) { c.Provider = nil },
		func(c *onetap.ProviderBoundConfig) { c.TenantID = "" },
		func(c *onetap.ProviderBoundConfig) { c.PolicyID = "" },
		func(c *onetap.ProviderBoundConfig) { c.PolicyVersion = 0 },
		func(c *onetap.ProviderBoundConfig) { c.Clock = nil },
		func(c *onetap.ProviderBoundConfig) { c.Origin = "https://APP.test" },
		func(c *onetap.ProviderBoundConfig) { c.Origin = "https://app.test:443" },
		func(c *onetap.ProviderBoundConfig) { c.Origin = "https://app.test/" },
	} {
		cfg := f.config
		change(&cfg)
		v, err := onetap.NewProviderBoundValidator(cfg)
		var rejected *onetap.Error
		if v != nil || !errors.As(err, &rejected) || rejected.Kind() != onetap.InvalidInput {
			t.Fatal("unsupported provider-bound configuration admitted", err)
		}
	}
}

func TestProviderBoundCallbackHostedDomainUsesOnlySignedHD(t *testing.T) {
	f := newProviderFixture(t)
	f.config.HostedDomain = "workspace.test"
	v, err := onetap.NewProviderBoundValidator(f.config)
	if err != nil {
		t.Fatal(err)
	}
	for _, hd := range []any{"workspace.test", "other.test", "WORKSPACE.test", "sub.workspace.test", "workspace.test.", nil, 42, true, []string{"workspace.test"}} {
		claims := f.claims()
		claims["hd"] = hd
		claims["email"] = "user@workspace.test"
		claims["email_verified"] = true
		c := f.callback
		c.Credential.IDToken = sign(t, f.key, claims)
		got, err := v.Validate(context.Background(), f.binding, c)
		if domain, ok := hd.(string); ok && domain == "workspace.test" {
			if err != nil || got.Identity().Subject() == "" {
				t.Fatal("exact signed domain denied", err)
			}
		} else {
			assertProviderFailure(t, got, err, onetap.InvalidProof)
		}
	}
	claims := f.claims()
	claims["email"], claims["email_verified"] = "user@workspace.test", true
	c := f.callback
	c.Credential.IDToken = sign(t, f.key, claims)
	got, err := v.Validate(context.Background(), f.binding, c)
	assertProviderFailure(t, got, err, onetap.InvalidProof)
	if got, err = f.validator.Validate(context.Background(), f.binding, c); err != nil || got.Identity().Subject() == "" {
		t.Fatal("optional domain became mandatory without configuration", err)
	}
	for _, domain := range []string{"Workspace.test", " workspace.test", "workspace.test.", "*.workspace.test", "single", "workspace.123", "https://workspace.test"} {
		cfg := f.config
		cfg.HostedDomain = domain
		v, err := onetap.NewProviderBoundValidator(cfg)
		var rejected *onetap.Error
		if v != nil || !errors.As(err, &rejected) || rejected.Kind() != onetap.InvalidInput {
			t.Fatal("invalid trusted domain admitted", err)
		}
	}
}

type advancingProviderClock struct {
	calls        atomic.Int32
	first, after time.Time
}

func (c *advancingProviderClock) Now() time.Time {
	if c.calls.Add(1) == 1 {
		return c.first
	}
	return c.after
}

func TestProviderBoundCallbackRechecksOriginalExpiryAfterSignature(t *testing.T) {
	f := newProviderFixture(t)
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
			cfg := f.config
			clock := &advancingProviderClock{first: tc.first, after: tc.after}
			cfg.Clock = clock
			v, err := onetap.NewProviderBoundValidator(cfg)
			if err != nil || clock.calls.Load() != 0 {
				t.Fatal("constructor read clock or failed", err)
			}
			before := f.keys.calls.Load()
			got, err := v.Validate(context.Background(), f.binding, f.callback)
			assertProviderFailure(t, got, err, onetap.Denied)
			if f.keys.calls.Load()-before != tc.wantKeys {
				t.Fatal("wrong signature-verification boundary")
			}
		})
	}
}

func TestProviderBoundCallbackFailuresAndPrivateDiagnostics(t *testing.T) {
	f := newProviderFixture(t)
	for _, token := range [][]byte{nil, bytes.Repeat([]byte{'x'}, f.config.Provider.Profile().MaxTokenBytes+1)} {
		c := f.callback
		c.Credential.IDToken = token
		got, err := f.validator.Validate(context.Background(), f.binding, c)
		assertProviderFailure(t, got, err, onetap.InvalidInput)
	}
	malformed := f.callback
	malformed.Credential.IDToken = []byte("not a JWT")
	malformedResult, malformedErr := f.validator.Validate(context.Background(), f.binding, malformed)
	assertProviderFailure(t, malformedResult, malformedErr, onetap.InvalidProof)
	claims := f.claims()
	claims["nonce"] = "another-nonce"
	c := f.callback
	c.Credential.IDToken = sign(t, f.key, claims)
	got, err := f.validator.Validate(context.Background(), f.binding, c)
	assertProviderFailure(t, got, err, onetap.InvalidProof)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err = f.validator.Validate(ctx, f.binding, f.callback)
	assertProviderFailure(t, got, err, onetap.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation")
	}
	f.keys.failure = errors.New("private-key-cache-diagnostic")
	got, err = f.validator.Validate(context.Background(), f.binding, f.callback)
	assertProviderFailure(t, got, err, onetap.InvalidProof)
	if strings.Contains(fmt.Sprintf("%#v", err), "private-key-cache") {
		t.Fatal("leaked key diagnostic")
	}
	f.keys.failure = nil
	f.keys.waitForCancellation = true
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	got, err = f.validator.Validate(ctx, f.binding, f.callback)
	cancel()
	assertProviderFailure(t, got, err, onetap.Unavailable)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lost deadline")
	}
	f.keys.waitForCancellation = false
	result, err := f.validator.Validate(context.Background(), f.binding, f.callback)
	if err != nil {
		t.Fatal(err)
	}
	f.config.HostedDomain = "private-workspace.test"
	for _, value := range []any{f.config, f.binding, result, f.validator} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			printed := fmt.Sprintf(verb, value)
			for _, secret := range []string{f.config.HostedDomain, f.fixture.binding.ClientID, f.config.Origin, "google-stable-subject", string(f.callback.Credential.IDToken)} {
				if strings.Contains(printed, secret) {
					t.Fatal("private callback diagnostic escaped")
				}
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private callback export allowed")
		}
	}
	var zero onetap.ProviderBoundValidator
	got, err = zero.Validate(context.Background(), f.binding, f.callback)
	assertProviderFailure(t, got, err, onetap.InvalidInput)
	got, err = f.validator.Validate(nil, f.binding, f.callback)
	assertProviderFailure(t, got, err, onetap.InvalidInput)
}
