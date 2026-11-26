package onetap_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

var now = time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type keys struct {
	set                 coreoidc.StaticKeySet
	calls               atomic.Int32
	failure             error
	waitForCancellation bool
}

func (k *keys) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	k.calls.Add(1)
	if k.waitForCancellation {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if k.failure != nil {
		return nil, k.failure
	}
	return k.set.VerifySignature(ctx, token)
}

type fixture struct {
	validator *onetap.Validator
	config    onetap.Config
	binding   onetap.AdapterBinding
	callback  onetap.Callback
	key       *rsa.PrivateKey
	keys      *keys
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks := &keys{set: coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}}
	provider, err := oauth.NewGoogleAccountsProvider(oauth.OIDCConfig{ID: "google", Version: 7, Issuer: "https://accounts.google.com", AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth", TokenEndpoint: "https://oauth2.googleapis.com/token", RedirectURI: "https://app.test/oauth/callback", ClientID: "client.apps.googleusercontent.com", ClientSecret: []byte("test-only-client-secret"), ClientAuthentication: oauth.ClientSecretPost, Scopes: []string{"openid", "email", "profile"}, Algorithms: []string{"RS256"}, KeySet: ks, Clock: fixedClock{now}, ClockSkew: time.Second, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	cfg := onetap.Config{Provider: provider, TenantID: "tenant", Origin: "https://app.test", PolicyID: "one-tap-callback-policy", PolicyVersion: 9, Clock: fixedClock{now}}
	v, err := onetap.NewValidator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.PersistentSession, AbsoluteTTL: 7 * 24 * time.Hour, IdleTTL: 2 * time.Hour, RefreshAfter: 30 * time.Minute, FreshFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	b := session.PreAuthBinding{ID: identity.PreAuthTransactionID("AQEBAQEBAQEBAQEBAQEBAQ"), Intent: session.PreAuthIntent{TenantID: "tenant", Action: "identity.oauth.onetap-start", Origin: cfg.Origin, Nonce: [32]byte{1, 2, 3}, Remember: remember, PolicyID: cfg.PolicyID, PolicyVersion: cfg.PolicyVersion}, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute)}
	token, err := session.ParseToken("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB")
	if err != nil {
		t.Fatal(err)
	}
	digestKey, err := session.NewDigestKey(1, bytes.Repeat([]byte{11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := token.PreAuthDigest(digestKey, b)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: cookie, Version: 3})
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{validator: v, config: cfg, key: key, keys: ks, binding: onetap.AdapterBinding{Transaction: transaction, Expected: b, Cookie: cookie, ProviderID: "google", ProviderVersion: 7, ClientID: provider.Profile().ClientID}, callback: onetap.Callback{Origin: cfg.Origin, CSRFCookies: []string{"gis-double-submit-test-value"}, CSRFBody: []string{"gis-double-submit-test-value"}}}
	f.callback.Credential = oauth.GoogleCredential{IDToken: sign(t, key, f.claims())}
	return f
}

func (f fixture) claims() map[string]any {
	return map[string]any{"iss": "https://accounts.google.com", "sub": "google-stable-subject", "aud": f.binding.ClientID, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": base64.RawURLEncoding.EncodeToString(f.binding.Expected.Intent.Nonce[:])}
}
func sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"test-key"}`)) + "." + base64.RawURLEncoding.EncodeToString(encoded)
	digest := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(message + "." + base64.RawURLEncoding.EncodeToString(sig))
}

func TestCallbackSignedGoogleEvidencePreservesOriginalFlow(t *testing.T) {
	f := newFixture(t)
	for _, issuer := range []string{"https://accounts.google.com", "accounts.google.com"} {
		claims := f.claims()
		claims["iss"] = issuer
		f.callback.Credential.IDToken = sign(t, f.key, claims)
		before := bytes.Clone(f.callback.Credential.IDToken)
		got, err := f.validator.Validate(context.Background(), f.binding, f.callback)
		if err != nil {
			t.Fatal("valid signed callback denied", err)
		}
		if got.Identity().Subject() != "google-stable-subject" || got.Identity().Issuer() != "https://accounts.google.com" || got.Identity().ProviderID() != "google" {
			t.Fatal("lost verified generic OAuth identity")
		}
		original, err := got.Original()
		if err != nil {
			t.Fatal(err)
		}
		want, _ := f.binding.Transaction.Bindings()
		if original != want || original.Binding.Intent.Remember != f.binding.Expected.Intent.Remember {
			t.Fatal("original cookie/version/nonce/remember/timeline changed")
		}
		if _, present := got.Identity().AuthenticationTime(); present {
			t.Fatal("iat became authentication freshness")
		}
		if !bytes.Equal(before, f.callback.Credential.IDToken) {
			t.Fatal("mutated borrowed credential")
		}
		// Validation deliberately does not consume state; only the durable owner
		// may promise single use. Repeating this read must not create new intent.
		if again, err := f.validator.Validate(context.Background(), f.binding, f.callback); err != nil || again.Identity().Subject() != got.Identity().Subject() {
			t.Fatal("read-only verification mutated original flow")
		}
	}
}

func assertFailure(t *testing.T, got onetap.Result, err error, want onetap.ErrorKind) {
	t.Helper()
	var rejected *onetap.Error
	if !errors.As(err, &rejected) || rejected.Kind() != want {
		t.Fatalf("wrong rejection: %v, want %s", err, want)
	}
	if got.Identity().Subject() != "" || got.Identity().ProviderID() != "" {
		t.Fatal("rejection yielded provider evidence")
	}
	if _, e := got.Original(); e == nil {
		t.Fatal("rejection yielded original flow")
	}
}

func TestCallbackRejectsBrowserAndTransactionSubstitutionBeforeKeys(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name   string
		change func(*onetap.AdapterBinding, *onetap.Callback)
	}{
		{"absent cookie", func(_ *onetap.AdapterBinding, c *onetap.Callback) { c.CSRFCookies = nil }},
		{"absent body", func(_ *onetap.AdapterBinding, c *onetap.Callback) { c.CSRFBody = nil }},
		{"duplicate cookie", func(_ *onetap.AdapterBinding, c *onetap.Callback) { c.CSRFCookies = []string{"same", "same"} }},
		{"duplicate body", func(_ *onetap.AdapterBinding, c *onetap.Callback) { c.CSRFBody = []string{"same", "same"} }},
		{"empty", func(_ *onetap.AdapterBinding, c *onetap.Callback) {
			c.CSRFCookies = []string{""}
			c.CSRFBody = []string{""}
		}},
		{"mismatch", func(_ *onetap.AdapterBinding, c *onetap.Callback) { c.CSRFBody = []string{"different"} }},
		{"whitespace", func(_ *onetap.AdapterBinding, c *onetap.Callback) {
			c.CSRFCookies = []string{" token"}
			c.CSRFBody = []string{" token"}
		}},
		{"oversized", func(_ *onetap.AdapterBinding, c *onetap.Callback) {
			c.CSRFCookies = []string{strings.Repeat("x", 1025)}
			c.CSRFBody = c.CSRFCookies
		}},
		{"origin", func(_ *onetap.AdapterBinding, c *onetap.Callback) { c.Origin = "https://evil.test" }},
		{"origin alias", func(_ *onetap.AdapterBinding, c *onetap.Callback) { c.Origin = "https://APP.test:443" }},
		{"redirect", func(_ *onetap.AdapterBinding, c *onetap.Callback) { c.Redirect = "https://app.test/return" }},
		{"empty transaction", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.Transaction = session.PreAuthTransaction{} }},
		{"transaction id", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.Expected.ID = "AgICAgICAgICAgICAgICAg" }},
		{"cookie", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.Cookie.Sum[0]++ }},
		{"cookie key", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.Cookie.KeyVersion++ }},
		{"nonce", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.Expected.Intent.Nonce[0]++ }},
		{"remember", func(b *onetap.AdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.Remember = session.RememberPolicy{}
		}},
		{"tenant", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.Expected.Intent.TenantID = "other" }},
		{"policy", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.Expected.Intent.PolicyID = "other" }},
		{"policy version", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.Expected.Intent.PolicyVersion++ }},
		{"action", func(b *onetap.AdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.Action = "identity.oauth.signin-start"
		}},
		{"stored redirect", func(b *onetap.AdapterBinding, _ *onetap.Callback) {
			b.Expected.Intent.CallbackURL = "https://app.test/return"
		}},
		{"provider", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.ProviderID = "other" }},
		{"provider version", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.ProviderVersion++ }},
		{"client", func(b *onetap.AdapterBinding, _ *onetap.Callback) { b.ClientID = "other-client" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, c := f.binding, f.callback
			tc.change(&b, &c)
			// Deliberately malformed input: browser/state rejection must occur before
			// any credential parsing or key-set access.
			c.Credential.IDToken = []byte("not a JWT")
			before := f.keys.calls.Load()
			got, err := f.validator.Validate(context.Background(), b, c)
			assertFailure(t, got, err, onetap.Denied)
			if f.keys.calls.Load() != before {
				t.Fatal("browser rejection reached signature verification")
			}
		})
	}
	for _, at := range []time.Time{f.binding.Expected.IssuedAt.Add(-time.Nanosecond), f.binding.Expected.ExpiresAt} {
		cfg := f.config
		cfg.Clock = fixedClock{at}
		v, err := onetap.NewValidator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		before := f.keys.calls.Load()
		got, err := v.Validate(context.Background(), f.binding, f.callback)
		assertFailure(t, got, err, onetap.Denied)
		if f.keys.calls.Load() != before {
			t.Fatal("expired/future state reached keys")
		}
	}
}

func TestCallbackRejectsRealSignedInvalidProof(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"nonce", func(c map[string]any) { c["nonce"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }},
		{"issuer", func(c map[string]any) { c["iss"] = "https://evil.test" }},
		{"audience", func(c map[string]any) { c["aud"] = "other" }},
		{"azp", func(c map[string]any) { c["azp"] = "other" }},
		{"multi audience missing azp", func(c map[string]any) { c["aud"] = []string{f.binding.ClientID, "other"} }},
		{"expired", func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }},
		{"future issuance", func(c map[string]any) { c["iat"] = now.Add(time.Minute).Unix() }},
		{"future nbf", func(c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() }},
		{"absent subject", func(c map[string]any) { delete(c, "sub") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := f.claims()
			tc.change(claims)
			c := f.callback
			c.Credential.IDToken = sign(t, f.key, claims)
			got, err := f.validator.Validate(context.Background(), f.binding, c)
			assertFailure(t, got, err, onetap.InvalidProof)
		})
	}
	wrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := f.callback
	c.Credential.IDToken = sign(t, wrong, f.claims())
	got, err := f.validator.Validate(context.Background(), f.binding, c)
	assertFailure(t, got, err, onetap.InvalidProof)
}

func TestCallbackCancellationBoundsAndRedaction(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := f.validator.Validate(ctx, f.binding, f.callback)
	assertFailure(t, got, err, onetap.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("lost context cancellation")
	}
	for _, token := range [][]byte{nil, bytes.Repeat([]byte{'x'}, f.config.Provider.Profile().MaxTokenBytes+1)} {
		c := f.callback
		c.Credential.IDToken = token
		got, err = f.validator.Validate(context.Background(), f.binding, c)
		assertFailure(t, got, err, onetap.InvalidInput)
	}
	got, err = f.validator.Validate(nil, f.binding, f.callback)
	assertFailure(t, got, err, onetap.InvalidInput)
	var zero onetap.Validator
	got, err = zero.Validate(context.Background(), f.binding, f.callback)
	assertFailure(t, got, err, onetap.InvalidInput)
	result, err := f.validator.Validate(context.Background(), f.binding, f.callback)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{f.config, f.binding, f.callback, result, f.validator} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			printed := fmt.Sprintf(verb, value)
			for _, secret := range []string{f.binding.ClientID, "google-stable-subject", string(f.callback.Credential.IDToken), "gis-double-submit-test-value", f.config.Origin} {
				if strings.Contains(printed, secret) {
					t.Fatal("diagnostic disclosure")
				}
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("automatic private export allowed")
		}
	}
}

func TestCallbackConfigurationAndSelfConsistentForeignFlowDeny(t *testing.T) {
	f := newFixture(t)
	for _, change := range []func(*onetap.Config){
		func(c *onetap.Config) { c.Provider = nil },
		func(c *onetap.Config) { c.TenantID = "" },
		func(c *onetap.Config) { c.PolicyID = "" },
		func(c *onetap.Config) { c.PolicyVersion = 0 },
		func(c *onetap.Config) { c.Clock = nil },
		func(c *onetap.Config) { c.Origin = "https://APP.test" },
		func(c *onetap.Config) { c.Origin = "https://app.test:443" },
		func(c *onetap.Config) { c.Origin = "https://app.test/" },
		func(c *onetap.Config) { c.Origin = "https://app.test?" },
		func(c *onetap.Config) { c.Origin = "https://user@app.test" },
		func(c *onetap.Config) { c.Origin = "https://app.test#" },
		func(c *onetap.Config) { c.Origin = "http://app.test" },
	} {
		cfg := f.config
		change(&cfg)
		v, err := onetap.NewValidator(cfg)
		var rejected *onetap.Error
		if v != nil || !errors.As(err, &rejected) || rejected.Kind() != onetap.InvalidInput {
			t.Fatal("unsupported configuration admitted", err)
		}
	}
	for _, change := range []func(*session.PreAuthIntent){
		func(i *session.PreAuthIntent) { i.TenantID = "foreign" },
		func(i *session.PreAuthIntent) { i.Origin = "https://foreign.test" },
		func(i *session.PreAuthIntent) { i.PolicyID = "foreign" },
		func(i *session.PreAuthIntent) { i.PolicyVersion++ },
		func(i *session.PreAuthIntent) { i.Action = "identity.oauth.signin-start" },
		func(i *session.PreAuthIntent) { i.CallbackURL = "https://app.test/return" },
	} {
		spec, _ := f.binding.Transaction.Bindings()
		change(&spec.Binding.Intent)
		transaction, err := session.NewPreAuthTransaction(spec)
		if err != nil {
			t.Fatal(err)
		}
		b := f.binding
		b.Transaction = transaction
		b.Expected = spec.Binding
		got, err := f.validator.Validate(context.Background(), b, f.callback)
		assertFailure(t, got, err, onetap.Denied)
	}
}

func TestCallbackKeyFailureTimeoutAndConcurrentReads(t *testing.T) {
	f := newFixture(t)
	f.keys.failure = errors.New("sensitive key cache diagnostics")
	got, err := f.validator.Validate(context.Background(), f.binding, f.callback)
	assertFailure(t, got, err, onetap.InvalidProof)
	if strings.Contains(fmt.Sprintf("%#v", err), "sensitive") {
		t.Fatal("key failure diagnostics escaped")
	}
	f.keys.failure = nil
	f.keys.waitForCancellation = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	got, err = f.validator.Validate(ctx, f.binding, f.callback)
	cancel()
	assertFailure(t, got, err, onetap.Unavailable)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline cause lost")
	}
	f.keys.waitForCancellation = false
	var workers sync.WaitGroup
	errorsSeen := make(chan error, 8)
	for range 8 {
		workers.Go(func() {
			c := f.callback
			c.Credential.IDToken = bytes.Clone(c.Credential.IDToken)
			result, err := f.validator.Validate(context.Background(), f.binding, c)
			clear(c.Credential.IDToken)
			if err != nil {
				errorsSeen <- err
				return
			}
			if result.Identity().Subject() != "google-stable-subject" {
				errorsSeen <- errors.New("lost identity")
			}
		})
	}
	workers.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
	f.config.Provider.Close()
	got, err = f.validator.Validate(context.Background(), f.binding, f.callback)
	assertFailure(t, got, err, onetap.InvalidInput)
}
