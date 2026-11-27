package oauthproxy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

func TestPreviewCompletionPreservesSignedIdentityAndEarliestDeadlineWithoutConsuming(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		originalTTL, flowTTL, wantTTL time.Duration
	}{
		{"signed proof", 3 * time.Minute, 4 * time.Minute, time.Minute},
		{"original envelope", 30 * time.Second, 4 * time.Minute, 30 * time.Second},
		{"browser flow", 3 * time.Minute, 20 * time.Second, 20 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCompletionFixture(t, tc.originalTTL, tc.flowTTL)
			admission := f.admission(t)
			before := bytes.Clone(f.request.Envelope)
			for range 2 {
				out, err := admission.Open(t.Context(), f.original, f.flow, f.request)
				principal, ok := out.Identity()
				if err != nil || !ok || principal.ProviderID() != "oidc" || principal.Issuer() != f.original.Issuer || principal.Subject() != "linked-test-subject" {
					t.Fatal("exact signed provider profile was not admitted", err)
				}
				if !principal.IDTokenIssuedAt().Equal(f.now.Add(-time.Second)) || !principal.IDTokenExpiresAt().Equal(f.now.Add(time.Minute)) || !principal.EvidenceExpiresAt().Equal(f.now.Add(time.Minute)) {
					t.Fatal("signed times were replaced or renewed")
				}
				if at, present := principal.AuthenticationTime(); present || !at.IsZero() {
					t.Fatal("token issuance was promoted to authentication time")
				}
				if !out.ExpiresAt().Equal(f.now.Add(tc.wantTTL)) || out.EnvelopeDigest() != sha256.Sum256(before) {
					t.Fatal("completion did not preserve the earliest deadline and exact authenticated wire")
				}
			}
			// Authentication can repeat locally. It is deliberately not a durable
			// one-use grant; native completion must still reserve and consume.
			if f.exchanges.Load() != 1 || !bytes.Equal(before, f.request.Envelope) {
				t.Fatal("preview performed provider work or modified borrowed wire")
			}
		})
	}
}

func TestPreviewCompletionRejectsMismatchedOriginalBrowserAndCiphertext(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*testing.T, *completionFixture)
	}{
		{"request origin", func(_ *testing.T, f *completionFixture) { f.request.Origin = "https://other.example" }},
		{"noncanonical origin", func(_ *testing.T, f *completionFixture) { f.request.Origin += "/" }},
		{"original tenant", func(_ *testing.T, f *completionFixture) { f.original.TenantID = "tenant-b" }},
		{"original production", func(_ *testing.T, f *completionFixture) { f.original.ProductionDeployment = "production-b" }},
		{"original preview", func(_ *testing.T, f *completionFixture) { f.original.PreviewDeployment = "preview-b" }},
		{"original origin", func(_ *testing.T, f *completionFixture) { f.original.PreviewOrigin = "https://other.example" }},
		{"original redirect", func(_ *testing.T, f *completionFixture) { f.original.PreviewRedirect += "/other" }},
		{"original recipient", func(_ *testing.T, f *completionFixture) { f.original.Recipient = "other-preview" }},
		{"original command", func(_ *testing.T, f *completionFixture) { f.original.CommandID = "AwMDAwMDAwMDAwMDAwMDAw" }},
		{"original fingerprint", func(_ *testing.T, f *completionFixture) { f.original.RequestFingerprint[0] ^= 1 }},
		{"ciphertext", func(_ *testing.T, f *completionFixture) { f.request.Envelope[len(f.request.Envelope)-1] ^= 1 }},
		{"different cookie", func(_ *testing.T, f *completionFixture) {
			f.request.FlowCookie = authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
		}},
		{"missing flow", func(_ *testing.T, f *completionFixture) { f.flow = session.PreAuthTransaction{} }},
		{"flow identity", completionAlterFlow(func(b *session.PreAuthBinding) { b.ID = "AwMDAwMDAwMDAwMDAwMDAw" })},
		{"flow tenant", completionAlterFlow(func(b *session.PreAuthBinding) { b.Intent.TenantID = "tenant-b" })},
		{"flow action", completionAlterFlow(func(b *session.PreAuthBinding) { b.Intent.Action = "identity.oauth.onetap-start" })},
		{"flow origin", completionAlterFlow(func(b *session.PreAuthBinding) { b.Intent.Origin = "https://other.example" })},
		{"flow redirect", completionAlterFlow(func(b *session.PreAuthBinding) { b.Intent.CallbackURL += "/other" })},
		{"flow policy", completionAlterFlow(func(b *session.PreAuthBinding) { b.Intent.PolicyID = "other-policy" })},
		{"flow policy version", completionAlterFlow(func(b *session.PreAuthBinding) { b.Intent.PolicyVersion++ })},
		{"identifier-bound flow", completionAlterFlow(func(b *session.PreAuthBinding) { b.Intent.IdentifierBinding[0] = 1 })},
		{"flow Remember", func(t *testing.T, f *completionFixture) {
			completionAlterFlow(func(b *session.PreAuthBinding) {
				spec, _ := b.Intent.Remember.Bindings()
				spec.FreshFor += time.Minute
				var err error
				b.Intent.Remember, err = session.NewRememberPolicy(spec)
				if err != nil {
					t.Fatal(err)
				}
			})(t, f)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCompletionFixture(t, 3*time.Minute, 4*time.Minute)
			tc.alter(t, &f)
			out, err := f.admission(t).Open(t.Context(), f.original, f.flow, f.request)
			assertCompletionFailure(t, out, err, CompletionDenied)
			if f.exchanges.Load() != 1 {
				t.Fatal("preview contacted the provider")
			}
		})
	}
}

func TestPreviewCompletionVerifiesRetainedCookieKeyAndEquivalentRemember(t *testing.T) {
	f := newCompletionFixture(t, 3*time.Minute, 4*time.Minute)
	spec, _ := f.flow.Bindings()
	remember, _ := spec.Binding.Intent.Remember.Bindings()
	spec.Binding.Intent.Remember, _ = session.NewRememberPolicy(remember)
	f.flow, _ = session.NewPreAuthTransaction(spec)
	active, err := session.NewDigestKey(2, bytes.Repeat([]byte{12}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.config.FlowKeys = []session.DigestKey{active, f.key}
	admission := f.admission(t)
	// Construction must copy the retained selection, not borrow the slice.
	f.config.FlowKeys[1] = active
	if _, err := admission.Open(t.Context(), f.original, f.flow, f.request); err != nil {
		t.Fatal("retained exact flow key or semantically equal Remember was denied", err)
	}
	f.config.FlowKeys = []session.DigestKey{active}
	out, err := f.admission(t).Open(t.Context(), f.original, f.flow, f.request)
	assertCompletionFailure(t, out, err, CompletionDenied)
	wrongMaterial, err := session.NewDigestKey(1, bytes.Repeat([]byte{19}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.config.FlowKeys = []session.DigestKey{wrongMaterial}
	out, err = f.admission(t).Open(t.Context(), f.original, f.flow, f.request)
	assertCompletionFailure(t, out, err, CompletionDenied)
}

func TestPreviewCompletionDeniesBrowserBeforeOpeningEnvelope(t *testing.T) {
	f := newCompletionFixture(t, 3*time.Minute, 4*time.Minute)
	var codecReads atomic.Int32
	codecClock := &completionClock{at: f.now, onRead: func() { codecReads.Add(1) }}
	f.config.Codec = testEvidenceCodec(t, codecClock)
	f.request.FlowCookie = authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	out, err := f.admission(t).Open(t.Context(), f.original, f.flow, f.request)
	assertCompletionFailure(t, out, err, CompletionDenied)
	if codecReads.Load() != 0 {
		t.Fatal("envelope was opened before authenticating original browser custody")
	}
}

func TestPreviewCompletionRejectsExpiredOrFutureOriginalFlowAndProof(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		originalTTL, flowTTL, advance time.Duration
		alter                         func(*testing.T, *completionFixture)
	}{
		{"signed proof expires", 3 * time.Minute, 4 * time.Minute, time.Minute, nil},
		{"original expires", 30 * time.Second, 4 * time.Minute, 30 * time.Second, nil},
		{"browser flow expires", 3 * time.Minute, 20 * time.Second, 20 * time.Second, nil},
		{"future original", 3 * time.Minute, 4 * time.Minute, 0, func(_ *testing.T, f *completionFixture) { f.original.IssuedAt = f.now.Add(time.Second) }},
		{"future flow", 3 * time.Minute, 4 * time.Minute, 0, completionAlterFlow(func(b *session.PreAuthBinding) { b.IssuedAt = b.IssuedAt.Add(2 * time.Minute) })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCompletionFixture(t, tc.originalTTL, tc.flowTTL)
			f.clock.at = f.now.Add(tc.advance)
			if tc.alter != nil {
				tc.alter(t, &f)
			}
			out, err := f.admission(t).Open(t.Context(), f.original, f.flow, f.request)
			assertCompletionFailure(t, out, err, CompletionDenied)
		})
	}
}

func TestPreviewCompletionRechecksClockAndCancellationAfterCodec(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after func(*completionFixture, context.CancelFunc)
		want  CompletionError
	}{
		{"clock rolls backwards", func(f *completionFixture, _ context.CancelFunc) { f.clock.at = f.now.Add(-time.Nanosecond) }, CompletionDenied},
		{"flow expires during open", func(f *completionFixture, _ context.CancelFunc) { f.clock.at = f.now.Add(20 * time.Second) }, CompletionDenied},
		{"cancelled during open", func(_ *completionFixture, cancel context.CancelFunc) { cancel() }, CompletionUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCompletionFixture(t, 3*time.Minute, 20*time.Second)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			codecClock := &completionClock{at: f.now}
			codecClock.onRead = func() { tc.after(&f, cancel) }
			// Both codecs use the same real keyring. Changing the recipient's
			// clock does not change the already authenticated handoff.
			f.config.Codec = testEvidenceCodec(t, codecClock)
			out, err := f.admission(t).Open(ctx, f.original, f.flow, f.request)
			assertCompletionFailure(t, out, err, tc.want)
		})
	}
}

func TestPreviewCompletionValidatesConfigurationAndBoundedRequest(t *testing.T) {
	f := newCompletionFixture(t, 3*time.Minute, 4*time.Minute)
	for _, alter := range []func(*PreviewCompletionConfig){
		func(c *PreviewCompletionConfig) { c.TenantID = "" },
		func(c *PreviewCompletionConfig) { c.ProductionDeployment = "production/A" },
		func(c *PreviewCompletionConfig) { c.ProductionDeployment = c.Target.Deployment },
		func(c *PreviewCompletionConfig) { c.Target.Origin += "/" },
		func(c *PreviewCompletionConfig) { c.PolicyID = "" },
		func(c *PreviewCompletionConfig) { c.PolicyVersion = 0 },
		func(c *PreviewCompletionConfig) { c.FlowKeys = nil },
		func(c *PreviewCompletionConfig) { c.FlowKeys = []session.DigestKey{{}} },
		func(c *PreviewCompletionConfig) { c.FlowKeys = []session.DigestKey{f.key, f.key} },
		func(c *PreviewCompletionConfig) { c.Codec = nil },
		func(c *PreviewCompletionConfig) { c.Clock = nil },
		func(c *PreviewCompletionConfig) { c.MaximumDuration = 0 },
		func(c *PreviewCompletionConfig) { c.MaximumDuration = 21 * time.Second },
	} {
		config := f.config
		alter(&config)
		if out, err := NewPreviewCompletionAdmission(config); out != nil || !errors.Is(err, CompletionInvalid) {
			t.Fatal("invalid configuration was accepted", err)
		}
	}
	for _, alter := range []func(*PreviewCompletionRequest){
		func(r *PreviewCompletionRequest) { r.Envelope = nil },
		func(r *PreviewCompletionRequest) { r.Envelope = make([]byte, 8193) },
		func(r *PreviewCompletionRequest) { r.FlowCookie = authentication.BearerCredential{} },
		func(r *PreviewCompletionRequest) {
			r.FlowCookie = authentication.NewBearerCredential(strings.Repeat("x", 8193))
		},
	} {
		request := f.request
		alter(&request)
		out, err := f.admission(t).Open(t.Context(), f.original, f.flow, request)
		assertCompletionFailure(t, out, err, CompletionInvalid)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out, err := f.admission(t).Open(ctx, f.original, f.flow, f.request)
	assertCompletionFailure(t, out, err, CompletionUnavailable)
	var absent *PreviewCompletionAdmission
	out, err = absent.Open(t.Context(), f.original, f.flow, f.request)
	assertCompletionFailure(t, out, err, CompletionInvalid)
	out, err = f.admission(t).Open(nil, f.original, f.flow, f.request)
	assertCompletionFailure(t, out, err, CompletionInvalid)
	f.config.MaximumDuration = time.Nanosecond
	out, err = f.admission(t).Open(t.Context(), f.original, f.flow, f.request)
	assertCompletionFailure(t, out, err, CompletionUnavailable)
}

func TestPreviewCompletionRedactsEveryAutomaticProjection(t *testing.T) {
	f := newCompletionFixture(t, 3*time.Minute, 4*time.Minute)
	admission := f.admission(t)
	out, err := admission.Open(t.Context(), f.original, f.flow, f.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{f.config, f.request, out, admission} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			printed := fmt.Sprintf(verb, value)
			for _, secret := range []string{f.request.FlowCookie.Token(), "linked-test-subject", f.original.Issuer, f.config.PolicyID} {
				if strings.Contains(printed, secret) {
					t.Fatal("automatic formatting disclosed completion custody")
				}
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("completion custody was serialized to JSON")
		}
		text, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatal("completion custody has no text disclosure guard")
		}
		if _, err := text.MarshalText(); err == nil {
			t.Fatal("completion custody was serialized to text")
		}
	}
	assertCompletionFailure(t, PreviewEvidence{}, CompletionDenied, CompletionDenied)
}

type completionFixture struct {
	now       time.Time
	clock     *completionClock
	config    PreviewCompletionConfig
	original  oauth.ProxyOIDCEvidenceBinding
	flow      session.PreAuthTransaction
	request   PreviewCompletionRequest
	key       session.DigestKey
	exchanges *atomic.Int32
}

func (f completionFixture) admission(t *testing.T) *PreviewCompletionAdmission {
	t.Helper()
	admission, err := NewPreviewCompletionAdmission(f.config)
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

type completionClock struct {
	at     time.Time
	onRead func()
}

func (c *completionClock) Now() time.Time {
	if c.onRead != nil {
		c.onRead()
	}
	return c.at
}

func newCompletionFixture(t *testing.T, originalTTL, flowTTL time.Duration) completionFixture {
	t.Helper()
	f := newCallbackFixture(t)
	exchanges := &atomic.Int32{}
	var signed atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/token" || req.ParseForm() != nil || req.PostForm.Get("code") != "local-code" {
			t.Error("unexpected production exchange")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-access", "id_token": signed.Load(), "token_type": "Bearer", "expires_in": 120})
	}))
	t.Cleanup(server.Close)
	key := newSigningKey(t)
	signed.Store(testIDToken(t, key, f, server.URL))
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: "oidc", Version: 2, Issuer: server.URL, ClientID: "client-a", RedirectURI: f.route,
		AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token",
		ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid"}, Algorithms: []string{"ES256"},
		KeySet: &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, Clock: f.clock, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	exchange, err := oauth.NewOIDCProxyExchange(provider, "")
	if err != nil {
		t.Fatal(err)
	}
	clock := &completionClock{at: f.now}
	codec := testEvidenceCodec(t, clock)
	f.store.original.Binding.Issuer = server.URL
	f.store.original.Binding.ExpiresAt = f.now.Add(originalTTL)
	f.store.checkForward = func() bool { return exchanges.Load() == 1 }
	production, err := NewProductionCallback(ProductionCallbackConfig{ProductionDeployment: "production-a", Provider: exchange, Codec: codec, Store: f.store, Clock: f.clock, Targets: []PreviewTarget{f.target}})
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"state": {f.state}, "code": {"local-code"}, "iss": {server.URL}}.Encode()
	handoff, err := production.Handle(t.Context(), f.route, query)
	if err != nil {
		t.Fatal("real signed production handoff failed", err)
	}
	flowKey, err := session.NewDigestKey(1, bytes.Repeat([]byte{11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	binding := session.PreAuthBinding{ID: f.store.original.Binding.TransactionID, Intent: session.PreAuthIntent{
		TenantID: f.store.original.Binding.TenantID, Action: "identity.oauth.callback", Origin: f.target.Origin, CallbackURL: f.target.Redirect,
		Nonce: [32]byte{1}, Remember: f.store.original.Binding.Remember, PolicyID: "preview-policy", PolicyVersion: 3,
	}, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(flowTTL)}
	flow := completionFlow(t, binding, cookie, flowKey)
	return completionFixture{now: f.now, clock: clock, original: f.store.original.Binding, flow: flow, key: flowKey, exchanges: exchanges,
		config:  PreviewCompletionConfig{TenantID: f.store.original.Binding.TenantID, ProductionDeployment: "production-a", Target: f.target, PolicyID: "preview-policy", PolicyVersion: 3, FlowKeys: []session.DigestKey{flowKey}, Codec: codec, Clock: clock, MaximumDuration: time.Second},
		request: PreviewCompletionRequest{Origin: f.target.Origin, FlowCookie: authentication.NewBearerCredential(cookie), Envelope: handoff.Envelope()},
	}
}

func completionFlow(t *testing.T, binding session.PreAuthBinding, cookie string, key session.DigestKey) session.PreAuthTransaction {
	t.Helper()
	token, err := session.ParseToken(cookie)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.PreAuthDigest(key, binding)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	return flow
}

func completionAlterFlow(alter func(*session.PreAuthBinding)) func(*testing.T, *completionFixture) {
	return func(t *testing.T, f *completionFixture) {
		t.Helper()
		spec, err := f.flow.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		alter(&spec.Binding)
		f.flow = completionFlow(t, spec.Binding, f.request.FlowCookie.Token(), f.key)
	}
}

func assertCompletionFailure(t *testing.T, out PreviewEvidence, err error, want CompletionError) {
	t.Helper()
	principal, ok := out.Identity()
	if !errors.Is(err, want) || ok || principal.Subject() != "" || !out.ExpiresAt().IsZero() || out.EnvelopeDigest() != ([32]byte{}) {
		t.Fatalf("failed completion returned evidence or wrong redacted outcome: %v", err)
	}
}
