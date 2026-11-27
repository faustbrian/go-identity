//go:build integration

package postgres

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/go-jose/go-jose/v4"
)

func TestProxyForwardKnownTLSExchangeCommitsBeforeHandoff(t *testing.T) {
	const callbackURI = "https://production.example/oauth/callback"
	const clientID = "proxy-test-client"
	const verifiedSubject = "controlled-provider-subject"
	var calls atomic.Int32
	var signed atomic.Pointer[string]
	var assertReserved func()
	loopback := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := signed.Load()
		if calls.Add(1) != 1 || token == nil || r.Method != http.MethodPost || r.URL.Path != "/token" || r.ParseForm() != nil ||
			r.PostForm.Get("code") != "fixture-code" || r.PostForm.Get("redirect_uri") != callbackURI ||
			r.PostForm.Get("code_verifier") != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{83}, 32)) {
			t.Error("unexpected or repeated provider call")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assertReserved()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": "provider-only-fixture", "id_token": *token, "token_type": "Bearer", "expires_in": 120}); err != nil {
			t.Error("write fixture response")
		}
	}))
	t.Cleanup(loopback.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: "oidc-test", Version: 7, Issuer: loopback.URL, AuthorizationEndpoint: loopback.URL + "/authorize",
		TokenEndpoint: loopback.URL + "/token", RedirectURI: callbackURI, ClientID: clientID,
		ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid"}, Algorithms: []string{"ES256"},
		KeySet: &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, Clock: clock.System{}, HTTPClient: loopback.Client(), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	f := newProxyForwardIntegration(t, false, provider)
	query := url.Values{"code": {"fixture-code"}, "state": {f.state}, "iss": {loopback.URL}}.Encode()
	callbackID, _ := base64.RawURLEncoding.DecodeString(string(f.locator.CallbackCommand))
	assertReserved = func() {
		var reserved bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT c.state='pending' AND c.preparation_started_generation IS NOT NULL AND
 (SELECT version=1 AND handoff_ciphertext IS NULL FROM onetap_oauth.proxy_transactions) AND
 (SELECT state='reserved' AND uses=0 FROM public.capability_identity_one_use)
 FROM identity.commands c WHERE c.command_id=$1`, callbackID).Scan(&reserved); err != nil || !reserved {
			t.Error("provider called without committed original reservation and generation marker", err)
		}
		// This competing callback runs while the first exchange is waiting for
		// the provider. It cannot disclose or enter the provider a second time.
		competing, err := f.callback.Handle(f.ctx, callbackURI, query)
		if !errors.Is(err, oauthproxy.CallbackReconcile) || competing.Destination() != "" || len(competing.Envelope()) != 0 || calls.Load() != 1 {
			t.Error("competing callback disclosed or repeated provider work", err)
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims, err := json.Marshal(map[string]any{"iss": loopback.URL, "sub": verifiedSubject, "aud": clientID,
		"nonce": f.original.CallbackNonce, "iat": now.Add(-time.Second).Unix(), "exp": now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signature.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	signed.Store(&compact)

	result, err := f.callback.Handle(f.ctx, callbackURI, query)
	handoff := result.Envelope()
	defer clear(handoff)
	if err != nil || result.Destination() != f.original.Evidence.PreviewRedirect || len(handoff) == 0 ||
		calls.Load() != 1 || bytes.Contains(handoff, []byte("provider-only-fixture")) {
		t.Fatal("did not return exactly one committed, tokenless handoff to the selected preview", err)
	}
	crypto, _, _ := proxyBindingFixture(t)
	codec, err := oauth.NewProxyOIDCEvidenceCodec(crypto, clock.System{}, "binding-v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := codec.Open(f.ctx, f.original.Evidence, handoff)
	if err != nil || observed.Subject() != verifiedSubject {
		t.Fatal("preview recipient could not authenticate the original evidence", err)
	}
	var recorded []byte
	var settled, finalized, terminal, noIdentityEffects bool
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT handoff_ciphertext,
 version=2 AND outcome=1 AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL,
 (SELECT state='finalized' AND uses=1 FROM public.capability_identity_one_use),
 (SELECT state='committed' AND preparation_ciphertext IS NULL FROM identity.commands WHERE command_id=$1),
 (SELECT count(*)=1 FROM audit.identity_command_bindings WHERE command_id=$1) AND
 (SELECT count(*)=1 FROM public.identity_outbox_bindings WHERE command_id=$1) AND
 (SELECT count(*)=0 FROM identity.users) AND (SELECT count(*)=0 FROM identity.accounts) AND
 (SELECT count(*)=0 FROM onetap_sessions.sessions)
 FROM onetap_oauth.proxy_transactions`, callbackID).Scan(&recorded, &settled, &finalized, &terminal, &noIdentityEffects)
	defer clear(recorded)
	if err != nil || !bytes.Equal(recorded, handoff) || !settled || !finalized || !terminal || !noIdentityEffects {
		t.Fatal("disclosure did not match exactly one acknowledged native outcome without production identity effects", err, settled, finalized, terminal, noIdentityEffects)
	}
	replay, err := f.callback.Handle(f.ctx, callbackURI, query)
	if !errors.Is(err, oauthproxy.CallbackDenied) || replay.Destination() != "" || len(replay.Envelope()) != 0 || calls.Load() != 1 {
		t.Fatal("replay delivered a retained handoff or repeated provider exchange", err)
	}
}
