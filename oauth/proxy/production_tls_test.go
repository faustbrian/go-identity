package oauthproxy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-identity/oauth"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/go-jose/go-jose/v4"
)

func TestProductionCallbackTLSHandoffRequiresConfirmedDisposalAndSettlement(t *testing.T) {
	testProductionTLSHandoff(t, false)
}

func TestProductionCommandCallbackTLSHandoffRequiresAcknowledgedCommit(t *testing.T) {
	testProductionTLSHandoff(t, true)
}

func testProductionTLSHandoff(t *testing.T, coordinated bool) {
	t.Helper()
	for _, tc := range []struct {
		name                string
		revocationStatus    int
		loseAcknowledgement bool
		want                CallbackDisposition
	}{
		{"confirmed", http.StatusOK, false, CallbackForwarded},
		{"provider disposal unknown", http.StatusServiceUnavailable, false, CallbackNeedsReconciliation},
		{"lost terminal acknowledgement", http.StatusOK, true, CallbackForwarded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newCallbackFixture(t)
			route := fixture.route
			var signed atomic.Value
			var exchanges, revocations atomic.Int32
			var acknowledged atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodPost || req.ParseForm() != nil {
					t.Error("provider did not receive the authorized form POST")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch req.URL.Path {
				case "/token":
					exchanges.Add(1)
					if req.PostForm.Get("code") != "local-code" || req.PostForm.Get("redirect_uri") != route || req.PostForm.Get("code_verifier") == "" {
						t.Error("provider received a different admitted exchange")
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-access", "refresh_token": "test-refresh", "id_token": signed.Load(), "token_type": "Bearer", "expires_in": 120})
				case "/revoke":
					revocations.Add(1)
					if req.PostForm.Get("token") != "test-refresh" {
						t.Error("provider did not receive the original refresh custody")
					}
					acknowledged.Store(tc.revocationStatus == http.StatusOK)
					w.WriteHeader(tc.revocationStatus)
				default:
					t.Error("unexpected provider route")
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(server.Close)
			key := newSigningKey(t)
			signed.Store(testIDToken(t, key, fixture, server.URL))
			provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
				ID: "oidc", Version: 2, Issuer: server.URL, ClientID: "client-a", RedirectURI: route,
				AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token",
				ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid"}, Algorithms: []string{"ES256"},
				KeySet: &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, Clock: fixture.clock, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			exchange, err := oauth.NewOIDCProxyExchange(provider, server.URL+"/revoke")
			if err != nil {
				t.Fatal(err)
			}
			codec := testEvidenceCodec(t, fixture.clock)
			fixture.store.original.Binding.Issuer = server.URL
			fixture.store.checkForward = func() bool { return acknowledged.Load() && exchanges.Load() == 1 && revocations.Load() == 1 }
			if tc.loseAcknowledgement {
				fixture.store.finishErr = errors.New("local simulated lost settlement acknowledgement")
			}
			config := ProductionCallbackConfig{
				ProductionDeployment: "production-a", Provider: exchange, Codec: codec,
				Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
			}
			var callback *ProductionCallback
			if coordinated {
				callback, err = NewProductionCommandCallback(config, callbackCommandFunc(func(ctx context.Context, lookup CallbackLookup, generate CallbackGeneration) error {
					original, err := fixture.store.Reserve(ctx, lookup)
					if err != nil {
						return err
					}
					prepared, err := generate(ctx, original)
					if err != nil {
						fixture.store.terminal = prepared.Disposition() // Observed, not a durably settled disposition.
						return err
					}
					if !prepared.ExpiresAt().Equal(fixture.now.Add(time.Minute)) {
						t.Error("prepared handoff did not retain the original earliest expiry")
					}
					return fixture.store.Finalize(ctx, original.ID, prepared.Disposition(), prepared.Envelope())
				}))
			} else {
				config.Store = fixture.store
				callback, err = NewProductionCallback(config)
			}
			if err != nil {
				t.Fatal(err)
			}
			query := url.Values{"state": {fixture.state}, "code": {"local-code"}, "iss": {server.URL}}.Encode()
			result, err := callback.Handle(t.Context(), route, query)
			if fixture.store.terminal != tc.want || exchanges.Load() != 1 || revocations.Load() != 1 {
				t.Fatal("provider work was repeated or original disposition was not recorded", err)
			}
			if tc.want != CallbackForwarded || tc.loseAcknowledgement {
				if !errors.Is(err, CallbackReconcile) || result.Destination() != "" || len(result.Envelope()) != 0 {
					t.Fatal("uncertainty released a preview handoff", err)
				}
				return
			}
			if err != nil || result.Destination() != fixture.target.Redirect || !bytes.Equal(result.Envelope(), fixture.store.envelope) {
				t.Fatal("acknowledged handoff did not match the registered target and retained envelope", err)
			}
			opened, err := codec.Open(t.Context(), fixture.store.original.Binding, result.Envelope())
			if err != nil || opened.Subject() != "linked-test-subject" || !opened.IDTokenExpiresAt().Equal(fixture.now.Add(time.Minute)) {
				t.Fatal("preview did not receive original verified subject and signed lifetime", err)
			}
			fixture.store.reserveErr = ErrOriginalUnavailable
			replayed, err := callback.Handle(t.Context(), route, query)
			if !errors.Is(err, CallbackDenied) || len(replayed.Envelope()) != 0 || exchanges.Load() != 1 || revocations.Load() != 1 {
				t.Fatal("replay released a new result or repeated provider work", err)
			}
		})
	}
}

func newSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testIDToken(t *testing.T, key *ecdsa.PrivateKey, fixture callbackFixture, issuer string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"iss": issuer, "sub": "linked-test-subject", "aud": "client-a", "nonce": fixture.state,
		"iat": fixture.now.Add(-time.Second).Unix(), "exp": fixture.now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signature.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func testEvidenceCodec(t *testing.T, clock oauth.Clock) *oauth.ProxyOIDCEvidenceCodec {
	t.Helper()
	keys, err := keyring.New(map[string][]byte{"local-test": bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := secretenvelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := oauth.NewProxyOIDCEvidenceCodec(crypto, clock, "local-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}
