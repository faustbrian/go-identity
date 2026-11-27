//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	database "github.com/faustbrian/go-postgres"
	"github.com/go-jose/go-jose/v4"
)

const proxyPreviewAuthorityEpoch = uint64(41)

func TestProxyPreviewSharedProviderAuthorityControlsBoundHandoff(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		name := "current_v2_delivers"
		if disabled {
			name = "disabled_and_reenabled_v2_never_delivers"
		}
		t.Run(name, func(t *testing.T) {
			production, preview, request, operator, key := newProxyPreviewProviderAuthorityHandoff(t)
			if !disabled {
				result, err := preview.service.Complete(preview.ctx, request)
				if err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted || result.Session.Replayed {
					t.Fatal("current live-epoch handoff did not commit a fresh preview session", err)
				}
				proxyPreviewSessionDelivery(t, preview, production, request.Handoff.FlowCookie, result)
				proxyPreviewSessionState(t, preview, request.FlowID, true)
				if preview.keys.opens.Load() != 1 {
					t.Fatal("current live-epoch handoff did not open evidence exactly once")
				}
				proxyPreviewProductionHasNoIdentity(t, production)
				return
			}

			disable := ProviderAuthorityChange{
				Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch,
				Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 1, ProfileVersion: production.provider.Version, Enabled: false},
				CommandID: providerAuthorityCommand(t),
			}
			if state, err := operator.Apply(production.ctx, disable); err != nil || state != disable.Next {
				t.Fatal("commit shared provider disable after binding and handoff issuance", state, err)
			}
			assertNoDelivery := func() {
				t.Helper()
				result, err := preview.service.Complete(preview.ctx, request)
				if err == nil || result.Session.CommitOutcome == identity.CommitOutcomeCommitted {
					t.Fatal("invalidated provider handoff reported a committed preview session", err)
				}
				proxyPreviewSessionNoDelivery(t, result)
				proxyPreviewSessionState(t, preview, request.FlowID, false)
				if preview.keys.opens.Load() != 0 {
					t.Fatal("invalidated shared provider authority reached encrypted evidence")
				}
				proxyPreviewProductionHasNoIdentity(t, production)
			}
			assertNoDelivery()

			reenable := ProviderAuthorityChange{
				Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch + 1,
				Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 2, ProfileVersion: production.provider.Version, Enabled: true},
				CommandID: providerAuthorityCommand(t),
			}
			if state, err := operator.Apply(production.ctx, reenable); err != nil || state != reenable.Next {
				t.Fatal("re-enable the same provider profile under a new authority epoch", state, err)
			}
			assertNoDelivery()
		})
	}
}

// Only the provider response is controlled; production and preview retain the
// existing independently migrated native fixtures and their real participants.
func newProxyPreviewProviderAuthorityHandoff(t *testing.T) (proxyStartIntegration, proxyPreviewSessionFixture, ProxyPreviewCallbackRequest, *ProviderAuthorityOperator, ProviderAuthorityKey) {
	t.Helper()
	const callbackURI = "https://production.example/oauth/callback"
	const clientID = "proxy-test-client"
	var calls atomic.Int32
	var signed atomic.Pointer[string]
	var challengeDigest [32]byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := signed.Load()
		if calls.Add(1) != 1 || token == nil || r.Method != http.MethodPost || r.URL.Path != "/token" || r.ParseForm() != nil ||
			r.PostForm.Get("code") != "fixture-code" || r.PostForm.Get("redirect_uri") != callbackURI {
			t.Error("unexpected or repeated provider exchange")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		verifierHash := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if sha256.Sum256([]byte(base64.RawURLEncoding.EncodeToString(verifierHash[:]))) != challengeDigest {
			t.Error("provider exchange changed the native S256 verifier")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": "provider-only-fixture", "id_token": *token, "token_type": "Bearer", "expires_in": 120}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: "oidc-test", Version: 7, Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint: server.URL + "/token", RedirectURI: callbackURI, ClientID: clientID,
		ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid"}, Algorithms: []string{"ES256"},
		KeySet: &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, Clock: clock.System{}, HTTPClient: server.Client(), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	production := newProxyStartIntegration(t, provider)
	preview := newProxyPreviewSessionFixture(t, production.target, provider)
	var productionDB, previewDB string
	if err := production.pool.Raw().QueryRow(production.ctx, `SELECT current_database()`).Scan(&productionDB); err != nil {
		t.Fatal(err)
	}
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT current_database()`).Scan(&previewDB); err != nil || productionDB == previewDB {
		t.Fatal("provider authority test did not retain two independently owned origins", err)
	}

	history, err := (ProviderAuthorityMigrationSource{Schema: production.forward.config.Schema, Version: 42}).Load(production.ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load shared production provider authority", err)
	}
	if _, err := production.pool.Raw().Exec(production.ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install provider authority in the production owner", err)
	}
	readPool, err := database.Connect(production.ctx, database.Config{
		DSN: production.pool.Raw().Config().ConnString(), MaxConns: 2,
		Configure: func(c *database.PoolConfig) error {
			c.ConnConfig.Database = production.pool.Raw().Config().ConnConfig.Database
			return nil
		},
	})
	if err != nil {
		t.Fatal("open independent reader of the production primary", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := readPool.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	authority, err := NewProviderAuthority(readPool, production.forward.config.Schema, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	operatorAuthority, err := NewProviderAuthority(production.pool, production.forward.config.Schema, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := NewProviderAuthorityOperator(operatorAuthority, oneTapStartActor)
	if err != nil {
		t.Fatal(err)
	}
	connection := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: production.provider.ID}
	configure := ProviderAuthorityChange{
		Key: connection, ExpectedVersion: 0,
		Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch, ProfileVersion: production.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(production.ctx, configure); err != nil || state != configure.Next {
		t.Fatal("configure live shared provider authority", state, err)
	}
	production.forward.providerAuthority = authority
	preview.service, err = NewProxyPreviewServiceWithProviderAuthority(preview.completion, preview.config, authority)
	if err != nil {
		t.Fatal("construct live-authority preview on the shared production primary", err)
	}
	flow, cookie := preview.issueBrowser(t, production.request.Remember)
	production.request.TransactionID = flow
	start, err := production.start.Start(production.ctx, production.request)
	if err != nil {
		t.Fatal("native live-authority production initiation", err)
	}
	binding, bound := start.Binding()
	authorization, authorized := start.Authorization()
	if !bound || !authorized || binding.ProviderAuthorityEpoch != proxyPreviewAuthorityEpoch || binding.ProviderVersion != production.provider.Version ||
		binding.ProviderAuthorityEpoch == binding.ProviderVersion || binding.TransactionID != flow {
		t.Fatal("native Start did not retain the independent positive provider authority epoch")
	}
	if err := preview.service.Bind(preview.ctx, ProxyPreviewBindRequest{Binding: binding, FlowCookie: cookie,
		Origin: production.target.Origin, Network: "192.0.2.19", Device: "original-preview-browser"}); err != nil {
		t.Fatal("bind the current v2 handoff before invalidation", err)
	}
	proxyPreviewSessionState(t, preview, flow, false)
	providerURL, err := url.Parse(authorization.URL())
	if err != nil {
		t.Fatal(err)
	}
	params := providerURL.Query()
	challengeDigest = binding.PKCEChallengeDigest
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims, err := json.Marshal(map[string]any{"iss": server.URL, "sub": proxyPreviewTestSubject, "aud": clientID,
		"nonce": params.Get("nonce"), "iat": now.Add(-time.Second).Unix(), "exp": now.Add(time.Minute).Unix()})
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
	query := url.Values{"code": {"fixture-code"}, "state": {params.Get("state")}, "iss": {server.URL}}.Encode()
	forwarded, err := production.callback.Handle(production.ctx, callbackURI, query)
	handoff := forwarded.Envelope()
	t.Cleanup(func() { clear(handoff) })
	if err != nil || forwarded.Destination() != production.target.Redirect || len(handoff) == 0 || calls.Load() != 1 || bytes.Contains(handoff, []byte("provider-only-fixture")) {
		t.Fatal("production did not issue the exact live-epoch tokenless handoff", err)
	}
	if preview.keys.opens.Load() != 0 {
		t.Fatal("binding opened provider evidence before preview completion")
	}
	request := ProxyPreviewCallbackRequest{FlowID: flow,
		Handoff: oauthproxy.PreviewCompletionRequest{Origin: production.target.Origin, FlowCookie: cookie, Envelope: handoff},
		Network: "192.0.2.20", Device: "original-preview-browser"}
	return production, preview, request, operator, connection
}
