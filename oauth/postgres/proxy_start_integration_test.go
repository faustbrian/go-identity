//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// Only the deployment's external preview credential check is controlled. The
// preview principal validation, issuance and native participants remain real.
type proxyStartPreviewAuthentication struct{ authenticated authentication.Result }

func (a proxyStartPreviewAuthentication) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Result, error) {
	if err := ctx.Err(); err != nil {
		return authentication.Result{}, err
	}
	bearer, ok := credential.(authentication.BearerCredential)
	if !ok || bearer.Token() != "controlled-preview-credential" {
		return authentication.Result{}, authentication.ErrCredentialsRejected
	}
	return a.authenticated, nil
}

type proxyStartIntegration struct {
	ctx      context.Context
	pool     *database.Pool
	start    *ProxyStartService
	forward  *ProxyForwardService
	callback *oauthproxy.ProductionCallback
	provider oauth.ProviderProfile
	target   oauthproxy.PreviewTarget
	request  oauthproxy.InitiationRequest
}

func newProxyStartIntegration(t *testing.T, providers ...*oauth.OIDCProvider) proxyStartIntegration {
	t.Helper()
	ctx, pool, existing, _ := oneTapStartIntegrationFixture(t)
	provider := existing.Provider
	if len(providers) != 0 {
		provider = providers[0]
	}
	installProxyForwardIntegrationHistory(t, ctx, pool, existing.Schema)
	history, err := (kernel.OAuthProxyStartPreparationErasureMigrationSource{
		Base: kernel.OAuthProxyForwardPreparationErasureMigrationSource{
			Base: kernel.OneTapCallbackPreparationErasureMigrationSource{Base: kernel.MigrationSource{}, Version: 20}, Version: 21,
		}, Version: 22,
	}).Load(ctx)
	if err != nil {
		t.Fatal("load real proxy-start erasure history", err)
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("begin proxy-start owner history", err)
	}
	defer tx.Rollback(ctx)
	for _, migration := range history {
		if migration.Version() <= 21 {
			continue
		}
		if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("install proxy-start owner history", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit proxy-start owner history", err)
	}
	coordinator := existing.Coordinator
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = nil, nil
	forward, err := NewProxyForwardService(pool, ProxyForwardConfig{
		Schema: existing.Schema, ProductionDeployment: "production-a", Actor: oneTapStartActor, PolicyID: oneTapStartPolicy,
		GlobalAuthorityID: existing.GlobalAuthorityID, PolicyVersion: 9, AuditRetention: 1, MaximumDuration: 3 * time.Second,
		Coordinator: coordinator, Capability: existing.Capability, StateKeys: map[uint32][32]byte{3: {82}},
		CurrentEnvelopeKey: "binding-v1", EnvelopeKeys: map[string][]byte{"binding-v1": bytes.Repeat([]byte{1}, 32)},
	})
	if err != nil {
		t.Fatal("public production-forward owner", err)
	}
	target := oauthproxy.PreviewTarget{Deployment: "preview-a", Origin: "https://preview.example", Redirect: "https://preview.example/oauth/complete", Recipient: "preview-identity"}
	principal, err := authentication.NewPrincipal(authentication.PrincipalSpec{
		Subject: oneTapStartActor, Method: "bearer", Issuer: "https://preview-control.example", Audiences: []string{"production-proxy"},
		Scopes: []string{"identity.oauth.proxy-start"}, AuthenticatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal("controlled authenticated preview principal", err)
	}
	authenticated, err := authentication.NewAuthenticatedResult(principal)
	if err != nil {
		t.Fatal("controlled authenticated preview result", err)
	}
	checkpoint := existing.CapabilityPreparation
	checkpoint.Deployment = "production-a"
	start, err := NewProxyStartService(forward, ProxyStartConfig{
		Preview: oauthproxy.PreviewInitiationConfig{TenantID: oneTapStartTenant, ActorID: oneTapStartActor,
			Issuer: "https://preview-control.example", Audience: "production-proxy", Target: target,
			Authentication: proxyStartPreviewAuthentication{authenticated: authenticated}, MaximumDuration: time.Second},
		Provider: provider, ClaimsProfile: "claims-a", ClaimsVersion: 11, CurrentStateKeyVersion: 3,
		StateLifetime: 4 * time.Minute, CapabilityPreparation: checkpoint,
	})
	if err != nil {
		t.Fatal("public native initiation owner", err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.PersistentSession, AbsoluteTTL: 37*time.Hour + time.Nanosecond,
		IdleTTL: 71*time.Minute + 3*time.Nanosecond, RefreshAfter: 13*time.Minute + 5*time.Nanosecond, FreshFor: 29*time.Minute + 7*time.Nanosecond,
	})
	if err != nil {
		t.Fatal("original resolved remember policy", err)
	}
	crypto, _, _ := proxyBindingFixture(t)
	codec, err := oauth.NewProxyOIDCEvidenceCodec(crypto, clock.System{}, "binding-v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := oauth.NewOIDCProxyExchange(provider, "")
	if err != nil {
		t.Fatal(err)
	}
	callback, err := oauthproxy.NewProductionCommandCallback(oauthproxy.ProductionCallbackConfig{
		ProductionDeployment: "production-a", Provider: exchange, Codec: codec, Clock: clock.System{}, Targets: []oauthproxy.PreviewTarget{target},
	}, forward)
	if err != nil {
		t.Fatal("shipped production callback", err)
	}
	return proxyStartIntegration{ctx: ctx, pool: pool, start: start, forward: forward, callback: callback, provider: provider.Profile(), target: target,
		request: oauthproxy.InitiationRequest{Credential: authentication.NewBearerCredential("controlled-preview-credential"), CommandID: command,
			TransactionID: transaction, RequestFingerprint: sha256.Sum256([]byte("original-preview-request")), Remember: remember}}
}

func TestProxyStartCreatesOriginalAndProductionDenialSettlesOnce(t *testing.T) {
	f := newProxyStartIntegration(t)
	var originals, issued, commands int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM onetap_oauth.proxy_transactions),
 (SELECT count(*) FROM public.capability_identity_one_use),
 (SELECT count(*) FROM identity.commands)`).Scan(&originals, &issued, &commands); err != nil || originals != 0 || issued != 0 || commands != 0 {
		t.Fatal("native initiation fixture must not preseed original transactions, grants or commands", err)
	}
	result, err := f.start.Start(f.ctx, f.request)
	if err != nil {
		t.Fatal("fresh native initiation", err)
	}
	authorization, ok := result.Authorization()
	if !ok {
		t.Fatal("acknowledged fresh initiation withheld provider authorization")
	}
	bound, ok := result.Binding()
	if !ok {
		t.Fatal("acknowledged fresh initiation withheld original binding")
	}
	parsed, err := url.Parse(authorization.URL())
	if err != nil {
		t.Fatal("rendered provider authorization", err)
	}
	query := parsed.Query()
	parsed.RawQuery = ""
	if parsed.String() != f.provider.AuthorizationEndpoint || query.Get("redirect_uri") != f.provider.RedirectURI ||
		query.Get("client_id") != f.provider.ClientID || query.Get("response_type") != "code" || query.Get("response_mode") != "query" ||
		query.Get("code_challenge_method") != "S256" || query.Get("scope") != strings.Join(f.provider.Scopes, " ") || len(query) != 9 {
		t.Fatal("native initiation changed the configured provider authorization route or S256 profile")
	}
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(query.Get(name))
		if err != nil || len(decoded) != 32 || len(query[name]) != 1 {
			t.Fatalf("authorization %s is not one canonical 32-byte value", name)
		}
		clear(decoded)
	}
	if bound.TenantID != oneTapStartTenant || bound.TransactionID != f.request.TransactionID || bound.CommandID != f.request.CommandID ||
		bound.RequestFingerprint != f.request.RequestFingerprint || bound.Remember != f.request.Remember ||
		bound.ProductionDeployment != "production-a" || bound.PreviewDeployment != f.target.Deployment || bound.PreviewOrigin != f.target.Origin ||
		bound.PreviewRedirect != f.target.Redirect || bound.Recipient != f.target.Recipient || bound.ProviderID != f.provider.ID ||
		bound.ProviderVersion != f.provider.Version || bound.Issuer != f.provider.Issuer || bound.ClientID != f.provider.ClientID ||
		bound.ClaimsProfile != "claims-a" || bound.ClaimsVersion != 11 || bound.ExpiresAt.Sub(bound.IssuedAt) != 4*time.Minute ||
		bound.StateDigest != sha256.Sum256([]byte(query.Get("state"))) || bound.PKCEChallengeDigest != sha256.Sum256([]byte(query.Get("code_challenge"))) {
		t.Fatal("native initiation changed the original command, preview, remember policy or browser binding")
	}
	selection := proxyLookupSelection{production: "production-a", provider: f.provider.ID, callback: f.provider.RedirectURI,
		providerVersion: f.provider.Version, state: bound.StateDigest}
	row, err := readProxyLookup(f.ctx, f.pool.Raw(), "onetap_oauth", f.forward.config.StateKeys, selection)
	if err != nil {
		t.Fatal("native initiation did not persist production callback custody", err)
	}
	defer row.clear()
	lookup := oauthproxy.CallbackLookup{StateDigest: bound.StateDigest, ProductionDeployment: "production-a", ProductionCallback: f.provider.RedirectURI,
		ProviderID: f.provider.ID, ProviderVersion: f.provider.Version, Issuer: f.provider.Issuer, ClientID: f.provider.ClientID}
	locator, err := row.forwardLocator(lookup)
	if err != nil {
		t.Fatal("native initiation did not allocate an independent callback command", err)
	}
	original, err := openProxyOriginalBinding(f.ctx, f.forward.envelopes, locator, row.binding)
	if err != nil || !reflect.DeepEqual(original.Evidence, bound) || original.CallbackNonce != query.Get("nonce") || locator.OriginCommand != f.request.CommandID || locator.CallbackCommand == f.request.CommandID {
		t.Fatal("stored callback custody does not authenticate the returned original initiation", err)
	}
	verifier, err := openProxyPart(f.ctx, f.forward.envelopes, locator, proxyVerifier, 0, row.verifier, 4096)
	if err != nil {
		t.Fatal("native initiation did not retain usable original PKCE custody", err)
	}
	defer clear(verifier)
	challenge := sha256.Sum256(verifier)
	if base64.RawURLEncoding.EncodeToString(challenge[:]) != query.Get("code_challenge") {
		t.Fatal("stored PKCE verifier does not match the returned S256 challenge")
	}
	originID, _ := base64.RawURLEncoding.DecodeString(string(f.request.CommandID))
	assertOriginalIssued := func() {
		t.Helper()
		var exactOriginal, exactGrant, erasedJournal, noIdentityEffects bool
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*)=1 AND bool_and(version=1 AND origin_command_id=$1 AND callback_command_id<>$1 AND binding_ciphertext=$2 AND state_proof_ciphertext=$3 AND pkce_ciphertext=$4) FROM onetap_oauth.proxy_transactions),
 (SELECT count(*)=1 AND bool_and(tenant_id=$5 AND origin_command_id=$6 AND subject_id=$7 AND purpose='identity.oauth.proxy-forward' AND state='issued' AND uses=0 AND max_uses=1 AND expires_at=$8) FROM public.capability_identity_one_use),
 (SELECT count(*)=1 AND bool_and(state='committed' AND purpose='identity.oauth.proxy-start' AND preparation_started_generation IS NOT NULL AND preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL) FROM identity.commands),
 (SELECT count(*)=1 FROM audit.identity_command_bindings WHERE command_id=$1) AND
 (SELECT count(*)=1 FROM public.identity_outbox_bindings WHERE command_id=$1) AND
 (SELECT count(*)=0 FROM identity.users) AND (SELECT count(*)=0 FROM identity.accounts) AND
 (SELECT count(*)=0 FROM onetap_sessions.sessions)`, originID, row.binding, row.proof, row.verifier,
			string(bound.TenantID), string(f.request.CommandID), string(f.request.TransactionID), bound.ExpiresAt).Scan(
			&exactOriginal, &exactGrant, &erasedJournal, &noIdentityEffects)
		if err != nil || !exactOriginal || !exactGrant || !erasedJournal || !noIdentityEffects {
			t.Fatal("native initiation did not commit one exact original and grant, erase journal custody or conserve zero identity effects", err, exactOriginal, exactGrant, erasedJournal, noIdentityEffects)
		}
	}
	assertOriginalIssued()
	replayed, err := f.start.Start(f.ctx, f.request)
	if authorization, ok := replayed.Authorization(); !errors.Is(err, oauthproxy.InitiationDenied) || ok || authorization.URL() != "" {
		t.Fatal("committed initiation replay did not refuse fresh state, nonce or PKCE authorization", err)
	}
	assertOriginalIssued()

	denial := url.Values{"state": {query.Get("state")}, "error": {"access_denied"}, "iss": {f.provider.Issuer}}.Encode()
	callbackID, _ := base64.RawURLEncoding.DecodeString(string(locator.CallbackCommand))
	for attempt := range 2 {
		result, err := f.callback.Handle(f.ctx, f.provider.RedirectURI, denial)
		if !errors.Is(err, oauthproxy.CallbackDenied) || result.Destination() != "" || len(result.Envelope()) != 0 {
			t.Fatalf("callback attempt %d did not return only an acknowledged denial: %v", attempt, err)
		}
		var settled, finalized, conserved bool
		err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*)=1 AND bool_and(version=2 AND outcome=2 AND handoff_ciphertext IS NULL AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL) FROM onetap_oauth.proxy_transactions),
 (SELECT count(*)=1 AND bool_and(state='finalized' AND uses=1 AND command_id=$2 AND origin_command_id=$3) FROM public.capability_identity_one_use),
 (SELECT count(*)=2 AND bool_and(state='committed' AND preparation_ciphertext IS NULL) FROM identity.commands) AND
 (SELECT count(*)=1 FROM audit.identity_command_bindings WHERE command_id=$1) AND
 (SELECT count(*)=1 FROM public.identity_outbox_bindings WHERE command_id=$1) AND
 (SELECT count(*)=0 FROM identity.users) AND (SELECT count(*)=0 FROM identity.accounts) AND
 (SELECT count(*)=0 FROM onetap_sessions.sessions)`, callbackID, string(locator.CallbackCommand), string(f.request.CommandID)).Scan(&settled, &finalized, &conserved)
		if err != nil || !settled || !finalized || !conserved {
			t.Fatalf("callback attempt %d did not preserve once-only settlement of natively issued original custody: %v", attempt, err)
		}
	}
}
