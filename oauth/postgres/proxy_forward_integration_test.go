//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"testing"
	"time"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

type proxyForwardIntegration struct {
	ctx       context.Context
	pool      *database.Pool
	service   *ProxyForwardService
	callback  *oauthproxy.ProductionCallback
	locator   proxyBindingLocator
	lookup    oauthproxy.CallbackLookup
	state     string
	proofPlan kernel.CapabilityPlan
	original  proxyOriginalBinding
}

func newProxyForwardIntegration(t *testing.T, corruptVerifier bool, providers ...*oauth.OIDCProvider) proxyForwardIntegration {
	t.Helper()
	ctx, pool, start, _ := oneTapStartIntegrationFixture(t)
	provider := start.Provider
	if len(providers) > 1 || len(providers) == 1 && providers[0] == nil {
		t.Fatal("at most one configured test provider is supported")
	}
	if len(providers) == 1 {
		provider = providers[0]
	}
	installProxyForwardIntegrationHistory(t, ctx, pool, start.Schema)

	crypto, locator, original := proxyBindingFixture(t)
	profile := provider.Profile()
	issued := time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	locator.Tenant, locator.Production = oneTapStartTenant, "production-a"
	locator.Provider, locator.ProviderVersion, locator.CallbackURI = profile.ID, profile.Version, profile.RedirectURI
	locator.IssuedAt, locator.ExpiresAt = issued, issued.Add(5*time.Minute)
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{81}, 32))
	stateDigest := sha256.Sum256([]byte(state))
	stateKey := [32]byte{82}
	locator.LookupDigest = proxyLookupDigest(stateKey, locator.StateKeyVersion, locator.Production, locator.Provider, locator.ProviderVersion, stateDigest)
	original.Evidence.TenantID = locator.Tenant
	original.Evidence.ProviderID, original.Evidence.ProviderVersion = profile.ID, profile.Version
	original.Evidence.Issuer, original.Evidence.ClientID = profile.Issuer, profile.ClientID
	original.Evidence.IssuedAt, original.Evidence.ExpiresAt = locator.IssuedAt, locator.ExpiresAt
	original.Evidence.StateDigest = stateDigest
	original.GlobalVersion, original.TenantVersion = 1, 1
	verifierRaw := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{83}, 32)))
	defer clear(verifierRaw)
	verifier, err := oauth.NewPKCEVerifier(verifierRaw)
	if err != nil {
		t.Fatal("original PKCE custody", err)
	}
	original.Evidence.PKCEChallengeDigest = sha256.Sum256([]byte(verifier.Challenge()))
	verifier.Destroy()
	binding, err := sealProxyOriginalBinding(ctx, crypto, "binding-v1", locator, original)
	if err != nil {
		t.Fatal("seal original environment binding", err)
	}
	defer clear(binding)

	command, err := makeProxyForwardCommand(locator, oneTapStartActor, oneTapStartPolicy, 9, binding, corruptVerifier)
	if err != nil {
		t.Fatal("original native callback command", err)
	}
	spec, _ := command.Feature()
	bindingDigest := sha256.Sum256(binding)
	payload := capability.Payload{
		Version: 1, Issuer: start.Capability.Crypto.Issuer, Audiences: []string{start.Capability.Audience},
		Subject: string(locator.Transaction), Resource: string(locator.Transaction), Tenant: string(locator.Tenant),
		Operation: "identity.oauth.proxy-forward", CorrelationID: string(locator.OriginCommand), ID: "original-proxy-state",
		IssuedAt: issued, NotBefore: issued, ExpiresAt: locator.ExpiresAt, MaxUses: 1,
		Caveats: map[string]string{"identity.oauth.proxy.binding": base64.RawURLEncoding.EncodeToString(bindingDigest[:])},
	}
	signer, err := capability.NewService(start.Capability.Crypto)
	if err != nil {
		t.Fatal("actual capability signing service", err)
	}
	proof, _, err := signer.Issue(ctx, payload)
	if err != nil {
		t.Fatal("sign original callback capability", err)
	}
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	issuer, err := capabilitypg.NewIssuer(start.Capability)
	if err != nil {
		t.Fatal("actual capability consumption issuer", err)
	}
	replayVersion := start.Capability.CurrentReplayKeyVersion
	plan, err := issuer.PrepareOAuthProxyForwardConsumption(ctx, spec.Binding, locator.OriginCommand, bindingDigest, proof, replayVersion)
	if err != nil {
		t.Fatal("authenticate original signed callback capability", err)
	}
	var framed []byte
	if err := proof.Transfer(ctx, func(_ context.Context, wire []byte) error {
		framed = make([]byte, 5+len(wire))
		framed[0] = 1
		binary.BigEndian.PutUint32(framed[1:5], replayVersion)
		copy(framed[5:], wire)
		return nil
	}); err != nil {
		t.Fatal("transfer signed original proof to encrypted custody", err)
	}
	defer clear(framed)
	proofWire, err := sealProxyPart(ctx, crypto, "binding-v1", locator, proxyStateProof, 0, framed, proxyStateProofLimit)
	if err != nil {
		t.Fatal("seal original proof framing", err)
	}
	defer clear(proofWire)
	pkceWire, err := sealProxyPart(ctx, crypto, "binding-v1", locator, proxyVerifier, 0, verifierRaw, 4096)
	if err != nil {
		t.Fatal("seal original PKCE custody", err)
	}
	defer clear(pkceWire)
	if corruptVerifier {
		// Provider denial must settle without decrypting browser PKCE custody.
		pkceWire[0] ^= 0xff
	}
	originID, _ := base64.RawURLEncoding.DecodeString(string(locator.OriginCommand))
	callbackID, _ := base64.RawURLEncoding.DecodeString(string(locator.CallbackCommand))
	_, err = pool.Raw().Exec(ctx, `INSERT INTO onetap_oauth.proxy_transactions
(tenant_id,transaction_id,origin_command_id,callback_command_id,production_deployment,provider_id,configuration_version,
 production_callback_uri,state_key_version,state_lookup_digest,binding_ciphertext,state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1)`,
		string(locator.Tenant), string(locator.Transaction), originID, callbackID, locator.Production, locator.Provider,
		locator.ProviderVersion, locator.CallbackURI, locator.StateKeyVersion, locator.LookupDigest[:], binding, proofWire, pkceWire, issued, locator.ExpiresAt)
	if err != nil {
		t.Fatal("seed original encrypted proxy custody", err)
	}
	canonical, err := capability.CanonicalPayload(payload, start.Capability.Crypto.Limits)
	if err != nil {
		t.Fatal("canonical original signed payload", err)
	}
	defer clear(canonical)
	payloadDigest := sha256.Sum256(canonical)
	_, err = pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use
(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,
 origin_command_id,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,1,$10,$11,$11,'onetap-signing',$12,clock_timestamp())`,
		string(locator.Tenant), string(plan.Purpose), plan.ReplayKeyVersion, plan.ReplayDigest[:], plan.CapabilityID,
		plan.ProofFingerprint[:], plan.ExpiresAt, string(locator.OriginCommand), original.Evidence.RequestFingerprint[:],
		string(locator.Transaction), issued, payloadDigest[:])
	if err != nil {
		t.Fatal("seed original capability issuance metadata, not issuance proof", err)
	}
	coordinator := start.Coordinator
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = nil, nil
	service, err := NewProxyForwardService(pool, ProxyForwardConfig{
		Schema: start.Schema, ProductionDeployment: locator.Production, Actor: oneTapStartActor, PolicyID: oneTapStartPolicy,
		GlobalAuthorityID: start.GlobalAuthorityID, PolicyVersion: 9, AuditRetention: 1, MaximumDuration: 3 * time.Second,
		Coordinator: coordinator, Capability: start.Capability, StateKeys: map[uint32][32]byte{locator.StateKeyVersion: stateKey},
		CurrentEnvelopeKey: "binding-v1", EnvelopeKeys: map[string][]byte{"binding-v1": bytes.Repeat([]byte{1}, 32)},
	})
	if err != nil {
		t.Fatal("public native proxy-forward service", err)
	}
	exchange, err := oauth.NewOIDCProxyExchange(provider, "")
	if err != nil {
		t.Fatal("real configured OIDC proxy exchange", err)
	}
	codec, err := oauth.NewProxyOIDCEvidenceCodec(crypto, clock.System{}, "binding-v1", nil)
	if err != nil {
		t.Fatal("real profile envelope codec", err)
	}
	callback, err := oauthproxy.NewProductionCommandCallback(oauthproxy.ProductionCallbackConfig{
		ProductionDeployment: locator.Production, Provider: exchange, Codec: codec, Clock: clock.System{},
		Targets: []oauthproxy.PreviewTarget{{Deployment: original.Evidence.PreviewDeployment, Origin: original.Evidence.PreviewOrigin,
			Redirect: original.Evidence.PreviewRedirect, Recipient: original.Evidence.Recipient}},
	}, service)
	if err != nil {
		t.Fatal("public production command callback", err)
	}
	return proxyForwardIntegration{ctx: ctx, pool: pool, service: service, callback: callback, locator: locator, state: state, proofPlan: plan, original: original,
		lookup: oauthproxy.CallbackLookup{StateDigest: stateDigest, ProductionDeployment: locator.Production, ProductionCallback: locator.CallbackURI,
			ProviderID: profile.ID, ProviderVersion: profile.Version, Issuer: profile.Issuer, ClientID: profile.ClientID}}
}

func installProxyForwardIntegrationHistory(t *testing.T, ctx context.Context, pool *database.Pool, schema string) {
	t.Helper()
	proxyHistory, err := (ProxyTransactionMigrationSource{Schema: schema, Version: 42}).Load(ctx)
	if err != nil {
		t.Fatal("load proxy owner history", err)
	}
	accounts, err := (kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.MigrationSource{}, Version: 18}, Version: 19}).Load(ctx)
	if err != nil {
		t.Fatal("load real account owner history", err)
	}
	erasure, err := (kernel.OAuthProxyForwardPreparationErasureMigrationSource{
		Base: kernel.OneTapCallbackPreparationErasureMigrationSource{Base: kernel.MigrationSource{}, Version: 20}, Version: 21,
	}).Load(ctx)
	if err != nil {
		t.Fatal("load native proxy command erasure history", err)
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("begin proxy fixture history", err)
	}
	defer tx.Rollback(ctx)
	for _, migration := range append(append(accounts, erasure...), proxyHistory...) {
		if migration.Version() <= 9 {
			continue
		}
		if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("install proxy fixture owner history", migration.Name(), err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit proxy fixture owner history", err)
	}
}

func TestProxyForwardProductionDenialCommitsOnceWithoutOpeningPKCE(t *testing.T) {
	f := newProxyForwardIntegration(t, true)
	query := url.Values{"state": {f.state}, "error": {"access_denied"}, "iss": {f.lookup.Issuer}}.Encode()
	for attempt := range 2 {
		result, err := f.callback.Handle(f.ctx, f.locator.CallbackURI, query)
		if !errors.Is(err, oauthproxy.CallbackDenied) || result.Destination() != "" || len(result.Envelope()) != 0 {
			t.Fatalf("attempt %d did not return only acknowledged denial: %v", attempt, err)
		}
		var settled, erased, finalized, committed bool
		var audits, events, commands, grants, users, accounts, sessions int
		callbackID, _ := base64.RawURLEncoding.DecodeString(string(f.locator.CallbackCommand))
		err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT version=2 AND outcome=2 AND handoff_ciphertext IS NULL AND settled_at IS NOT NULL FROM onetap_oauth.proxy_transactions),
 (SELECT state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL FROM onetap_oauth.proxy_transactions),
 (SELECT state='finalized' AND uses=1 AND command_id=$2 AND replay_digest=$3 AND proof_fingerprint=$4 FROM public.capability_identity_one_use),
 (SELECT state='committed' AND preparation_ciphertext IS NULL AND preparation_started_generation IS NOT NULL FROM identity.commands WHERE command_id=$1),
 (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM public.capability_identity_one_use),
 (SELECT count(*) FROM identity.users),
 (SELECT count(*) FROM identity.accounts),
 (SELECT count(*) FROM onetap_sessions.sessions)`, callbackID, string(f.locator.CallbackCommand), f.proofPlan.ReplayDigest[:], f.proofPlan.ProofFingerprint[:]).Scan(
			&settled, &erased, &finalized, &committed, &audits, &events, &commands, &grants, &users, &accounts, &sessions)
		if err != nil || !settled || !erased || !finalized || !committed || audits != 1 || events != 1 || commands != 1 || grants != 1 || users != 0 || accounts != 0 || sessions != 0 {
			t.Fatalf("attempt %d violated atomic denial/replay/no-identity-write contract: settled=%t erased=%t finalized=%t committed=%t audits=%d events=%d commands=%d grants=%d users=%d accounts=%d sessions=%d: %v",
				attempt, settled, erased, finalized, committed, audits, events, commands, grants, users, accounts, sessions, err)
		}
	}
}

func TestProxyForwardUnknownGenerationCannotRunAgain(t *testing.T) {
	f := newProxyForwardIntegration(t, false)
	calls := 0
	generate := func(ctx context.Context, original oauthproxy.OriginalCallback) (oauthproxy.CallbackPrepared, error) {
		calls++
		if original.ID == ([32]byte{}) || original.Binding.StateDigest != f.lookup.StateDigest || original.Verifier.Challenge() == "" || ctx.Err() != nil {
			t.Error("generation did not receive the reserved original callback custody")
		}
		return oauthproxy.CallbackPrepared{}, oauthproxy.CallbackReconcile
	}
	for attempt := range 2 {
		if err := f.service.ExecuteOAuthProxyForward(f.ctx, f.lookup, generate); !errors.Is(err, oauthproxy.CallbackReconcile) {
			t.Fatalf("attempt %d converted unknown generation into a known result: %v", attempt, err)
		}
		var pending, reserved, started bool
		var audits, events, users, accounts, sessions int
		callbackID, _ := base64.RawURLEncoding.DecodeString(string(f.locator.CallbackCommand))
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT version=1 AND outcome IS NULL AND handoff_ciphertext IS NULL FROM onetap_oauth.proxy_transactions),
 (SELECT state='reserved' AND uses=0 AND command_id=$2 FROM public.capability_identity_one_use),
 (SELECT state<>'committed' AND preparation_started_generation IS NOT NULL FROM identity.commands WHERE command_id=$1),
 (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),
 (SELECT count(*) FROM identity.users),
 (SELECT count(*) FROM identity.accounts),
 (SELECT count(*) FROM onetap_sessions.sessions)`, callbackID, string(f.locator.CallbackCommand)).Scan(
			&pending, &reserved, &started, &audits, &events, &users, &accounts, &sessions)
		if err != nil || calls != 1 || !pending || !reserved || !started || audits != 0 || events != 0 || users != 0 || accounts != 0 || sessions != 0 {
			t.Fatalf("attempt %d lost unknown-generation custody or replayed external work: calls=%d pending=%t reserved=%t started=%t audits=%d events=%d users=%d accounts=%d sessions=%d: %v",
				attempt, calls, pending, reserved, started, audits, events, users, accounts, sessions, err)
		}
	}
}
