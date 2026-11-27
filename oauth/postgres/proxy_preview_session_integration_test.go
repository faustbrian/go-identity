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
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/go-jose/go-jose/v4"
)

const proxyPreviewTestSubject = "controlled-provider-subject"

// Only the remote provider, preview credential check and velocity-store seam
// are controlled. Each origin owns an independently migrated PostgreSQL database.
func TestProxyPreviewTwoOriginsIssueOneLinkedAccountSession(t *testing.T) {
	for _, abortCommit := range []bool{false, true} {
		name := "committed"
		if abortCommit {
			name = "commit_rolls_back"
		}
		t.Run(name, func(t *testing.T) {
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
					t.Error("exchange did not use the original native S256 verifier")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{"access_token": "provider-only-fixture", "id_token": *token, "token_type": "Bearer", "expires_in": 120}); err != nil {
					t.Error("write local provider response", err)
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
				t.Fatal("production and preview must own separate databases", err)
			}

			flow, cookie := preview.issueBrowser(t, production.request.Remember)
			production.request.TransactionID = flow
			start, err := production.start.Start(production.ctx, production.request)
			if err != nil {
				t.Fatal("native production initiation", err)
			}
			binding, bound := start.Binding()
			authorization, authorized := start.Authorization()
			if !bound || !authorized || binding.TransactionID != flow || binding.Remember != production.request.Remember {
				t.Fatal("production initiation changed the real preview browser flow")
			}
			bind := ProxyPreviewBindRequest{Binding: binding, FlowCookie: cookie,
				Origin: production.target.Origin, Network: "192.0.2.19", Device: "original-preview-browser"}
			bindAt := time.Now()
			if err := preview.service.Bind(preview.ctx, bind); err != nil {
				t.Fatal("bind native preview custody", err)
			}
			t.Logf("isolated native preview Bind acknowledgement: %s", time.Since(bindAt))
			if err := preview.service.Bind(preview.ctx, bind); err != nil {
				t.Fatal("exact replay did not acknowledge the original preview binding", err)
			}
			changed := bind
			changed.Binding.RequestFingerprint[0] ^= 1
			if err := preview.service.Bind(preview.ctx, changed); err == nil {
				t.Fatal("changed expected binding reused the original command")
			}
			proxyPreviewSessionState(t, preview, flow, false)
			var issued bool
			if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT count(*)=1 AND bool_and(state='issued' AND uses=0) FROM public.capability_identity_one_use`).Scan(&issued); err != nil || !issued {
				t.Fatal("native Bind did not commit exactly one issued preview grant", err)
			}
			if calls.Load() != 0 || preview.keys.opens.Load() != 0 {
				t.Fatal("preview binding exchanged or opened provider evidence")
			}
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
			defer clear(handoff)
			if err != nil || forwarded.Destination() != production.target.Redirect || len(handoff) == 0 || calls.Load() != 1 || bytes.Contains(handoff, []byte("provider-only-fixture")) {
				t.Fatal("production did not return one exact-bound tokenless handoff", err)
			}
			proxyPreviewProductionHasNoIdentity(t, production)

			_, foreignCookie := preview.issueBrowser(t, production.request.Remember)
			request := ProxyPreviewCallbackRequest{FlowID: flow,
				Handoff: oauthproxy.PreviewCompletionRequest{Origin: production.target.Origin, FlowCookie: cookie, Envelope: handoff},
				Network: "192.0.2.20", Device: "original-preview-browser"}
			wrong := request
			wrong.Handoff.FlowCookie = foreignCookie
			denied, err := preview.service.Complete(preview.ctx, wrong)
			if err == nil || preview.keys.opens.Load() != 0 {
				t.Fatal("mismatched browser reached encrypted provider evidence", err)
			}
			proxyPreviewSessionNoDelivery(t, denied)
			proxyPreviewSessionState(t, preview, flow, false)

			if abortCommit {
				if _, err := preview.pool.Raw().Exec(preview.ctx, `CREATE SEQUENCE onetap_sessions.proxy_commit_observed;
CREATE FUNCTION onetap_sessions.reject_proxy_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
PERFORM nextval('onetap_sessions.proxy_commit_observed');
RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='fixture requested preview abort'; END $$;
CREATE CONSTRAINT TRIGGER reject_proxy_commit AFTER INSERT ON onetap_sessions.session_issuances
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION onetap_sessions.reject_proxy_commit()`); err != nil {
					t.Fatal("install deferred preview COMMIT fault", err)
				}
			}
			if abortCommit {
				result, err := preview.service.Complete(preview.ctx, request)
				if preview.keys.opens.Load() != 1 {
					t.Fatal("the original browser did not open the authenticated handoff once")
				}
				if err == nil || result.Session.CommitOutcome == identity.CommitOutcomeCommitted {
					t.Fatal("failed preview COMMIT reported a committed session", err)
				}
				proxyPreviewSessionNoDelivery(t, result)
				var reached bool
				if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT is_called FROM onetap_sessions.proxy_commit_observed`).Scan(&reached); err != nil || !reached {
					t.Fatal("preview did not reach the deferred COMMIT fence", err)
				}
				proxyPreviewSessionState(t, preview, flow, false)
			} else {
				completeAt := time.Now()
				result := raceProxyPreviewCompletion(t, preview, request)
				t.Logf("isolated two concurrent native Complete calls: %s", time.Since(completeAt))
				proxyPreviewSessionDelivery(t, preview, production, cookie, result)
				proxyPreviewSessionState(t, preview, flow, true)
				restarted, err := NewProxyPreviewService(preview.completion, preview.config)
				if err != nil {
					t.Fatal(err)
				}
				replayed, err := restarted.Complete(preview.ctx, request)
				if err == nil && replayed.Session.CommitOutcome != identity.CommitOutcomeCommitted {
					t.Fatal("preview replay fabricated a different outcome")
				}
				proxyPreviewSessionNoDelivery(t, replayed)
				proxyPreviewSessionState(t, preview, flow, true)
			}
			if calls.Load() != 1 {
				t.Fatal("preview completion repeated the production provider exchange")
			}
			proxyPreviewProductionHasNoIdentity(t, production)
		})
	}
}

func raceProxyPreviewCompletion(t *testing.T, f proxyPreviewSessionFixture, request ProxyPreviewCallbackRequest) oauth.SigninCallbackResult {
	t.Helper()
	type completion struct {
		result oauth.SigninCallbackResult
		err    error
	}
	start := make(chan struct{})
	finished := make(chan completion, 2)
	for range 2 {
		go func() {
			<-start
			result, err := f.service.Complete(f.ctx, request)
			finished <- completion{result, err}
		}()
	}
	close(start)
	var winner oauth.SigninCallbackResult
	fresh := 0
	for range 2 {
		attempt := <-finished
		if attempt.err == nil && attempt.result.Session.CommitOutcome == identity.CommitOutcomeCommitted && !attempt.result.Session.Replayed {
			winner = attempt.result
			fresh++
			continue
		}
		proxyPreviewSessionNoDelivery(t, attempt.result)
	}
	if fresh != 1 || f.keys.opens.Load() != 1 {
		t.Fatalf("concurrent completion had %d fresh sessions and %d envelope openings", fresh, f.keys.opens.Load())
	}
	return winner
}

type proxyPreviewObservedKeys struct {
	envelope.KeyProvider
	opens atomic.Int32
}

func (k *proxyPreviewObservedKeys) DecryptDataKey(ctx context.Context, ref string, encrypted []byte, binding envelope.Context) ([]byte, error) {
	k.opens.Add(1)
	return k.KeyProvider.DecryptDataKey(ctx, ref, encrypted, binding)
}

type proxyPreviewSessionFixture struct {
	ctx        context.Context
	pool       *database.Pool
	issuer     *session.PreAuthIssuer
	completion *SigninCompletionService
	service    *ProxyPreviewService
	config     ProxyPreviewConfig
	sessions   sessionpg.Config
	issuance   SigninCompletionConfig
	keys       *proxyPreviewObservedKeys
}

func newProxyPreviewSessionFixture(t *testing.T, target oauthproxy.PreviewTarget, provider *oauth.OIDCProvider) proxyPreviewSessionFixture {
	t.Helper()
	ctx, pool, c, counter := oneTapStartIntegrationFixture(t)
	accounts := kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 50}, Version: 51}, Version: 52}
	for _, source := range []migrations.Source{
		kernel.OneTapCallbackPreparationErasureMigrationSource{Base: accounts, Version: 53}, mfapg.MigrationSource{Version: 54},
		sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: c.Session.Schema, Version: 30}, Version: 55}, Version: 56},
		sessionpg.CSRFMigrationSource{Schema: c.Session.Schema, Version: 57},
		sessionpg.OAuthSigninMigrationSource{Schema: c.Session.Schema, Version: 58, ValidationVersion: 59, PreviousConstraint: "session_issuances_purpose_check"},
		ProxyPreviewBindingMigrationSource{Schema: c.Schema, Version: 61},
	} {
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load real preview owner history", err)
		}
		for _, step := range steps {
			if step.Version() < 50 {
				continue
			}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, step.UpSQL()); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("install preview owner history", step.Name(), err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	authority, err := policy.AuthoritySchemaMigration(60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, authority.Up); err != nil {
		t.Fatal(err)
	}
	seed := `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'preview-user','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),$1,'identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),$1,'identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES($1,'preview-user',1,0,decode(repeat('01',16),'hex'),'identity.password.signup');
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,'preview-user','preview-credential',3,'identity/oauth',1,true)`
	for _, statement := range strings.Split(seed, ";") {
		if _, err := pool.Raw().Exec(ctx, statement, oneTapStartTenant); err != nil {
			t.Fatal("seed preview existing identity and known-empty factors", err)
		}
	}
	profile := provider.Profile()
	if _, err := pool.Raw().Exec(ctx, `WITH a AS (SELECT $2::text AS provider,$3::text AS issuer,$4::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT $1,'preview-user','preview-account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a`,
		oneTapStartTenant, profile.ID, profile.Issuer, proxyPreviewTestSubject); err != nil {
		t.Fatal("seed exact linked provider account", err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES($1,'preview-user','preview-credential','preview-account')`, oneTapStartTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), policy.AuthorityScope{TenantID: oneTapStartTenant, PolicyNamespace: "users", SubjectID: "preview-user"}, time.Second); err != nil {
		t.Fatal(err)
	}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: oneTapStartPolicy, Revision: 9, Evaluator: proxyPreviewApplicationPolicy{}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &query
	flowConfig := c.Issuance
	flowConfig.Action, flowConfig.Origin, flowConfig.CallbackURL = "identity.oauth.callback", target.Origin, target.Redirect
	executor, err := sessionpg.NewPreAuthIssueExecutor(pool, sessionpg.PreAuthIssueExecutorConfig{Repository: c.Session, Coordinator: c.Coordinator,
		Authorization: authorize, Clock: clock.System{}, ActorID: flowConfig.ActorID, Action: flowConfig.Action, Origin: flowConfig.Origin,
		CallbackURL: flowConfig.CallbackURL, PolicyID: flowConfig.PolicyID, PolicyVersion: 9, AuditRetentionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := session.NewPreAuthIssuer(executor, flowConfig)
	if err != nil {
		t.Fatal(err)
	}
	start, err := NewSigninService(pool, SigninServiceConfig{Schema: c.Schema, ConfigurationID: "proxy-preview-native-v1", PolicyID: oneTapStartPolicy,
		Origin: target.Origin, GlobalAuthorityID: c.GlobalAuthorityID, Providers: []oauth.Provider{provider}, CallbackAllowlist: []string{target.Redirect},
		Session: c.Session, FlowKeys: []session.DigestKey{flowConfig.LookupKey}, Risk: proxyPreviewAuthenticationRisk(t, pool, c.Risk, counter),
		Coordinator: c.Coordinator, Capability: c.Capability, CapabilityPreparation: c.CapabilityPreparation, MaximumDuration: c.MaximumDuration,
		StateLifetime: 4 * time.Minute, AuditRetentionPolicyVersion: 1, IntentKey: c.IntentKey, CurrentStateKeyVersion: 3, StateKeys: map[uint32][32]byte{3: {83}},
		CurrentPKCEKeyVersion: 4, PKCECommitmentKeys: map[uint32][32]byte{4: {84}}, CurrentEnvelopeKey: c.CurrentEnvelopeKey, EnvelopeKeys: c.EnvelopeKeys})
	if err != nil {
		t.Fatal("construct real preview signin owner", err)
	}
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{85}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{86}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	issuance := SigninCompletionConfig{ConfigurationID: "proxy-preview-completion-v1", PolicyNamespace: "users", Audience: "identity", CSRF: csrf,
		Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}}
	completion, err := NewSigninCompletionService(start, issuance)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := keyring.New(map[string][]byte{"binding-v1": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	keys := &proxyPreviewObservedKeys{KeyProvider: ring}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := oauth.NewProxyOIDCEvidenceCodec(crypto, clock.System{}, "binding-v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	config := ProxyPreviewConfig{TenantID: oneTapStartTenant, ActorID: oneTapStartActor, ProductionDeployment: "production-a", Target: target, Codec: codec, Clock: clock.System{}}
	service, err := NewProxyPreviewService(completion, config)
	if err != nil {
		t.Fatal("construct native preview handoff owner", err)
	}
	return proxyPreviewSessionFixture{ctx: ctx, pool: pool, issuer: issuer, completion: completion, service: service, config: config, sessions: c.Session, issuance: issuance, keys: keys}
}

func (f proxyPreviewSessionFixture) issueBrowser(t *testing.T, remember session.RememberPolicy) (identity.PreAuthTransactionID, auth.BearerCredential) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.issuer.Prepare(session.PreAuthPrepareInput{CommandID: id, TenantID: oneTapStartTenant, CorrelationID: string(id), Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	browser, err := f.issuer.Issue(f.ctx, prepared)
	if err != nil || browser.CommitOutcome != identity.CommitOutcomeCommitted || browser.Replayed {
		t.Fatal("issue genuine original preview browser", err)
	}
	flow, err := browser.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := browser.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return flow.Binding.ID, auth.NewBearerCredential(wire)
}

type proxyPreviewApplicationPolicy struct{}

func (proxyPreviewApplicationPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	deny := authorization.Decision{Outcome: authorization.Deny}
	if err := ctx.Err(); err != nil {
		return deny, err
	}
	if r.Tenant != oneTapStartTenant || r.Subject.Kind != authorization.SubjectServiceAccount || r.Subject.ID != oneTapStartActor {
		return deny, nil
	}
	if r.Action != "identity.session.preauth-issue" && r.Action != "identity.oauth.signin-start" && r.Action != "identity.oauth.callback" {
		return deny, nil
	}
	if (r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(r.Action)) ||
		(r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != "") {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return deny, nil
}

func proxyPreviewAuthenticationRisk(t *testing.T, pool *database.Pool, original risk.AuthenticationAdmissionCustodyConfig, counter *oneTapStartCounterBoundary) risk.AuthenticationAdmissionCustodyConfig {
	t.Helper()
	p, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, OAuthProviderDiscovery: true,
		Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
			{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
			{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
			{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
			{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{78}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counted, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Store: counter, Clock: time.Now, Timeout: time.Second, Keys: []risk.CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: p, Clock: time.Now, Timeout: 2 * time.Second, Counters: &counted,
		Sources: []risk.Source{{Name: "status", Version: "proxy-preview-test-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(30 * time.Second)}, nil
		}}}, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: oneTapStartPolicy, Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
			_, err := sink.Append(ctx, lost.Record())
			return err
		}}})
	if err != nil {
		t.Fatal(err)
	}
	original.Evaluation = evaluation
	return original
}

func proxyPreviewSessionDelivery(t *testing.T, f proxyPreviewSessionFixture, production proxyStartIntegration, flowCookie auth.BearerCredential, result oauth.SigninCallbackResult) {
	t.Helper()
	linked, ok := result.Outcome.Identity()
	if !ok || linked.Outcome != "signin" || linked.ProviderID != production.provider.ID || linked.ProviderSubject != proxyPreviewTestSubject ||
		linked.UserID != "preview-user" || linked.AccountID != "preview-account" || linked.RememberPolicy != production.request.Remember {
		t.Fatal("handoff did not select the exact existing preview provider account")
	}
	redirect, ok := result.Outcome.RedirectURI()
	if !ok || redirect.String() != production.target.Redirect {
		t.Fatal("preview session changed the original application redirect")
	}
	spec, err := result.Session.Session.Bindings()
	if err != nil || spec.TenantID != oneTapStartTenant || spec.UserID != linked.UserID || spec.Audience != "identity" || spec.Remember != production.request.Remember ||
		spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "oauth" || spec.Authentication.Proof.Subject != "preview-user" ||
		spec.Authentication.CredentialID != "preview-credential" || spec.Authentication.ProofVersion != 7 {
		t.Fatal("preview session changed linked identity or original remember policy", err)
	}
	bearer, err := result.Session.Token.Reveal()
	if err != nil || len(bearer) != 43 || bearer == flowCookie.Token() || result.Session.Cookie.Name != "__Host-identity" || result.Session.Cookie.Value != "" ||
		!result.Session.Cookie.HttpOnly || !result.Session.Cookie.Secure || !result.Session.DeliveryValidUntil.After(time.Now()) {
		t.Fatal("fresh preview session did not deliver one independent opaque cookie", err)
	}
	token, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(f.issuance.Issuer.LookupKey, string(spec.TenantID))
	if err != nil || digest != spec.Lookup {
		t.Fatal("delivered preview bearer does not authenticate the committed session", err)
	}
	csrf, err := result.CSRFToken.Reveal()
	if err != nil || len(csrf) != 43 || csrf == bearer {
		t.Fatal("preview completion did not deliver independent synchronizer state", err)
	}
	csrfToken, err := session.ParseCSRFToken(csrf)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := sessionpg.NewRepository(f.pool, f.sessions)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := repository.Get(f.ctx, spec.TenantID, spec.SessionID)
	if err != nil || stored.Revoked || stored.FamilyRevoked || stored.CurrentFamilyVersion != 1 {
		t.Fatal("preview bearer does not name an active committed session", err)
	}
	if stored.Session.CSRFState().Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, csrfToken, f.issuance.CSRF) != nil {
		t.Fatal("preview CSRF did not authenticate the committed session")
	}
	if _, err := result.Session.Token.Reveal(); err == nil {
		t.Fatal("preview session bearer delivery was reusable")
	}
	if _, err := result.CSRFToken.Reveal(); err == nil {
		t.Fatal("preview CSRF delivery was reusable")
	}
}

func proxyPreviewSessionNoDelivery(t *testing.T, result oauth.SigninCallbackResult) {
	t.Helper()
	if _, err := result.Session.Token.Reveal(); err == nil {
		t.Fatal("nonfresh preview completion disclosed a bearer")
	}
	if _, err := result.CSRFToken.Reveal(); err == nil {
		t.Fatal("nonfresh preview completion disclosed CSRF")
	}
	if !reflect.DeepEqual(result.Session.Cookie, http.Cookie{}) || result.Session.Session != (session.Session{}) || !result.Session.DeliveryValidUntil.IsZero() {
		t.Fatal("nonfresh preview completion exposed session delivery custody")
	}
}

func proxyPreviewSessionState(t *testing.T, f proxyPreviewSessionFixture, flow identity.PreAuthTransactionID, committed bool) {
	t.Helper()
	var sessions, families, issuances, grants, uses, accounts, users, audits, lifecycle int
	var version uint64
	var flowState, grantState string
	var proofErased bool
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
(SELECT count(*) FROM onetap_sessions.sessions),
(SELECT count(*) FROM onetap_sessions.families),
(SELECT count(*) FROM onetap_sessions.session_issuances),
(SELECT state FROM onetap_sessions.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2),
(SELECT count(*) FROM public.capability_identity_one_use),
(SELECT uses FROM public.capability_identity_one_use),
(SELECT state FROM public.capability_identity_one_use),
(SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.accounts),
(SELECT count(*) FROM audit.identity_command_bindings a WHERE a.command_id=b.callback_command_id),
(SELECT count(*) FROM public.identity_outbox_bindings o WHERE o.command_id=b.callback_command_id),
b.version,b.proof_ciphertext IS NULL
FROM onetap_oauth.proxy_preview_bindings b WHERE b.tenant_id=$1 AND b.flow_id=$2`, oneTapStartTenant, string(flow)).
		Scan(&sessions, &families, &issuances, &flowState, &grants, &uses, &grantState, &users, &accounts, &audits, &lifecycle, &version, &proofErased)
	if err != nil {
		t.Fatal("read native preview atomic effects", err)
	}
	if users != 1 || accounts != 1 || grants != 1 {
		t.Fatal("preview created another identity/account or did not issue exactly one grant", users, accounts, grants)
	}
	if committed {
		if sessions != 1 || families != 1 || issuances != 1 || flowState != "consumed" || uses != 1 || grantState != "finalized" || version != 2 || !proofErased || audits != 1 || lifecycle != 1 {
			t.Fatal("preview did not atomically consume one browser/grant and issue one audited session", sessions, families, issuances, flowState, uses, grantState, version, proofErased, audits, lifecycle)
		}
		return
	}
	if sessions != 0 || families != 0 || issuances != 0 || flowState != "issued" || uses != 0 || grantState == "finalized" || version != 1 || proofErased || audits != 0 || lifecycle != 0 {
		t.Fatal("preview rejection or rollback leaked effects or destroyed original custody", sessions, families, issuances, flowState, uses, grantState, version, proofErased, audits, lifecycle)
	}
}

func proxyPreviewProductionHasNoIdentity(t *testing.T, f proxyStartIntegration) {
	t.Helper()
	var users, accounts, sessions int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.accounts),(SELECT count(*) FROM onetap_sessions.sessions)`).Scan(&users, &accounts, &sessions); err != nil || users != 0 || accounts != 0 || sessions != 0 {
		t.Fatal("production proxy wrote identity or session state", err, users, accounts, sessions)
	}
}
