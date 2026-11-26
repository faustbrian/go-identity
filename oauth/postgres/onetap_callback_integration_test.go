//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// Only Google's remote signing-key distribution and the existing velocity
// store seam are local fixtures. JWT signature/claim validation, original Start,
// admission, account selection, session effects and one-use custody are real.
// This does not exercise HTTP transport or a live Google service.
func TestOneTapNativeCallbackCommitsLinkedAccountAndTokenlessRecovery(t *testing.T) {
	ctx, pool, start, completion, config, signing := oneTapNativeCallbackFixture(t)
	flow, request := oneTapNativeCallbackRequest(t, ctx, start, signing, "native-callback-success")
	_, foreign := oneTapNativeCallbackRequest(t, ctx, start, signing, "native-callback-foreign")
	wrong := request
	wrong.FlowCookie = foreign.FlowCookie
	denied, err := completion.Callback(ctx, wrong)
	if err == nil {
		t.Fatal("foreign browser cookie completed the original flow")
	}
	oneTapNativeCallbackNoDelivery(t, denied)

	_, original, _, err := start.readOneTapCallbackBrowser(ctx, flow.FlowID, request.FlowCookie, config.FlowKeys)
	if err != nil {
		t.Fatal("read original native browser", err)
	}
	grant, err := start.loadOneTapCallbackGrant(ctx, original)
	if err != nil {
		t.Fatal("read original sealed callback grant", err)
	}
	defer grant.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })

	result, err := completion.Callback(ctx, request)
	if err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted || result.Session.Replayed {
		t.Fatal("native callback did not freshly commit", result.Session.CommitOutcome, err)
	}
	spec, err := result.Session.Session.Bindings()
	remember, rememberErr := spec.Remember.Bindings()
	originalRemember, originalRememberErr := original.Transaction.Binding.Intent.Remember.Bindings()
	if err != nil || spec.TenantID != oneTapStartTenant || spec.UserID != "onetap-user" || spec.Audience != "identity" ||
		spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Subject != "onetap-user" ||
		spec.Authentication.Proof.Method != "oauth" || spec.Authentication.CredentialID != "google-credential" ||
		spec.Authentication.ProofVersion != 7 || rememberErr != nil || originalRememberErr != nil || remember != originalRemember {
		t.Fatal("session did not retain the exact linked Google identity and browser policy", err)
	}
	if result.Session.DeliveryValidUntil.IsZero() || !result.Session.DeliveryValidUntil.After(time.Now()) ||
		result.Session.DeliveryValidUntil.After(flow.ExpiresAt) {
		t.Fatal("fresh callback lost its original bounded delivery deadline")
	}
	bearer, err := result.Session.Token.Reveal()
	if err != nil || len(bearer) != 43 || result.Session.Cookie.Name != "__Host-identity" || result.Session.Cookie.Value != "" ||
		!result.Session.Cookie.HttpOnly || !result.Session.Cookie.Secure || bearer == request.FlowCookie.Token() {
		t.Fatal("fresh callback did not deliver one new opaque session cookie", err)
	}
	parsed, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal("session bearer was not canonical opaque token", err)
	}
	digest, err := parsed.Digest(config.Issuer.LookupKey, string(spec.TenantID))
	if err != nil || digest != spec.Lookup {
		t.Fatal("delivered bearer did not authenticate the committed lookup", err)
	}
	csrf, err := result.CSRF.Reveal()
	if err != nil || len(csrf) != 43 || csrf == bearer {
		t.Fatal("fresh callback did not deliver independent synchronizer state", err)
	}
	csrfToken, err := session.ParseCSRFToken(csrf)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sessionpg.NewRepository(pool, start.config().Session)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := reader.Get(ctx, spec.TenantID, spec.SessionID)
	if err != nil || stored.Revoked || stored.FamilyRevoked || stored.CurrentFamilyVersion != 1 {
		t.Fatal("fresh bearer did not name a committed active session", err)
	}
	storedSpec, err := stored.Session.Bindings()
	if err != nil || storedSpec.UserID != spec.UserID || storedSpec.Lookup != digest || storedSpec.FamilyID != spec.FamilyID ||
		stored.Session.CSRFState().Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, csrfToken, config.CSRF) != nil {
		t.Fatal("stored session lost exact identity, bearer or CSRF binding", err)
	}
	if _, err := result.Session.Token.Reveal(); err == nil {
		t.Fatal("session bearer reveal was reusable")
	}
	if _, err := result.CSRF.Reveal(); err == nil {
		t.Fatal("CSRF reveal was reusable")
	}
	oneTapNativeCallbackState(t, ctx, pool, flow.FlowID, grant.Grant.CapabilityID, result.Session.CommandID, true)

	restarted, err := NewOneTapCompletionService(start, config)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Callback(ctx, request)
	if err == nil && replayed.Session.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("callback retry fabricated a new outcome")
	}
	oneTapNativeCallbackNoDelivery(t, replayed)
	q := identity.RecoveryQuery{CommandID: result.Session.CommandID, TenantID: oneTapStartTenant, ActorID: oneTapStartActor,
		ActorKind: authorization.SubjectServiceAccount, OperationID: oneTapCallbackPurpose, RecordID: string(flow.FlowID), AnonymousFlowID: string(flow.FlowID)}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{
		Subject: authorization.Subject{ID: oneTapStartActor, Kind: authorization.SubjectServiceAccount}, Tenant: oneTapStartTenant,
		Action: oneTapCallbackPurpose, Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow.FlowID)},
	}}
	recovered, err := restarted.RecoverCallback(ctx, q, caller)
	if err != nil || recovered.CommandID != result.Session.CommandID || recovered.CommitOutcome != identity.CommitOutcomeCommitted || !recovered.Replayed {
		t.Fatal("authorized tokenless recovery lost the original commitment", err)
	}
	oneTapNativeCallbackNoDelivery(t, OneTapCallbackResult{Session: recovered})
	q.RecordID, q.AnonymousFlowID = "AAAAAAAAAAAAAAAAAAAAAg", "AAAAAAAAAAAAAAAAAAAAAg"
	if other, err := restarted.RecoverCallback(ctx, q, caller); err == nil || other.CommandID != "" {
		t.Fatal("scope-substituted recovery disclosed the original outcome")
	}
	oneTapNativeCallbackState(t, ctx, pool, flow.FlowID, grant.Grant.CapabilityID, result.Session.CommandID, true)
}

func TestOneTapNativeCallbackRejectsInvalidSignedCredential(t *testing.T) {
	ctx, pool, start, completion, config, signing := oneTapNativeCallbackFixture(t)
	flow, request := oneTapNativeCallbackRequest(t, ctx, start, signing, "native-callback-invalid-signature")
	_, original, _, err := start.readOneTapCallbackBrowser(ctx, flow.FlowID, request.FlowCookie, config.FlowKeys)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := start.loadOneTapCallbackGrant(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	// Keep all strict claims valid but sign with a key absent from the trusted
	// Google key set. A verifier that merely decodes claims must fail this test.
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	request.Callback.Credential.IDToken = oneTapNativeGoogleCredential(t, foreign, flow)
	result, err := completion.Callback(ctx, request)
	if err == nil || result.Session.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("untrusted Google signature issued a session", err)
	}
	oneTapNativeCallbackNoDelivery(t, result)
	oneTapNativeCallbackState(t, ctx, pool, flow.FlowID, grant.Grant.CapabilityID, result.Session.CommandID, false)
}

func TestOneTapNativeCallbackCommitFailureWithholdsBearerAndRollsBack(t *testing.T) {
	ctx, pool, start, completion, config, signing := oneTapNativeCallbackFixture(t)
	flow, request := oneTapNativeCallbackRequest(t, ctx, start, signing, "native-callback-commit-failure")
	_, original, _, err := start.readOneTapCallbackBrowser(ctx, flow.FlowID, request.FlowCookie, config.FlowKeys)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := start.loadOneTapCallbackGrant(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	// The nontransactional sequence proves the actual deferred COMMIT fence
	// was reached, not an unrelated early rejection of the callback.
	if _, err := pool.Raw().Exec(ctx, `CREATE SEQUENCE onetap_sessions.callback_commit_observed;
CREATE FUNCTION onetap_sessions.reject_callback_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
PERFORM nextval('onetap_sessions.callback_commit_observed');
RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='fixture requested callback abort'; END $$;
CREATE CONSTRAINT TRIGGER reject_callback_commit AFTER INSERT ON onetap_sessions.session_issuances
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION onetap_sessions.reject_callback_commit()`); err != nil {
		t.Fatal("install deferred callback fault", err)
	}
	result, err := completion.Callback(ctx, request)
	if err == nil || result.Session.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("failed callback COMMIT was reported committed", err)
	}
	oneTapNativeCallbackNoDelivery(t, result)
	var reached bool
	if err := pool.Raw().QueryRow(ctx, `SELECT is_called FROM onetap_sessions.callback_commit_observed`).Scan(&reached); err != nil || !reached {
		t.Fatal("callback did not reach the deferred COMMIT fence", err)
	}
	oneTapNativeCallbackState(t, ctx, pool, flow.FlowID, grant.Grant.CapabilityID, result.Session.CommandID, false)
}

func oneTapNativeCallbackFixture(t *testing.T) (context.Context, *database.Pool, *OneTapStartService, *OneTapCompletionService, OneTapCompletionConfig, *rsa.PrivateKey) {
	t.Helper()
	ctx, pool, c, _ := oneTapStartIntegrationFixture(t)
	// A valid overall callback budget can exceed the independent MFA reader's
	// limit. The callback must bound that sub-read without rejecting the flow.
	c.MaximumDuration = 10 * time.Second
	accounts := kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 50}, Version: 51}, Version: 52}
	history := kernel.OneTapCallbackPreparationErasureMigrationSource{Base: accounts, Version: 53}
	for _, source := range []migrations.Source{history, mfapg.MigrationSource{Version: 54},
		sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: c.Session.Schema, Version: 30}, Version: 55}, Version: 56},
		sessionpg.CSRFMigrationSource{Schema: c.Session.Schema, Version: 57},
		sessionpg.OneTapCallbackSessionMigrationSource{Schema: c.Session.Schema, Version: 58, ValidationVersion: 59, PreviousConstraint: "session_issuances_purpose_check"}} {
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load native callback history", err)
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
				t.Fatal("install native callback history", step.Name(), err)
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
		t.Fatal("install authorization authority", err)
	}
	seed := `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'onetap-user','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),$1,'identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),$1,'identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES($1,'onetap-user',1,0,decode(repeat('01',16),'hex'),'identity.password.signup');
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,'onetap-user','google-credential',3,'identity/oauth',1,true);
WITH a AS (SELECT 'google'::text AS provider,'https://accounts.google.com'::text AS issuer,'opaque-google-subject'::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT $1,'onetap-user','google-account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a;
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES($1,'onetap-user','google-credential','google-account')`
	for _, statement := range strings.Split(seed, ";") {
		if _, err := pool.Raw().Exec(ctx, statement, oneTapStartTenant); err != nil {
			t.Fatal("seed exact linked account and authoritative empty factors", err)
		}
	}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), policy.AuthorityScope{TenantID: oneTapStartTenant, PolicyNamespace: "users", SubjectID: "onetap-user"}, time.Second); err != nil {
		t.Fatal(err)
	}
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oauth.NewGoogleAccountsProvider(oauth.OIDCConfig{ID: "google", Version: 7, Issuer: "https://accounts.google.com",
		AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth", TokenEndpoint: "https://oauth2.googleapis.com/token", RedirectURI: oneTapStartOrigin + "/google/callback",
		ClientID: "onetap-original-client", ClientSecret: []byte("test-only-client-secret"), ClientAuthentication: oauth.ClientSecretPost,
		Scopes: []string{"openid", "email", "profile"}, Algorithms: []string{"RS256"}, Clock: c.Issuance.Clock, Timeout: time.Second,
		KeySet: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&signing.PublicKey}}})
	if err != nil {
		t.Fatal("configure locally signed Google profile", err)
	}
	t.Cleanup(provider.Close)
	c.Provider = provider
	start, err := NewOneTapStartService(pool, c)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{81}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{82}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	config := OneTapCompletionConfig{ConfigurationID: "onetap-completion-v1", PolicyNamespace: "users", Audience: "identity",
		FlowKeys: map[uint32]session.DigestKey{1: c.Issuance.LookupKey}, CSRF: csrf,
		Issuer: session.IssuerConfig{Clock: c.Issuance.Clock, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}}
	completion, err := NewOneTapCompletionService(start, config)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, start, completion, config, signing
}

func oneTapNativeCallbackRequest(t *testing.T, ctx context.Context, start *OneTapStartService, signing *rsa.PrivateKey, key string) (OneTapBrowserStart, OneTapCallbackRequest) {
	t.Helper()
	_, request := oneTapStartIntegrationRequest(t, key)
	result, err := start.Start(ctx, request)
	flow, delivered := result.Browser()
	if err != nil || !delivered {
		t.Fatal("start original native Google One Tap flow", err)
	}
	wire, err := flow.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return flow, OneTapCallbackRequest{FlowID: flow.FlowID, FlowCookie: auth.NewBearerCredential(wire), Network: netip.MustParseAddr("192.0.2.19"), Device: "trusted-onetap-browser",
		Callback: onetap.Callback{Origin: flow.Origin, CSRFCookies: []string{"gis-double-submit-test-value"}, CSRFBody: []string{"gis-double-submit-test-value"},
			Credential: oauth.GoogleCredential{IDToken: oneTapNativeGoogleCredential(t, signing, flow)}}}
}

func oneTapNativeGoogleCredential(t *testing.T, signing *rsa.PrivateKey, flow OneTapBrowserStart) []byte {
	t.Helper()
	now := time.Now().UTC()
	claims, err := json.Marshal(map[string]any{"iss": "https://accounts.google.com", "sub": "opaque-google-subject", "aud": flow.ClientID,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": flow.Nonce})
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"native-test"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signing, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(message + "." + base64.RawURLEncoding.EncodeToString(signature))
}

func oneTapNativeCallbackNoDelivery(t *testing.T, result OneTapCallbackResult) {
	t.Helper()
	if _, err := result.Session.Token.Reveal(); err == nil {
		t.Fatal("nonfresh callback disclosed a session bearer")
	}
	if _, err := result.CSRF.Reveal(); err == nil {
		t.Fatal("nonfresh callback disclosed CSRF")
	}
	if !reflect.DeepEqual(result.Session.Cookie, http.Cookie{}) || result.Session.Session != (session.Session{}) || !result.Session.DeliveryValidUntil.IsZero() {
		t.Fatal("nonfresh callback exposed session or cookie custody")
	}
}

func oneTapNativeCallbackState(t *testing.T, ctx context.Context, pool *database.Pool, flow identity.PreAuthTransactionID, capability string, command identity.CommandID, committed bool) {
	t.Helper()
	var sessions, families, issuances, uses, audits, lifecycle int
	var flowState, capabilityState string
	var grantErased bool
	flowBytes, err := base64.RawURLEncoding.DecodeString(string(flow))
	if err != nil {
		t.Fatal(err)
	}
	commandBytes, err := base64.RawURLEncoding.DecodeString(string(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM onetap_sessions.sessions),
(SELECT count(*) FROM onetap_sessions.families),
(SELECT count(*) FROM onetap_sessions.session_issuances),
(SELECT state FROM onetap_sessions.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2),
(SELECT proof_ciphertext IS NULL AND erased_at IS NOT NULL FROM onetap_oauth.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$3),
uses,state,
(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$5),
(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$5)
FROM public.capability_identity_one_use WHERE capability_id=$4`, oneTapStartTenant, string(flow), flowBytes, capability, commandBytes).
		Scan(&sessions, &families, &issuances, &flowState, &grantErased, &uses, &capabilityState, &audits, &lifecycle); err != nil {
		t.Fatal("read native callback atomic effects", err)
	}
	if committed {
		if sessions != 1 || families != 1 || issuances != 1 || flowState != "consumed" || !grantErased || uses != 1 || capabilityState != "finalized" || audits != 1 || lifecycle != 1 {
			t.Fatal("callback did not atomically issue once, consume browser/grant, erase proof and bind audit/lifecycle", sessions, families, issuances, flowState, grantErased, uses, capabilityState, audits, lifecycle)
		}
		var erased bool
		if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL FROM identity.commands WHERE command_id=$1`, commandBytes).Scan(&erased); err != nil || !erased {
			t.Fatal("committed callback retained encrypted preparation custody", err)
		}
		return
	}
	if sessions != 0 || families != 0 || issuances != 0 || flowState != "issued" || grantErased || uses != 0 || capabilityState == "finalized" || audits != 0 || lifecycle != 0 {
		t.Fatal("denied callback leaked session/audit/lifecycle effects, consumed browser/grant or erased retry custody", sessions, families, issuances, flowState, grantErased, uses, capabilityState, audits, lifecycle)
	}
}
