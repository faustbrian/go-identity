//go:build integration

package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth/onetap"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

const oneTapRedirectStartEndpoint = oneTapStartOrigin + "/v1/oauth/onetap/redirect"

func oneTapRedirectStartConfig(config OneTapStartConfig) OneTapStartConfig {
	config.Issuance.Cookie = session.CookiePolicy{}
	config.Issuance.CallbackURL = oneTapRedirectStartEndpoint
	return config
}

func oneTapRedirectStartRequest(t *testing.T, key string) (onetap.BrowserStartRequestSpec, onetap.BrowserRedirectStartRequest) {
	t.Helper()
	spec, _ := oneTapStartIntegrationRequest(t, key)
	button, err := onetap.NewOneTapButtonOptions(onetap.OneTapButtonConfig{Type: onetap.ButtonStandard, Theme: onetap.ButtonOutline, Size: onetap.ButtonLarge, Width: 400})
	if err != nil {
		t.Fatal(err)
	}
	spec.Options, err = onetap.NewBrowserRedirectStartOptions(button)
	if err != nil {
		t.Fatal(err)
	}
	request, err := onetap.NewBrowserRedirectStartRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	return spec, request
}

func oneTapRedirectStartNoDelivery(t *testing.T, result OneTapStartResult) {
	t.Helper()
	if _, ok := result.Browser(); ok {
		t.Fatal("redirect result disclosed callback browser material")
	}
	if _, ok := result.RedirectBrowser(); ok {
		t.Fatal("non-fresh redirect result disclosed browser material")
	}
}

func TestOneTapRedirectStartCommitsOriginalAndEncryptedDevice(t *testing.T) {
	ctx, pool, base, counter := oneTapStartIntegrationFixture(t)
	config := oneTapRedirectStartConfig(base)
	owner, err := NewOneTapRedirectStartService(pool, config)
	if err != nil {
		t.Fatal("construct explicitly selected redirect service", err)
	}
	spec, request := oneTapRedirectStartRequest(t, "native-redirect-original")
	first, err := owner.StartRedirect(ctx, request)
	if err != nil || first.Outcome != identity.CommitOutcomeCommitted || first.Replayed {
		t.Fatal("redirect start did not commit", first.Outcome, err)
	}
	if _, ok := first.Browser(); ok {
		t.Fatal("redirect start populated callback browser accessor")
	}
	browser, ok := first.RedirectBrowser()
	if !ok {
		t.Fatal("fresh redirect commit withheld browser custody")
	}
	launch := browser.Projection
	if launch.Experience != onetap.BrowserStartRedirectButton || launch.Button.UXMode != onetap.ButtonRedirect || launch.Button.Width != 400 ||
		launch.LoginURI != config.Issuance.CallbackURL || launch.ClientID != config.Provider.Profile().ClientID || launch.AllowedParentOrigin != spec.Origin ||
		launch.State == "" || launch.Nonce == "" || launch.ExpiresAt.Sub(launch.IssuedAt) != 5*time.Minute {
		t.Fatal("redirect launch lost original Google profile or lifetime")
	}
	policy, err := session.NewOneTapRedirectFrontchannelCookiePolicy(config.Issuance.Origin, config.Issuance.CallbackURL)
	if err != nil {
		t.Fatal(err)
	}
	wantCookie, err := policy.Attributes(browser.Cookie.Expires.Add(-time.Duration(browser.Cookie.MaxAge)*time.Second), launch.ExpiresAt)
	if err != nil || !reflect.DeepEqual(browser.Cookie, wantCookie) || browser.Cookie.Name != "__Secure-identity_frontchannel" || browser.Cookie.Path != "/v1/oauth/onetap/redirect" ||
		browser.Cookie.Value != "" || browser.Cookie.Domain != "" || browser.Cookie.SameSite != http.SameSiteNoneMode || !browser.Cookie.Secure || !browser.Cookie.HttpOnly {
		t.Fatal("fresh redirect did not use exact path-bound frontchannel cookie", err)
	}
	token, err := browser.Token.Reveal()
	if err != nil || token == "" || token == launch.State {
		t.Fatal("fresh redirect did not retain distinct opaque cookie custody", err)
	}
	if _, err := browser.Token.Reveal(); err == nil {
		t.Fatal("redirect token could be revealed twice")
	}
	flowID := identity.PreAuthTransactionID(launch.State)
	original, err := sessionpg.ReadProviderPreAuth(ctx, pool.Raw(), config.Session, config.TenantID, flowID, owner.selected)
	if err != nil {
		t.Fatal("read durable original redirect profile", err)
	}
	bound, err := original.ProviderBindings()
	if err != nil || bound.Provider.Mode != session.PreAuthProviderRedirect || bound.Transaction.Binding.Intent.CallbackURL != config.Issuance.CallbackURL || bound.Transaction.Binding.Intent.Remember != spec.Remember {
		t.Fatal("persisted redirect mode, exact endpoint or Remember changed", err)
	}
	parsed, err := session.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := parsed.ProviderPreAuthDigest(config.Issuance.LookupKey, bound.Transaction.Binding, owner.selected)
	if err != nil || digest != bound.Transaction.Cookie || original.CheckProvider(time.Now().UTC(), bound.Transaction.Binding, owner.selected, digest) != nil {
		t.Fatal("redirect token does not authenticate original persisted cookie binding", err)
	}
	wantLaunch, err := owner.redirectValidator.BrowserRedirectStart(spec.Options, original)
	if err != nil || !reflect.DeepEqual(launch, wantLaunch) {
		t.Fatal("native delivery was not the validator-owned original projection", err)
	}
	flow, _ := base64.RawURLEncoding.DecodeString(launch.State)
	var ciphertext []byte
	var command []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT proof_ciphertext,origin_command_id FROM onetap_oauth.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`, string(config.TenantID), flow).Scan(&ciphertext, &command); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(spec.Device)) || bytes.Contains(ciphertext, []byte(token)) || bytes.Contains(ciphertext, []byte(launch.Nonce)) {
		t.Fatal("callback grant disclosed trusted device or browser secrets in clear")
	}
	binding := identity.CommandBinding{CommandID: first.CommandID, TenantID: config.TenantID, AnonymousFlowID: launch.State, RecordID: launch.State,
		CorrelationID: string(first.CommandID), ActorID: config.Issuance.ActorID, ActorKind: authorization.SubjectServiceAccount,
		OperationID: oneTapStartOperationID, PolicyID: config.Issuance.PolicyID, PolicyVersion: config.Issuance.PolicyVersion,
		SchemaID: kernel.OneTapStartOperation().SchemaID, SchemaVersion: kernel.OneTapStartOperation().SchemaVersion}
	aad, err := owner.callbackAAD(binding, launch.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	var sealed struct {
		Original rpStoredBinding
		Grant    rpStoredGrant
		Proof    []byte
		Device   string `json:",omitempty"`
	}
	if err := owner.openOneTap(ctx, aad, ciphertext, 65536, &sealed); err != nil || sealed.Device != spec.Device || len(sealed.Proof) == 0 {
		t.Fatal("sealed callback grant did not retain original trusted device", err)
	}
	clear(sealed.Proof)
	phase := &oneTapStartPhase{service: owner, request: spec, input: &oneTapStartInput{Binding: rpStoredBinding(binding)}}
	unknownReceipt := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeUnknown,
		Feature: &identity.FeatureReceipt{Operation: kernel.OneTapStartOperation(), AfterVersion: 1}}
	unknown, err := phase.deliver(ctx, OneTapStartResult{CommandID: first.CommandID, Outcome: identity.CommitOutcomeUnknown}, unknownReceipt)
	if err == nil {
		t.Fatal("unknown commitment entered redirect delivery")
	}
	oneTapRedirectStartNoDelivery(t, unknown)
	issued := session.PreAuthIssueResult{Flow: original, Cookie: browser.Cookie, Token: parsed, CommitOutcome: identity.CommitOutcomeCommitted}
	wrongCookie := issued
	wrongCookie.Cookie.Path = "/wrong-path"
	deniedCookie, err := phase.deliverRedirect(OneTapStartResult{}, wrongCookie, bound)
	if err == nil {
		t.Fatal("redirect delivery accepted a substituted cookie path")
	}
	oneTapRedirectStartNoDelivery(t, deniedCookie)
	expiredConfig := config
	expiredConfig.Issuance.Clock = oneTapCallbackGrantClock{now: launch.ExpiresAt}
	expiredOwner, err := NewOneTapRedirectStartService(pool, expiredConfig)
	if err != nil {
		t.Fatal(err)
	}
	expiredPhase := &oneTapStartPhase{service: expiredOwner, request: spec}
	expired, err := expiredPhase.deliverRedirect(OneTapStartResult{}, issued, bound)
	if err == nil {
		t.Fatal("original expiry entered redirect delivery")
	}
	oneTapRedirectStartNoDelivery(t, expired)
	var effects int
	if err := pool.Raw().QueryRow(ctx, `SELECT
	 (SELECT count(*) FROM onetap_sessions.preauth_transactions)+
	 (SELECT count(*) FROM onetap_oauth.onetap_callback_grants)+
	 (SELECT count(*) FROM onetap_sessions.preauth_issuances WHERE command_id=$1)+
	 (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1)+
	 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)+
	 (SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$2)`, command, string(first.CommandID)).Scan(&effects); err != nil || effects != 6 {
		t.Fatal("redirect start did not conserve all atomic owner effects", effects, err)
	}
	charges := counter.calls
	restarted, err := NewOneTapRedirectStartService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.StartRedirect(ctx, request)
	if err != nil || replay.CommandID != first.CommandID || replay.Outcome != first.Outcome || !replay.Replayed || counter.calls != charges {
		t.Fatal("exact redirect retry changed original outcome or charged again", err)
	}
	oneTapRedirectStartNoDelivery(t, replay)
	q := identity.RecoveryQuery{CommandID: first.CommandID, TenantID: config.TenantID, ActorID: config.Issuance.ActorID,
		ActorKind: authorization.SubjectServiceAccount, OperationID: oneTapStartOperationID, RecordID: launch.State, AnonymousFlowID: launch.State}
	recovered, err := restarted.recoverOneTap(ctx, q)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding.CommandID != first.CommandID {
		t.Fatal("redirect recovery lost original receipt", err)
	}
	changed := config
	changed.Issuance.CallbackURL = oneTapStartOrigin + "/other/redirect"
	replacement, err := NewOneTapRedirectStartService(pool, changed)
	if err != nil || replacement.profile == owner.profile {
		t.Fatal("exact endpoint did not bind selected profile", err)
	}
	denied, err := replacement.StartRedirect(ctx, request)
	if err == nil || counter.calls != charges {
		t.Fatal("changed endpoint reused the original keyed intent or charged risk")
	}
	oneTapRedirectStartNoDelivery(t, denied)
}

func TestOneTapRedirectStartRejectsWrongModesAndPreservesPopupFraming(t *testing.T) {
	ctx, pool, config, _ := oneTapStartIntegrationFixture(t)
	popup, err := NewOneTapStartService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := json.Marshal(struct {
		Schema, Configuration, Directory, SessionSchema, RiskConfiguration string
		Tenant, Origin, Actor, Policy                                      string
		PolicyVersion                                                      uint64
		Provider                                                           any
	}{config.Schema, config.ConfigurationID, config.GlobalAuthorityID, config.Session.Schema, config.Risk.ConfigurationID,
		string(config.TenantID), config.Issuance.Origin, string(config.Issuance.ActorID), config.Issuance.PolicyID, config.Issuance.PolicyVersion, config.Provider.Profile()})
	if err != nil || sha256.Sum256(frame) != popup.profile {
		t.Fatal("deployed popup profile fingerprint changed", err)
	}
	legacy := oneTapStoredCallbackGrant{}
	wire, err := json.Marshal(legacy)
	var oldShape struct {
		Original rpStoredBinding
		Grant    rpStoredGrant
		Proof    []byte
	}
	want, wantErr := json.Marshal(oldShape)
	if err != nil || wantErr != nil || !bytes.Equal(wire, want) {
		t.Fatal("empty redirect-only device changed legacy callback plaintext")
	}
	redirectConfig := oneTapRedirectStartConfig(config)
	redirect, err := NewOneTapRedirectStartService(pool, redirectConfig)
	if err != nil {
		t.Fatal(err)
	}
	_, popupRequest := oneTapStartIntegrationRequest(t, "native-redirect-wrong-mode")
	_, redirectRequest := oneTapRedirectStartRequest(t, "native-redirect-wrong-mode")
	wrongPopup, err := redirect.Start(ctx, popupRequest)
	if err == nil {
		t.Fatal("redirect service accepted callback Start")
	}
	oneTapRedirectStartNoDelivery(t, wrongPopup)
	wrongRedirect, err := popup.StartRedirect(ctx, redirectRequest)
	if err == nil {
		t.Fatal("callback service accepted StartRedirect")
	}
	oneTapRedirectStartNoDelivery(t, wrongRedirect)
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
	completionConfig := OneTapCompletionConfig{ConfigurationID: "onetap-completion-v1", PolicyNamespace: "users", Audience: "identity",
		FlowKeys: map[uint32]session.DigestKey{1: config.Issuance.LookupKey}, CSRF: csrf,
		Issuer: session.IssuerConfig{MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}}
	if completion, err := NewOneTapCompletionService(popup, completionConfig); err != nil || completion == nil {
		t.Fatal("otherwise valid callback configuration rejected before mode test", err)
	}
	if completion, err := NewOneTapCompletionService(redirect, completionConfig); err == nil || completion != nil {
		t.Fatal("callback completion constructor accepted redirect start service")
	}
	for _, bad := range []OneTapStartConfig{config, func() OneTapStartConfig { c := redirectConfig; c.Issuance.Cookie = config.Issuance.Cookie; return c }(), func() OneTapStartConfig {
		c := redirectConfig
		c.Issuance.CallbackURL = "https://foreign.test/callback"
		return c
	}()} {
		if service, err := NewOneTapRedirectStartService(pool, bad); err == nil || service != nil {
			t.Fatal("redirect constructor accepted non-exact endpoint or ordinary cookie")
		}
	}
	if service, err := NewOneTapStartService(pool, redirectConfig); err == nil || service != nil {
		t.Fatal("callback constructor accepted redirect configuration")
	}
}

func TestOneTapRedirectStartFailedCommitWithholdsDelivery(t *testing.T) {
	ctx, pool, base, _ := oneTapStartIntegrationFixture(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE SEQUENCE onetap_oauth.redirect_commit_failure;
	 CREATE FUNCTION onetap_oauth.reject_redirect_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
	 PERFORM nextval('onetap_oauth.redirect_commit_failure'); RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='fixture abort'; END $$;
	 CREATE CONSTRAINT TRIGGER reject_redirect_commit AFTER INSERT ON onetap_oauth.onetap_callback_grants
	 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION onetap_oauth.reject_redirect_commit();`); err != nil {
		t.Fatal(err)
	}
	owner, err := NewOneTapRedirectStartService(pool, oneTapRedirectStartConfig(base))
	if err != nil {
		t.Fatal(err)
	}
	_, request := oneTapRedirectStartRequest(t, "native-redirect-failed-commit")
	result, err := owner.StartRedirect(ctx, request)
	if err == nil || result.CommandID == "" || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("failed redirect commit reported success", err)
	}
	oneTapRedirectStartNoDelivery(t, result)
	var fired bool
	var effects int
	if err := pool.Raw().QueryRow(ctx, `SELECT is_called,(SELECT count(*) FROM onetap_sessions.preauth_transactions)+(SELECT count(*) FROM onetap_oauth.onetap_callback_grants) FROM onetap_oauth.redirect_commit_failure`).Scan(&fired, &effects); err != nil || !fired || effects != 0 {
		t.Fatal("failed redirect commit did not roll back staged flow/grant", fired, effects, err)
	}
}
