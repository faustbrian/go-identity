//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/jackc/pgx/v5"
)

func TestNativeSocialSigninStartOriginalBrowserAndReplay(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCNativeStart: "original"}, true)
}

func TestNativeSocialSigninStartDeniesDisabledTenant(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCNativeStart: "disabled-tenant"}, true)
}

func TestNativeSocialSigninStartReplayDeniesLaterTenantSuspension(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCNativeStart: "revoked-replay"}, true)
}

func TestNativeSocialSigninStartReplayRetainsOriginalDirectoryEpochs(t *testing.T) {
	for _, mode := range []string{"tenant-epoch-replay", "global-epoch-replay"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCNativeStart: mode}, true)
		})
	}
}

func TestNativeSocialSigninCallbackOriginalBrowserAttribution(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCNativeStart: "callback"}, true)
}

func TestNativeSocialSigninExistingAccountSession(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCNativeSignin: true}, true)
}

func TestNativeSocialSigninProviderDenial(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCNativeSignin: true, socialOIDCNativeMode: "denial"}, true)
}

func TestNativeSocialSigninConcurrentCallback(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCNativeSignin: true, socialOIDCNativeMode: "concurrent"}, true)
}

func TestNativeSocialSigninUnknownExchangeDoesNotRetry(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCNativeSignin: true, socialOIDCNativeMode: "unknown-exchange"}, true)
}

type nativeSigninCompletionFixture struct {
	provider *referenceSocialOIDCIssuer
	user     identity.UserID
	mode     string
}

// Reuse the operational graph's real migrations and configured native owners.
// The direct consumer below supplies configuration, not stores or workflow
// substitutes. Initiation has no local user and performs no provider exchange.
func proveNativeSocialSigninStart(t *testing.T, ctx context.Context, c reference.StoreConfiguration, d reference.ReferenceDependencies, origin, mode string) {
	proveNativeSocialSignin(t, ctx, c, d, origin, mode, nil)
}

func proveNativeSocialSignin(t *testing.T, ctx context.Context, c reference.StoreConfiguration, d reference.ReferenceDependencies, origin, mode string, completion *nativeSigninCompletionFixture) {
	t.Helper()
	if c.DurableAdmission == nil || c.SocialOAuth == nil {
		t.Fatal("actual durable risk and RP graph required")
	}
	n := c.SocialOAuth
	pc := registrationRiskPolicyConfig(3, false)
	for i, operation := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.oauth-server.client-create", "identity.session.get"} {
		admitted, err := c.DurableAdmission.Policy.Admit(operation)
		if err != nil {
			t.Fatal("actual risk profile unavailable", err)
		}
		pc.Profiles[i] = admitted.Profile
		pc.Version = admitted.PolicyVersion
	}
	pc.OAuthProviderDiscovery = true
	policy, err := risk.NewPolicy(pc)
	if err != nil {
		t.Fatal("OAuth admission policy", err)
	}
	a := c.DurableAdmission
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: d.PostgreSQL, Schema: a.Schema, Namespace: a.Namespace, Policy: policy, Keys: a.Keys, ReplayKey: a.ReplayKey, Tenants: a.Tenants, MaximumRecords: a.MaximumRecords, Timeout: a.Timeout})
	if err != nil {
		t.Fatal("native durable OAuth counters", err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: a.Keys, Store: store, Clock: time.Now, Timeout: c.OTP.RiskTimeout})
	if err != nil {
		t.Fatal("counted OAuth coordinator", err)
	}
	sink, err := auditpg.New(d.PostgreSQL.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("native audit sink", err)
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Counters: &counters, Clock: time.Now, Timeout: c.OTP.RiskTimeout, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: c.OTP.RiskPolicyID, Timeout: c.OTP.AuditTimeout, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
		_, err := sink.Append(ctx, lost.Record())
		return err
	}}})
	if err != nil {
		t.Fatal("audited OAuth evaluator", err)
	}
	p := *c.PasswordSignup.PreAuth
	flowConfig := session.PreAuthIssuerConfig{ActorID: p.ActorID, Action: "identity.oauth.callback", Origin: origin, CallbackURL: n.CallbackAllowlist[0], PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, Clock: clock.System{}, MaximumDuration: c.PasswordSignup.Native.Session.MaximumDuration, FlowTTL: p.FlowTTL, LookupKey: c.PasswordSignup.Native.FlowKeys[p.FlowKeyIndex], TokenSize: p.TokenSize, Cookie: p.Cookie}
	executor, err := sessionpg.NewPreAuthIssueExecutor(d.PostgreSQL, sessionpg.PreAuthIssueExecutorConfig{Repository: c.PasswordSignup.Native.Session, Coordinator: n.Coordinator, Authorization: n.Coordinator.AdmissionPolicy.Authorization, Clock: clock.System{}, ActorID: flowConfig.ActorID, Action: flowConfig.Action, Origin: origin, CallbackURL: flowConfig.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, AuditRetentionVersion: 1})
	if err != nil {
		t.Fatal("native original browser executor", err)
	}
	issuer, err := session.NewPreAuthIssuer(executor, flowConfig)
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.Prepare(session.PreAuthPrepareInput{CommandID: id, TenantID: otpTenant, CorrelationID: string(id), Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	browser, err := issuer.Issue(ctx, prepared)
	if err != nil || browser.CommitOutcome != identity.CommitOutcomeCommitted || browser.Replayed {
		t.Fatal("real original browser did not commit", err)
	}
	flow, err := browser.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := browser.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("native-social-original"))
	if err != nil {
		t.Fatal(err)
	}
	callback, err := oauth.NewValidatedCallbackURL(n.CallbackAllowlist[0], n.CallbackAllowlist)
	if err != nil {
		t.Fatal(err)
	}
	failure, err := oauth.NewValidatedCallbackURL(n.CallbackAllowlist[1], n.CallbackAllowlist)
	if err != nil {
		t.Fatal(err)
	}
	profile := n.Providers[0].Profile()
	scopes, err := oauth.NewScopeSet(profile.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	config := oauthpg.SigninServiceConfig{Schema: n.Schema, ConfigurationID: n.ConfigurationID, GlobalAuthorityID: c.OTP.Store.GlobalAuthorityID, PolicyID: n.PolicyID, Origin: origin, Providers: n.Providers, CallbackAllowlist: n.CallbackAllowlist, Session: c.PasswordSignup.Native.Session, FlowKeys: c.PasswordSignup.Native.FlowKeys, Risk: risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "reference-social-authentication-v1", Keys: c.OTP.RiskKeys}, Coordinator: n.Coordinator, Capability: n.Issuer, CapabilityPreparation: c.PasswordSignup.Preparation, MaximumDuration: n.MaximumDuration, StateLifetime: n.StateLifetime, AuditRetentionPolicyVersion: 1, IntentKey: n.IntentKey, CurrentStateKeyVersion: n.CurrentStateKeyVersion, StateKeys: n.StateKeys, CurrentPKCEKeyVersion: n.CurrentPKCEKeyVersion, PKCECommitmentKeys: n.PKCECommitmentKeys, CurrentEnvelopeKey: n.CurrentEnvelopeKey, EnvelopeKeys: n.EnvelopeKeys}
	owner, err := oauthpg.NewSigninService(d.PostgreSQL, config)
	if err != nil {
		t.Fatal("native signin construction", err)
	}
	r := oauth.SigninStartRequest{TenantID: otpTenant, Provider: oauth.ProviderID(profile.ID), Callback: callback, ErrorCallback: failure, Scopes: scopes, SignupDisabled: true, IdempotencyKey: key, FlowID: flow.Binding.ID, FlowCookie: auth.NewBearerCredential(wire), Remember: remember, Origin: origin, Network: "192.0.2.19", Device: "native-social-trusted-browser", Caller: authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(flowConfig.ActorID)}, Action: "identity.oauth.signin-start", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow.Binding.ID)}}}}
	if mode == "disabled-tenant" {
		if _, err := d.PostgreSQL.Raw().Exec(ctx, `UPDATE identity.tenant_authorities SET enabled=false,version=version+1 WHERE tenant_id=$1`, otpTenant); err != nil {
			t.Fatal(err)
		}
		result, err := owner.SigninStart(ctx, r)
		if err == nil || result.TransactionID != "" {
			t.Fatal("disabled tenant issued OAuth state", err)
		}
		var rows int
		if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_social.transactions WHERE operation='identity.oauth.signin-start'`).Scan(&rows); err != nil || rows != 0 {
			t.Fatal("disabled tenant persisted provider state", err)
		}
		return
	}
	first, err := owner.SigninStart(ctx, r)
	if err != nil || first.TransactionID == "" || first.RedirectURI.Query().Get("state") == "" || first.ExpiresAt.After(flow.Binding.ExpiresAt) {
		t.Fatal("native initiation did not commit original authorization state", err)
	}
	secondOwner, err := oauthpg.NewSigninService(d.PostgreSQL, config)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := secondOwner.SigninStart(ctx, r)
	if err != nil || replayed.TransactionID != first.TransactionID || replayed.RedirectURI.String() != first.RedirectURI.String() || !replayed.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("restart renewed or replaced original authorization state", err)
	}
	changed := r
	changed.Device = "another-browser"
	var conflict identity.ConflictError
	if _, err := secondOwner.SigninStart(ctx, changed); !errors.As(err, &conflict) {
		t.Fatal("same key adopted another original browser-device", err)
	}
	if completion != nil {
		proveNativeSocialSessionCompletion(t, ctx, c, d, owner, r, first, completion)
		return
	}
	if mode == "callback" {
		for _, response := range []string{"code", "error"} {
			values := url.Values{"state": {first.RedirectURI.Query().Get("state")}, "iss": {profile.Issuer}}
			if response == "code" {
				values.Set("code", "not-exchanged-by-attribution")
			} else {
				values.Set("error", "access_denied")
			}
			parsed, err := oauth.ParseQueryCallback(ctx, values.Encode(), profile)
			if err != nil {
				t.Fatal(err)
			}
			defer parsed.Destroy()
			request := oauth.SigninCallbackRequest{Callback: parsed, TenantID: otpTenant, FlowCookie: r.FlowCookie, Origin: r.Origin, Network: r.Network, Device: r.Device}
			attribution, err := secondOwner.SigninCallbackRateSource(ctx, request)
			if err != nil || attribution.TransactionID != first.TransactionID || attribution.ProviderID != profile.ID || attribution.Lifetime <= 0 {
				t.Fatal("native callback lost original browser/state attribution", err)
			}
			for _, change := range []func(*oauth.SigninCallbackRequest){
				func(r *oauth.SigninCallbackRequest) {
					r.FlowCookie = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")
				},
				func(r *oauth.SigninCallbackRequest) { r.Device = "another-browser" },
				func(r *oauth.SigninCallbackRequest) { r.TenantID = "other-tenant" },
			} {
				other := request
				change(&other)
				if got, err := secondOwner.SigninCallbackRateSource(ctx, other); err == nil || got.TransactionID != "" {
					t.Fatal("callback attributed foreign browser/tenant", err)
				}
			}
		}
		var intact bool
		if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT version=1 AND secrets_erased_at IS NULL AND pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL FROM identity_social.transactions WHERE transaction_id=$1`, first.TransactionID).Scan(&intact); err != nil || !intact {
			t.Fatal("rate attribution consumed or erased original exchange custody", err)
		}
	}
	var authorityChange string
	var authorityID any
	switch mode {
	case "revoked-replay":
		authorityChange = `UPDATE identity.tenant_authorities SET enabled=false,version=version+1 WHERE tenant_id=$1`
		authorityID = otpTenant
	case "tenant-epoch-replay":
		authorityChange = `UPDATE identity.tenant_authorities SET version=version+1 WHERE tenant_id=$1`
		authorityID = otpTenant
	case "global-epoch-replay":
		authorityChange = `UPDATE identity.global_authorities SET version=version+1 WHERE authority_id=$1`
		authorityID = config.GlobalAuthorityID
	}
	if authorityChange != "" {
		if _, err := d.PostgreSQL.Raw().Exec(ctx, authorityChange, authorityID); err != nil {
			t.Fatal(err)
		}
		result, err := secondOwner.SigninStart(ctx, r)
		if err == nil || result.TransactionID != "" {
			t.Fatal("committed replay bypassed changed directory authority", err)
		}
	}
	var rows, users, sessions int
	if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_social.transactions WHERE operation='identity.oauth.signin-start' AND user_id IS NULL AND session_id IS NULL AND preauth_id=$1),(SELECT count(*) FROM identity.users),(SELECT count(*) FROM `+pgx.Identifier{c.Session.Native.Execution.Repository.Schema}.Sanitize()+`.sessions)`, string(flow.Binding.ID)).Scan(&rows, &users, &sessions); err != nil || rows != 1 || users != 0 || sessions != 0 {
		t.Fatal("initiation duplicated state or selected a local identity/session", rows, users, sessions, err)
	}
}

func proveNativeSocialSessionCompletion(t *testing.T, ctx context.Context, c reference.StoreConfiguration, d reference.ReferenceDependencies, owner *oauthpg.SigninService, r oauth.SigninStartRequest, start oauth.SigninStartResult, f *nativeSigninCompletionFixture) {
	t.Helper()
	// Install the public forward-only session purpose expansion after genuine
	// populated password/link history; no user, credential or session is seeded.
	schema := c.Session.Native.Execution.Repository.Schema
	var previous string
	if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT conname FROM pg_constraint WHERE conrelid=$1::regclass AND contype='c' AND conname LIKE 'session_issuances_purpose%'`, schema+".session_issuances").Scan(&previous); err != nil {
		t.Fatal(err)
	}
	steps, err := (sessionpg.OAuthSigninMigrationSource{Schema: schema, Version: 101, ValidationVersion: 102, PreviousConstraint: previous}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		if _, err := d.PostgreSQL.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal("native OAuth session expansion", err)
		}
	}
	n := c.PasswordSignin.Native
	service, err := oauthpg.NewSigninCompletionService(owner, oauthpg.SigninCompletionConfig{ConfigurationID: "reference-social-signin-v1", PolicyNamespace: n.Profile.PolicyNamespace, Audience: n.Profile.Audience, Issuer: n.Issuance, CSRF: n.CSRFKey})
	if err != nil {
		t.Fatal("native signin completion construction", err)
	}
	provider := *f.provider.server.Client()
	if f.mode == "denial" {
		f.provider.denyAuthorization.Store(true)
	}
	provider.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, start.RedirectURI.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatal("provider authorization did not return original code", response.StatusCode)
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := oauth.ParseQueryCallback(ctx, location.RawQuery, c.SocialOAuth.Providers[0].Profile())
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	before := f.provider.exchanges.Load()
	callbackRequest := oauth.SigninCallbackRequest{Callback: parsed, TenantID: r.TenantID, FlowCookie: r.FlowCookie, Origin: r.Origin, Network: r.Network, Device: r.Device}
	var result oauth.SigninCallbackResult
	if f.mode == "concurrent" {
		gate := &referenceSocialExchangeGate{entered: make(chan struct{}), release: make(chan struct{})}
		var once sync.Once
		unblock := func() { once.Do(func() { close(gate.release) }) }
		f.provider.gate.Store(gate)
		t.Cleanup(func() { unblock(); f.provider.gate.Store(nil) })
		type callbackResult struct {
			result oauth.SigninCallbackResult
			err    error
		}
		finished := make(chan callbackResult, 1)
		go func() { out, e := service.Callback(ctx, callbackRequest); finished <- callbackResult{out, e} }()
		select {
		case <-gate.entered:
		case <-ctx.Done():
			unblock()
			<-finished
			t.Fatal("provider exchange never entered", ctx.Err())
		}
		otherParsed, e := oauth.ParseQueryCallback(ctx, location.RawQuery, c.SocialOAuth.Providers[0].Profile())
		if e != nil {
			unblock()
			<-finished
			t.Fatal(e)
		}
		defer otherParsed.Destroy()
		other := callbackRequest
		other.Callback = otherParsed
		competing, e := service.Callback(ctx, other)
		if e != nil || competing.Session.CommitOutcome != identity.CommitOutcomeInProgress || competing.Session.Token != (session.Token{}) || f.provider.exchanges.Load() != before+1 {
			unblock()
			<-finished
			t.Fatal("competing callback exchanged or delivered another session", e)
		}
		unblock()
		completed := <-finished
		f.provider.gate.Store(nil)
		result, err = completed.result, completed.err
	} else {
		if f.mode == "unknown-exchange" {
			f.provider.failExchange.Store(true)
		}
		result, err = service.Callback(ctx, callbackRequest)
	}
	if f.mode == "unknown-exchange" {
		if err == nil || result.Session.Token != (session.Token{}) || f.provider.exchanges.Load() != before+1 {
			t.Fatal("uncertain provider outcome issued access", err)
		}
		retry, e := service.Callback(ctx, callbackRequest)
		if e != nil || retry.Session.CommitOutcome != identity.CommitOutcomeInProgress || retry.Session.Token != (session.Token{}) || f.provider.exchanges.Load() != before+1 {
			t.Fatal("unknown provider exchange retried original code", e)
		}
		if result.Session.CommandID == "" || retry.Session.CommandID != result.Session.CommandID {
			t.Fatal("unknown exchange lost stable recovery identity")
		}
		query := identity.RecoveryQuery{CommandID: result.Session.CommandID, TenantID: r.TenantID, AnonymousFlowID: string(r.FlowID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.oauth.callback"}
		caller := r.Caller.Clone()
		caller.Request.Action = "identity.oauth.callback"
		recovered, e := service.RecoverCallback(ctx, query, caller)
		if e != nil || recovered.CommandID != query.CommandID || recovered.CommitOutcome != identity.CommitOutcomeInProgress || recovered.Token != (session.Token{}) || recovered.Session != (session.Session{}) || f.provider.exchanges.Load() != before+1 {
			t.Fatal("unknown exchange recovery invented commit/access", e)
		}
		// Expire only this owned test command's lease. Expiry cannot prove that
		// the provider did not consume its code or authorize another exchange.
		raw, e := base64.RawURLEncoding.Strict().DecodeString(string(query.CommandID))
		if e != nil {
			t.Fatal(e)
		}
		changed, e := d.PostgreSQL.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1 AND state='pending'`, raw)
		if e != nil || changed.RowsAffected() != 1 {
			t.Fatal("uncertain callback lease control did not reach original command", e)
		}
		recovered, e = service.RecoverCallback(ctx, query, caller)
		if e != nil || recovered.CommandID != query.CommandID || recovered.CommitOutcome != identity.CommitOutcomeInProgress || recovered.Token != (session.Token{}) || recovered.Session != (session.Session{}) || f.provider.exchanges.Load() != before+1 {
			t.Fatal("expired uncertain exchange was reconstructed or released", e)
		}
		return
	}
	if f.mode == "denial" {
		if err != nil || !result.Outcome.Denied() || result.Session.Token != (session.Token{}) || f.provider.exchanges.Load() != before {
			t.Fatal("provider denial did not terminalize without exchange/session", err)
		}
		repeated, err := service.Callback(ctx, callbackRequest)
		if err != nil || !repeated.Outcome.Denied() || f.provider.exchanges.Load() != before {
			t.Fatal("provider denial retry lost terminal outcome", err)
		}
		var erased bool
		if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT version=2 AND secrets_erased_at IS NOT NULL AND pkce_ciphertext IS NULL AND state_proof_ciphertext IS NULL FROM identity_social.transactions WHERE transaction_id=$1`, start.TransactionID).Scan(&erased); err != nil || !erased {
			t.Fatal("provider denial retained exchange custody", err)
		}
		return
	}
	if err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted || result.Session.Replayed || result.Session.Token == (session.Token{}) || result.CSRFToken == (session.CSRFToken{}) {
		var committed int
		if queryErr := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{schema}.Sanitize()+`.session_issuances WHERE purpose='identity.oauth.callback'`).Scan(&committed); queryErr != nil {
			t.Fatal("callback failure observation", queryErr)
		}
		t.Fatal("provider callback did not issue original committed session", "provider attempts", f.provider.exchanges.Load()-before, "committed sessions", committed, err)
	}
	identityResult, ok := result.Outcome.Identity()
	if !ok || identityResult.UserID != f.user || identityResult.Outcome != "signin" || f.provider.exchanges.Load() != before+1 {
		t.Fatal("signin did not select genuine linked account exactly once")
	}
	spec, err := result.Session.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	if spec.UserID != f.user || spec.Authentication.Proof.Method != "oauth" || spec.Authentication.CredentialID == "" {
		t.Fatal("provider signin fabricated password-session provenance")
	}
	replayed, err := service.Callback(ctx, callbackRequest)
	if err != nil || !replayed.Session.Replayed || replayed.Session.Token != (session.Token{}) || replayed.CSRFToken != (session.CSRFToken{}) || f.provider.exchanges.Load() != before+1 {
		t.Fatal("committed callback retry lost original outcome or redisclosed/re-exchanged", err)
	}
	replayedIdentity, ok := replayed.Outcome.Identity()
	if !ok || replayedIdentity != identityResult {
		t.Fatal("callback retry replaced original selected identity")
	}
	query := identity.RecoveryQuery{CommandID: result.Session.CommandID, TenantID: r.TenantID, AnonymousFlowID: string(r.FlowID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.oauth.callback"}
	caller := r.Caller.Clone()
	caller.Request.Action = "identity.oauth.callback"
	recovered, err := service.RecoverCallback(ctx, query, caller)
	if err != nil || recovered.CommitOutcome != identity.CommitOutcomeCommitted || recovered.Token != (session.Token{}) || recovered.Session != (session.Session{}) {
		t.Fatal("proof-free recovery did not retain tokenless historical receipt", err)
	}
	for _, dimension := range []string{"flow", "tenant", "actor", "operation", "caller"} {
		foreign, foreignCaller := query, caller.Clone()
		switch dimension {
		case "flow":
			foreign.AnonymousFlowID = "other-flow"
		case "tenant":
			foreign.TenantID = "other-tenant"
		case "actor":
			foreign.ActorID = "other-service"
		case "operation":
			foreign.OperationID = "identity.oauth.signin-start"
		case "caller":
			foreignCaller.Request.Subject.ID = "other-service"
		}
		if denied, e := service.RecoverCallback(ctx, foreign, foreignCaller); e == nil || denied.CommandID != "" || denied.CommitOutcome != identity.CommitOutcomeInvalid || denied.Token != (session.Token{}) || denied.Session != (session.Session{}) {
			t.Fatal("foreign recovery scope disclosed original receipt", dimension, e)
		}
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: c.OTP.Store.GlobalAuthorityID, PolicyNamespace: n.Profile.PolicyNamespace, Audience: n.Profile.Audience, AuthenticationMethod: "oauth", CredentialKind: identity.CredentialProvider, CredentialOwner: "identity/oauth"}
	validation := c.Session.Native.Validation
	validation.Clock = clock.System{}
	reader, err := sessionpg.NewSessionService(d.PostgreSQL, sessionpg.SessionServiceConfig{Repository: c.Session.Native.Execution.Repository, Profile: profile, Validation: validation})
	if err != nil {
		t.Fatal("native OAuth session reader configuration", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, result.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential})
	if err != nil || !read.Authenticated {
		t.Fatal("committed provider session is not usable by native primary reader", err)
	}
	execution := c.Session.Native.Execution
	execution.Profile = sessionpg.IssueAdmissionConfig(profile)
	selected := sessionpg.SingleFactorSessionAdmissionConfig{Verified: &profile}
	executor, err := sessionpg.NewCookieRevokeOneExecutor(d.PostgreSQL, sessionpg.RevokeOneExecutorConfig{Execution: execution, Sessions: reader, Admission: &selected}, c.Session.CSRFKeys)
	if err != nil {
		t.Fatal("native OAuth logout execution", err)
	}
	base, err := session.NewSignOutService(reader, executor, session.SignOutConfig{Cookie: c.Session.Native.Cookie, PolicyID: execution.PolicyID, PolicyVersion: execution.PolicyVersion, MaximumDuration: c.Session.Native.MaximumDuration})
	if err != nil {
		t.Fatal(err)
	}
	logout, err := session.NewCookieSignOutService(base, c.Session.CSRFKeys)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	logoutRequest := session.SignOutRequest{TenantID: r.TenantID, CommandID: command, CorrelationID: string(command), Transport: session.CredentialCookie, Credential: credential}
	wrong, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	if rejected, err := logout.SignOut(ctx, logoutRequest, wrong); err == nil || rejected.SignedOut {
		t.Fatal("wrong CSRF revoked provider session", err)
	}
	if still, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential}); err != nil || !still.Authenticated {
		t.Fatal("refused logout changed live provider session", err)
	}
	loggedOut, err := logout.SignOut(ctx, logoutRequest, result.CSRFToken)
	if err != nil || !loggedOut.SignedOut || loggedOut.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("native provider logout did not commit", err)
	}
	if after, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential}); err != nil || after.Authenticated {
		t.Fatal("provider session remained usable after logout", err)
	}
}
