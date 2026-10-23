//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	native "github.com/faustbrian/go-passkey/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	webauthn "github.com/faustbrian/go-webauthn"
)

// Actual registration, captured verification delivery and password signin precede
// this extension. Only raw authenticator bytes are controlled; no user/session,
// proof, protocol verification or domain store is seeded or substituted here.
func TestReferencePostgresPasskeyNative(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true}, true)
}

func TestReferencePostgresPasskeyManagement(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyUpgrade: upgrade, passkeyKeyed: true, passkeyManagement: true, passkeySessionHTTP: true}, true)
		})
	}
}

func TestReferencePostgresPasskeyDeletion(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyUpgrade: upgrade, passkeyKeyed: true, passkeyManagement: true, passkeyDeletion: true, passkeySessionHTTP: true}, true)
		})
	}
	t.Run("without-label-management", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeyDeletion: true, passkeySessionHTTP: true}, true)
	})
}

func proveReferencePasskeyDeletionSelection(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies) {
	t.Helper()
	deny := func(name string, selected reference.StoreConfiguration, field string) {
		t.Helper()
		graph, err := reference.ComposeStores(selected, deps)
		if err == nil {
			bounded, stop := context.WithTimeout(t.Context(), time.Second)
			_ = graph.Close(bounded)
			stop()
			t.Fatal(name, "accepted incomplete deletion authority")
		}
		var input identity.InvalidInputError
		if !errors.As(err, &input) || input.Field != field {
			t.Fatal(name, "did not reach the selected dependency guard", err)
		}
	}
	selected := c
	selected.PasswordReset, selected.HTTPPasswordReset = nil, nil
	deny("missing real reset owner", selected, "reference_passkey_deletion")
	for _, action := range []string{"identity.passkey.update", "identity.password.change"} {
		selected = c
		native, deletion := *c.Passkey, *c.Passkey.Deletion
		deletion.Primary.Action = action
		native.Deletion = &deletion
		selected.Passkey = &native
		deny("wrong signed action", selected, "reference_passkey_deletion")
	}
	if c.HTTPPasskey == nil || !c.HTTPPasskey.Delete {
		return
	}
	selected = c
	native, deletion := *c.Passkey, *c.Passkey.Deletion
	deletion.Primary.Transport = session.CredentialBearer
	native.Deletion = &deletion
	selected.Passkey, selected.HTTPPasskey = &native, nil
	graph, err := reference.ComposeStores(selected, deps)
	if err != nil {
		t.Fatal("valid native bearer deletion was removed", err)
	}
	bounded, stop := context.WithTimeout(t.Context(), time.Second)
	err = graph.Close(bounded)
	stop()
	if err != nil {
		t.Fatal("native selection cleanup", err)
	}
	selected.HTTPPasskey = c.HTTPPasskey
	deny("HTTP bearer deletion", selected, "reference_http_passkey")
	native = *c.Passkey
	native.Deletion = nil
	selected.Passkey = &native
	deny("HTTP without native deletion", selected, "reference_http_passkey")
}

func TestReferencePostgresPasskeyPopulatedUpgrade(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyUpgrade: true}, true)
}

func TestReferencePostgresPasskeyDiscoverable(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyDiscovery: true}, true)
}

func TestReferencePostgresPasskeyDiscoverablePopulatedUpgrade(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyDiscovery: true, passkeyUpgrade: true}, true)
}

func TestReferencePostgresPasskeyCommonSessionHTTP(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		for _, upgrade := range []bool{false, true} {
			name := "identified"
			if discoverable {
				name = "discoverable"
			}
			if upgrade {
				name += "/populated-upgrade"
			} else {
				name += "/fresh"
			}
			t.Run(name, func(t *testing.T) {
				proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyDiscovery: discoverable, passkeyUpgrade: upgrade, passkeySessionHTTP: true}, true)
			})
		}
	}
}

func TestReferencePostgresPasskeyKeyedOptions(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		for _, upgrade := range []bool{false, true} {
			name := "identified"
			if discoverable {
				name = "discoverable"
			}
			if upgrade {
				name += "/populated-upgrade"
			} else {
				name += "/fresh"
			}
			t.Run(name, func(t *testing.T) {
				proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyDiscovery: discoverable, passkeyUpgrade: upgrade, passkeySessionHTTP: true, passkeyKeyed: true}, true)
			})
		}
	}
}

func configureReferencePasskeyKeyed(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	token, err := session.NewDigestKey(1, bytes.Repeat([]byte{221}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{222}, 32))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := reference.NewPasskeyKeyedOptionsConfiguration("reference-passkey-options", [32]byte{223}, token, csrf)
	if err != nil {
		t.Fatal(err)
	}
	c.Passkey.KeyedOptions = &selected
}

func upgradeReferencePasskey(t *testing.T, ctx context.Context, previous reference.StoreSet, c reference.StoreConfiguration, deps reference.ReferenceDependencies, configs []deliverypg.WorkerConfig, modules []reference.ModuleID) reference.FeatureSet {
	t.Helper()
	if err := previous.Close(ctx); err != nil {
		t.Fatal("close prior graph before upgrade", err)
	}
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("compose populated passkey upgrade", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(cleanup); err != nil {
			t.Error("close upgraded graph", err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, configs...)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := features.Passkeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.PrepareFlow(ctx, session.PreAuthPrepareInput{TenantID: otpTenant}); err == nil {
		t.Fatal("uninitialized upgrade issued flow")
	}
	ids := append(append([]reference.ModuleID(nil), modules...), "passkey/postgres", "webauthn/postgres")
	r := applyRequest(t, ctx, stores, ids)
	r.CommandID = "migration_command_0002"
	r.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("passkey-populated-upgrade"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := stores.ReferenceMigrationApply(ctx, r); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("actual populated passkey upgrade", err)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("initialize actual successor", err)
	}
	return features
}

func configureReferencePasskey(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	challenge, err := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{218}, 32))
	if err != nil {
		t.Fatal(err)
	}
	flowKey, err := session.NewDigestKey(1, bytes.Repeat([]byte{219}, 32))
	if err != nil {
		t.Fatal(err)
	}
	flowCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	protected := c.PasswordSignup.Counters
	protected.EnforceLockouts = true
	issuer := c.PasswordSignin.Native.Issuance
	issuer.Clock = nil
	c.Passkey = &reference.PasskeyConfiguration{
		Protocol:            webauthn.Config{TenantID: otpTenant, RelyingParty: webauthn.RelyingParty{ID: "identity.example", Name: "Reference", Origins: []string{"https://identity.example"}, Version: 1}, ChallengeKey: challenge, MaximumDuration: c.OTP.Timeout},
		RPNamespace:         "reference-rp",
		OptionsPrimary:      passwordpg.ActionPrimaryConfig{Action: "identity.passkey.register-options", Audience: "reference-passkey", MaximumAge: time.Minute, Transport: session.CredentialCookie},
		RegistrationPrimary: passwordpg.ActionPrimaryConfig{Action: "identity.passkey.register-verify", Audience: "reference-passkey", MaximumAge: time.Minute, Transport: session.CredentialCookie},
		Protected:           protected,
		Flow:                session.PreAuthIssuerConfig{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", Action: "identity.passkey.signin-verify", Origin: "https://identity.example", PolicyID: c.Session.Native.Execution.PolicyID, PolicyVersion: 9, Purpose: session.PreAuthSessionIssuance, MaximumDuration: c.OTP.Timeout, FlowTTL: time.Minute, LookupKey: flowKey, TokenSize: 32, Cookie: flowCookie},
		Issuer:              issuer, CSRF: c.PasswordSignin.Native.CSRFKey,
		Risk:          risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-passkey", Keys: c.OTP.RiskKeys},
		IdentifierKey: bytes.Repeat([]byte{220}, 32), SessionPredecessor: "session_issuances_purpose_v3",
	}
	for _, action := range []string{"identity.passkey.register-options", "identity.passkey.register-verify"} {
		c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: action, Audience: "reference-passkey"})
	}
}

func proveReferencePasskey(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, user identity.UserID, cookies []*http.Cookie, csrfWire string, discoverable bool, sessionHandler http.Handler) {
	t.Helper()
	owner, err := features.Passkeys()
	if err != nil {
		t.Fatal("selected passkey handle", err)
	}
	proofs, err := features.CookiePasswordVerification()
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "reference-passkey", Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}
	registration := func(action string) native.RegistrationRequest {
		t.Helper()
		secret, err := primitive.NewSecret([]byte("synthetic-registration-password"))
		if err != nil {
			t.Fatal(err)
		}
		defer secret.Destroy()
		proof, err := proofs.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: auth.NewBearerCredential(cookies[0].Value), Password: secret, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: action, Audience: "reference-passkey"}, Caller: caller, Network: "127.0.0.1", Device: "reference-passkey"}, CSRFToken: csrf})
		if err != nil {
			t.Fatal("genuine passkey action proof", err)
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		authorized := caller.Clone()
		authorized.Request.Action = authorization.Action(action)
		authorized.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}
		return native.RegistrationRequest{Primary: passwordpg.ActionPrimaryRequest{TenantID: otpTenant, CommandID: id, Session: auth.NewBearerCredential(cookies[0].Value), Proof: proof.Proof, Caller: authorized, CSRFToken: csrf}, Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1", Device: "reference-passkey"}
	}
	request := registration("identity.passkey.register-options")
	missing := request
	missing.Primary.Proof = auth.ReauthenticationProof{}
	if _, err := owner.RegistrationOptions(ctx, missing); err == nil {
		t.Fatal("missing proof enrolled")
	}
	var options webauthn.RegistrationOptions
	if c.Passkey.KeyedOptions != nil {
		request.Primary.CommandID = ""
		key, e := identity.NewIdempotencyKey([]byte("reference-registration-options"))
		if e != nil {
			t.Fatal(e)
		}
		keyed := passkey.KeyedRegistrationOptionsRequest{RegistrationRequest: request, IdempotencyKey: key}
		first, e := owner.KeyedRegistrationOptions(ctx, keyed)
		if e != nil || first.CommandID == "" || first.Replayed || first.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("reference original keyed enrollment", e)
		}
		options = first.Options
		replay, e := owner.KeyedRegistrationOptions(ctx, keyed)
		if e != nil || !replay.Replayed || replay.CommandID != first.CommandID || replay.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("reference enrollment original-key recovery", e)
		}
		if _, present := replay.Options.Ceremony(); present || replay.Options.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("replay exposed registration challenge"); return nil }) == nil {
			t.Fatal("reference replay acquired registration options")
		}
	} else {
		options, err = owner.RegistrationOptions(ctx, request)
	}
	if err != nil {
		t.Fatal("native reference registration options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("committed options absent")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	completion := native.RegistrationCompletion{RegistrationRequest: registration("identity.passkey.register-verify"), CeremonyID: ceremony.ID, Label: "Reference key", Response: referencePasskeyRegistration(t, key, id, referencePasskeyChallenge(t, ctx, options.TransferJSON))}
	if c.Passkey.KeyedOptions != nil {
		source, e := owner.RegistrationRateSource(ctx, passkey.RegistrationCeremonyRateRequest{RegistrationRequest: completion.RegistrationRequest, CeremonyID: ceremony.ID})
		if e != nil || source.Kind != passkey.RateSourceUser || source.UserID != user || source.CeremonyID != ceremony.ID || source.Lifetime != 5*time.Minute {
			t.Fatal("reference genuine original registration source", e)
		}
	}
	verified, err := owner.Register(ctx, completion)
	if err != nil {
		t.Fatal("reference-native passkey register", err)
	}
	credential, ok := verified.Credential()
	if !ok || credential.UserID != user {
		t.Fatal("wrong enrolled identity")
	}
	query := identity.RecoveryQuery{CommandID: completion.Primary.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.passkey.register-verify", RecordID: string(completion.Primary.CommandID)}
	if recovered, err := owner.RecoverEnrollment(ctx, query, completion.Primary.Caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original enrollment recovery", err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	flowCommand, _ := identity.NewCommandID()
	prepared, err := owner.PrepareFlow(ctx, session.PreAuthPrepareInput{CommandID: flowCommand, TenantID: otpTenant, CorrelationID: "reference-passkey", Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	issuedFlow, err := owner.IssueFlow(ctx, prepared)
	if err != nil {
		t.Fatal("reference-native passkey initiation", err)
	}
	flow, flowErr := issuedFlow.Flow.Bindings()
	if flowErr != nil {
		t.Fatal(flowErr)
	}
	optionsID, _ := identity.NewCommandID()
	input := native.SigninRequest{CommandID: optionsID, FlowID: flow.Binding.ID, Cookie: issuedFlow.Token, Identifier: "registered@example.invalid", Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1", Device: "reference-passkey", CorrelationID: "reference-passkey"}
	// This type has no identifier, user, tenant or RP input. Discovery must
	// resolve the verified resident credential, not reuse the email above.
	discovery := native.DiscoverableSigninRequest{CommandID: optionsID, FlowID: flow.Binding.ID, Cookie: issuedFlow.Token, Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1", Device: "reference-passkey", CorrelationID: "reference-passkey"}
	var assertionOptions webauthn.AssertionOptions
	if c.Passkey.KeyedOptions != nil {
		key, e := identity.NewIdempotencyKey([]byte("reference-signin-options"))
		if e != nil {
			t.Fatal(e)
		}
		input.CommandID, discovery.CommandID = "", ""
		caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.Passkey.Flow.ActorID)}, Action: "identity.passkey.signin-options", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow.Binding.ID)}}}
		call := func() (passkey.KeyedAssertionOptionsResult, error) {
			if discoverable {
				return owner.KeyedDiscoverableAuthenticationOptions(ctx, passkey.KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: discovery, IdempotencyKey: key, Caller: caller})
			}
			return owner.KeyedAuthenticationOptions(ctx, passkey.KeyedSigninOptionsRequest{SigninRequest: input, IdempotencyKey: key, Caller: caller})
		}
		first, e := call()
		if e != nil || first.CommandID == "" || first.Replayed || first.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("reference original keyed signin", e)
		}
		assertionOptions = first.Options
		replay, e := call()
		if e != nil || !replay.Replayed || replay.CommandID != first.CommandID || replay.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("reference signin original-key recovery", e)
		}
		if _, present := replay.Options.Ceremony(); present || replay.Options.TransferJSON(ctx, func(context.Context, []byte) error { t.Fatal("replay exposed assertion challenge"); return nil }) == nil {
			t.Fatal("reference replay acquired assertion options")
		}
	} else if discoverable {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := owner.DiscoverableAuthenticationOptions(canceled, discovery); err == nil {
			t.Fatal("canceled graph admitted discovery")
		}
		assertionOptions, err = owner.DiscoverableAuthenticationOptions(ctx, discovery)
	} else {
		if _, err := owner.DiscoverableAuthenticationOptions(ctx, discovery); err == nil {
			t.Fatal("disabled discovery policy admitted options")
		}
		assertionOptions, err = owner.AuthenticationOptions(ctx, input)
	}
	if err != nil {
		t.Fatal("reference-native assertion options", err)
	}
	assertionCeremony, _ := assertionOptions.Ceremony()
	input.CommandID, _ = identity.NewCommandID()
	signin := native.SigninCompletion{SigninRequest: input, CeremonyID: assertionCeremony.ID, Response: referencePasskeyAssertion(t, key, id, credential.UserHandle, referencePasskeyChallenge(t, ctx, assertionOptions.TransferJSON))}
	discovery.CommandID = input.CommandID
	discoveryCompletion := native.DiscoverableSigninCompletion{DiscoverableSigninRequest: discovery, CeremonyID: signin.CeremonyID, Response: signin.Response}
	if c.Passkey.KeyedOptions != nil {
		var source passkey.CeremonyRateSource
		var e error
		if discoverable {
			source, e = owner.DiscoverableSigninRateSource(ctx, passkey.DiscoverableCeremonyRateRequest{DiscoverableSigninRequest: discovery, CeremonyID: signin.CeremonyID})
			if source.Kind != passkey.RateSourceAnonymousFlow || source.AnonymousFlowID != discovery.FlowID || source.Identifier != "" {
				t.Fatal("reference discovery source became an identifier")
			}
		} else {
			source, e = owner.SigninRateSource(ctx, passkey.SigninCeremonyRateRequest{SigninRequest: input, CeremonyID: signin.CeremonyID})
			if source.Kind != passkey.RateSourceIdentifier || source.Identifier != input.Identifier || source.AnonymousFlowID != "" {
				t.Fatal("reference identified source changed original input")
			}
		}
		if e != nil || source.UserID != "" || source.CeremonyID != signin.CeremonyID || source.Lifetime != 5*time.Minute {
			t.Fatal("reference original assertion source", e)
		}
	}
	foreignToken, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	var issued native.SigninResult
	if discoverable {
		foreignBrowser := discoveryCompletion
		foreignBrowser.Cookie = foreignToken
		if result, err := owner.DiscoverableSignin(ctx, foreignBrowser); err == nil || result.Session.Token != (session.Token{}) {
			t.Fatal("foreign browser received a discovery session")
		}
		wrongMode := signin
		// A different request mode needs its own command identity: native risk
		// custody deliberately rejects changed-input reuse of the same attempt.
		wrongMode.CommandID, _ = identity.NewCommandID()
		if result, err := owner.Signin(ctx, wrongMode); err == nil || result.Session.Token != (session.Token{}) {
			t.Fatal("identified completion accepted discovery ceremony")
		}
		issued, err = owner.DiscoverableSignin(ctx, discoveryCompletion)
	} else {
		foreignBrowser := signin
		foreignBrowser.Cookie = foreignToken
		if result, err := owner.Signin(ctx, foreignBrowser); err == nil || result.Session.Token != (session.Token{}) {
			t.Fatal("foreign browser received a session")
		}
		wrongMode := discoveryCompletion
		// Preserve the actual completion's immutable risk attempt identity.
		wrongMode.CommandID, _ = identity.NewCommandID()
		if result, err := owner.DiscoverableSignin(ctx, wrongMode); err == nil || result.Session.Token != (session.Token{}) {
			t.Fatal("discovery completion accepted identified ceremony")
		}
		issued, err = owner.Signin(ctx, signin)
	}
	if err != nil {
		t.Fatal("reference-native actual passkey signin", err)
	}
	if c.Passkey.Management != nil {
		first, _ := session.NewCredential(session.CredentialCookie, issued.Session.Token)
		listCaller := caller.Clone()
		listCaller.Request.Action = "identity.passkey.list"
		listCaller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}
		attempt, _ := identity.NewCommandID()
		page, e := owner.List(ctx, native.InventoryRequest{Credential: first, Caller: listCaller, AttemptID: attempt, Limit: 10})
		if e != nil || len(page.Credentials) != 1 {
			t.Fatal("genuine safe rename reference", e)
		}
		primary := registration("identity.passkey.update").Primary
		primary.CommandID, primary.RecordID = "", ""
		requestKey, _ := identity.NewIdempotencyKey([]byte("reference-rename-original"))
		update := passkey.UpdateRequest{Primary: primary, ReferenceID: identity.CredentialID(page.Credentials[0].ReferenceID), ExpectedVersion: page.Credentials[0].Version, Name: "Renamed reference key", IdempotencyKey: requestKey, Network: "127.0.0.1"}
		wrong := update
		wrong.Primary.Proof.SessionID = "foreign-session"
		if out, e := owner.Update(ctx, wrong); e == nil || out.Credential != nil {
			t.Fatal("wrong original session renamed")
		}
		out, e := owner.Update(ctx, update)
		if e != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || out.Credential == nil || out.Credential.Label != update.Name || out.Credential.Version != update.ExpectedVersion+1 {
			t.Fatal("real Reference rename", e)
		}
		replay, e := owner.Update(ctx, update)
		if e != nil || !replay.Replayed || replay.CommandID != out.CommandID || replay.Credential != nil {
			t.Fatal("Reference rename redelivered metadata", e)
		}
		attempt, _ = identity.NewCommandID()
		page, e = owner.List(ctx, native.InventoryRequest{Credential: first, Caller: listCaller, AttemptID: attempt, Limit: 10})
		if e != nil || len(page.Credentials) != 1 || page.Credentials[0].Label != update.Name || page.Credentials[0].Version != update.ExpectedVersion+1 {
			t.Fatal("renamed inventory not visible", e)
		}
		if got, e := owner.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: first}); e != nil || !got.Authenticated {
			t.Fatal("metadata rename invalidated authentication", e)
		}
		firstLogout, _ := identity.NewCommandID()
		if result, e := owner.SignOut(ctx, session.SignOutRequest{TenantID: otpTenant, CommandID: firstLogout, CorrelationID: "reference-rename-first-session", Transport: session.CredentialCookie, Credential: first}, issued.CSRF); e != nil || !result.SignedOut {
			t.Fatal("first passkey session logout", e)
		}
		issued = referencePasskeySigninAfterRename(t, ctx, owner, c, key, id, credential.UserHandle)
	}
	wire, err := issued.Session.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	read := session.GetRequest{TenantID: otpTenant, Credential: browser}
	if got, err := owner.Get(ctx, read); err != nil || !got.Authenticated {
		t.Fatal("issued passkey session unusable", err)
	}
	common, err := features.Sessions()
	if err != nil {
		t.Fatal("common session handle", err)
	}
	if got, err := common.Get(ctx, read); c.Session.Passkey {
		if err != nil || !got.Authenticated {
			t.Fatal("explicitly selected common passkey session unusable", err)
		}
	} else if err == nil && got.Authenticated {
		t.Fatal("native passkey selection implicitly enabled common sessions")
	}
	foreign := read
	foreign.TenantID = "foreign-tenant"
	if got, err := owner.Get(ctx, foreign); err == nil || got.Authenticated {
		t.Fatal("foreign tenant read selected passkey session")
	}
	listCaller := caller.Clone()
	listCaller.Request.Action = "identity.passkey.list"
	listCaller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}
	attempt, _ := identity.NewCommandID()
	expectedLabel := "Reference key"
	if c.Passkey.Management != nil {
		expectedLabel = "Renamed reference key"
	}
	if page, err := owner.List(ctx, native.InventoryRequest{Credential: browser, Caller: listCaller, AttemptID: attempt, Limit: 10}); err != nil || len(page.Credentials) != 1 || page.Credentials[0].Label != expectedLabel {
		t.Fatal("safe reference passkey inventory", err)
	}
	logoutID, _ := identity.NewCommandID()
	logout := session.SignOutRequest{TenantID: otpTenant, CommandID: logoutID, CorrelationID: "reference-passkey", Transport: session.CredentialCookie, Credential: browser}
	wrong, _ := session.NewCSRFToken()
	if _, err := owner.SignOut(ctx, logout, wrong); err == nil {
		t.Fatal("foreign synchronizer logged out passkey")
	}
	if got, err := owner.Get(ctx, read); err != nil || !got.Authenticated {
		t.Fatal("denied logout invalidated session", err)
	}
	if c.Passkey.Deletion != nil {
		attempt, _ = identity.NewCommandID()
		page, err := owner.List(ctx, native.InventoryRequest{Credential: browser, Caller: listCaller, AttemptID: attempt, Limit: 10})
		if err != nil || len(page.Credentials) != 1 {
			t.Fatal("genuine removal reference", err)
		}
		primary := registration("identity.passkey.delete").Primary
		primary.CommandID, primary.RecordID = "", ""
		key, _ := identity.NewIdempotencyKey([]byte("reference-delete-original"))
		request := passkey.DeleteRequest{Primary: primary, ReferenceID: identity.CredentialID(page.Credentials[0].ReferenceID), ExpectedVersion: page.Credentials[0].Version, IdempotencyKey: key, Network: "127.0.0.1"}
		wrong := request
		wrong.Primary.Proof.SessionID = "foreign-session"
		if out, e := owner.Delete(ctx, wrong); e == nil || out.CommandID != "" {
			t.Fatal("foreign proof removed credential")
		}
		removed, e := owner.Delete(ctx, request)
		if e != nil || removed.Outcome != identity.CommitOutcomeCommitted || removed.Replayed || removed.Receipt.Feature == nil || removed.Receipt.Feature.BeforeVersion != 1 || removed.Receipt.Feature.AfterVersion != 2 {
			t.Fatal("Reference native deletion failed independent version transition", e)
		}
		replay, e := owner.Delete(ctx, request)
		if e != nil || !replay.Replayed || replay.CommandID != removed.CommandID {
			t.Fatal("Reference original deletion retry", e)
		}
		if got, e := owner.Get(ctx, read); e != nil || got.Authenticated {
			t.Fatal("removed passkey retained native session", e)
		}
		if got, e := common.Get(ctx, read); e != nil || got.Authenticated {
			t.Fatal("removed passkey retained common session", e)
		}
		passwordToken, e := session.ParseToken(cookies[0].Value)
		if e != nil {
			t.Fatal(e)
		}
		passwordCredential, e := session.NewCredential(session.CredentialCookie, passwordToken)
		if e != nil {
			t.Fatal(e)
		}
		passwordRead := session.GetRequest{TenantID: otpTenant, Credential: passwordCredential}
		if got, e := common.Get(ctx, passwordRead); e != nil || !got.Authenticated {
			t.Fatal("deletion revoked unrelated password session", e)
		}
		if sessionHandler == nil {
			t.Fatal("selected deletion profile lacks common session HTTP proof")
		}
		proveReferencePasskeySessionHTTP(t, ctx, sessionHandler, c, user, cookies[0].Value, csrfWire, func() bool { got, e := common.Get(ctx, passwordRead); return e == nil && got.Authenticated })
		return
	}
	csrfOut, err := issued.CSRF.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	csrfToken, err := session.ParseCSRFToken(csrfOut)
	if err != nil {
		t.Fatal(err)
	}
	if sessionHandler != nil {
		proveReferencePasskeySessionHTTP(t, ctx, sessionHandler, c, user, wire, csrfOut, func() bool {
			got, err := common.Get(ctx, read)
			return err == nil && got.Authenticated
		})
	} else {
		if result, err := owner.SignOut(ctx, logout, csrfToken); err != nil || !result.SignedOut || !result.ClearCookie {
			t.Fatal("real reference passkey logout", err)
		}
	}
	if got, err := owner.Get(ctx, read); err != nil || got.Authenticated {
		t.Fatal("logged-out passkey authenticated", err)
	}
}

func referencePasskeySigninAfterRename(t *testing.T, ctx context.Context, owner *reference.PasskeyService, c reference.StoreConfiguration, key *ecdsa.PrivateKey, id, handle []byte) native.SigninResult {
	t.Helper()
	remember, e := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	command, _ := identity.NewCommandID()
	prepared, e := owner.PrepareFlow(ctx, session.PreAuthPrepareInput{CommandID: command, TenantID: otpTenant, CorrelationID: "reference-after-rename", Remember: remember})
	if e != nil {
		t.Fatal(e)
	}
	flow, e := owner.IssueFlow(ctx, prepared)
	if e != nil {
		t.Fatal(e)
	}
	binding, e := flow.Flow.Bindings()
	if e != nil {
		t.Fatal(e)
	}
	input := native.SigninRequest{FlowID: binding.Binding.ID, Cookie: flow.Token, Identifier: "registered@example.invalid", Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1", Device: "reference-passkey", CorrelationID: "reference-after-rename"}
	requestKey, _ := identity.NewIdempotencyKey([]byte("reference-after-rename-options"))
	options, e := owner.KeyedAuthenticationOptions(ctx, passkey.KeyedSigninOptionsRequest{SigninRequest: input, IdempotencyKey: requestKey, Caller: authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.Passkey.Flow.ActorID)}, Action: "identity.passkey.signin-options", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(binding.Binding.ID)}}}})
	if e != nil {
		t.Fatal("post-rename actual options", e)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("post-rename challenge absent")
	}
	input.CommandID, _ = identity.NewCommandID()
	result, e := owner.Signin(ctx, native.SigninCompletion{SigninRequest: input, CeremonyID: ceremony.ID, Response: referencePasskeyAssertion(t, key, id, handle, referencePasskeyChallenge(t, ctx, options.Options.TransferJSON), 2)})
	if e != nil || result.Session.Token == (session.Token{}) {
		t.Fatal("same passkey cannot authenticate after rename", e)
	}
	return result
}

func proveReferencePasskeySessionHTTP(t *testing.T, ctx context.Context, handler http.Handler, c reference.StoreConfiguration, user identity.UserID, token, csrf string, nativeRead func() bool) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	cookie, err := c.Session.Native.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	type response struct {
		code    int
		header  http.Header
		body    []byte
		cookies []*http.Cookie
	}
	request := func(method, path, origin, csrf string) response {
		t.Helper()
		var body io.Reader
		if method == http.MethodPost {
			body = strings.NewReader("{}")
		}
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		// The successor uses a separate local listener but retains the original
		// deployment's public authority and frozen same-origin HTTP policy.
		r.Host = strings.TrimPrefix(string(c.HTTPSession.TrustedOrigins[0]), "https://")
		r.AddCookie(&http.Cookie{Name: cookie.Name, Value: token})
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
		}
		got, err := client.Do(r)
		if err != nil {
			t.Fatal("passkey HTTPS request failed")
		}
		defer got.Body.Close()
		wire, err := io.ReadAll(io.LimitReader(got.Body, 16385))
		if err != nil || len(wire) > 16384 {
			t.Fatal("passkey HTTPS response exceeded its bound")
		}
		return response{got.StatusCode, got.Header, wire, got.Cookies()}
	}
	read := func(want bool) {
		t.Helper()
		w := request(http.MethodGet, "/v1/session/get", "", "")
		var out sessionhttp.GetResponse
		if w.code != http.StatusOK || json.Unmarshal(w.body, &out) != nil || out.Authenticated != want || w.header.Get("Cache-Control") != "no-store" || len(w.cookies) != 0 {
			t.Fatal("HTTP passkey session read", w.code, "authenticated", out.Authenticated)
		}
		if want && (out.Principal == nil || out.Principal.UserID != user || out.Principal.TenantID != otpTenant) {
			t.Fatal("HTTP passkey read selected another principal")
		}
	}
	read(true)
	wrong, _ := session.NewCSRFToken()
	wrongWire, err := wrong.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	trustedOrigin := string(c.HTTPSession.TrustedOrigins[0])
	for _, denied := range []struct{ origin, csrf string }{{trustedOrigin, wrongWire}, {"https://foreign.example", csrf}} {
		w := request(http.MethodPost, "/v1/session/signout", denied.origin, denied.csrf)
		if w.code != http.StatusForbidden || len(w.cookies) != 0 || !nativeRead() {
			t.Fatal("denied HTTP logout changed passkey session", w.code)
		}
		read(true)
	}
	w := request(http.MethodPost, "/v1/session/signout", trustedOrigin, csrf)
	var out sessionhttp.SignOutResponse
	decodeErr := json.Unmarshal(w.body, &out)
	if w.code != http.StatusOK || decodeErr != nil || !out.SignedOut || out.CommitOutcome != "committed" || w.header.Get("Cache-Control") != "no-store" {
		t.Fatal("HTTP passkey logout", w.code, out.CommitOutcome, out.Error, "response bytes", len(w.body), "decode", decodeErr)
	}
	cleared := w.cookies
	if len(cleared) != 1 || cleared[0].Name != cookie.Name || cleared[0].Value != "" || cleared[0].MaxAge >= 0 || !cleared[0].Secure || !cleared[0].HttpOnly || cleared[0].Path != cookie.Path || cleared[0].Domain != cookie.Domain || cleared[0].SameSite != cookie.SameSite {
		t.Fatal("HTTP logout did not clear the original cookie tuple")
	}
	if nativeRead() {
		t.Fatal("HTTP logout left common native passkey session active")
	}
	read(false)
}

func referencePasskeyChallenge(t *testing.T, ctx context.Context, transfer func(context.Context, func(context.Context, []byte) error) error) string {
	t.Helper()
	var out struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := transfer(ctx, func(_ context.Context, wire []byte) error { return json.Unmarshal(wire, &out) }); err != nil || out.PublicKey.Challenge == "" {
		t.Fatal("real options challenge", err)
	}
	return out.PublicKey.Challenge
}

// Controlled none/ES256 raw authenticator, not a protocol or proof substitute.
func referencePasskeyRegistration(t *testing.T, key *ecdsa.PrivateKey, id []byte, challenge string) []byte {
	t.Helper()
	bstr := func(value []byte) []byte {
		if len(value) < 24 {
			return append([]byte{0x40 | byte(len(value))}, value...)
		}
		if len(value) < 256 {
			return append([]byte{0x58, byte(len(value))}, value...)
		}
		return append(binary.BigEndian.AppendUint16([]byte{0x59}, uint16(len(value))), value...)
	}
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	cose = append(cose, bstr(key.X.FillBytes(make([]byte, 32)))...)
	cose = append(cose, 0x22)
	cose = append(cose, bstr(key.Y.FillBytes(make([]byte, 32)))...)
	rp := sha256.Sum256([]byte("identity.example"))
	data := append([]byte{}, rp[:]...)
	data = binary.BigEndian.AppendUint32(append(data, 0x45), 0)
	data = append(data, make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(id)))
	data = append(append(data, id...), cose...)
	att := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'}
	att = append(att, bstr(data)...)
	client, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": "https://identity.example", "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	wire, err := json.Marshal(map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "attestationObject": b64(att)}, "clientExtensionResults": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func referencePasskeyAssertion(t *testing.T, key *ecdsa.PrivateKey, id, handle []byte, challenge string, counters ...uint32) []byte {
	t.Helper()
	counter := uint32(1)
	if len(counters) > 1 {
		t.Fatal("ambiguous synthetic authenticator counter")
	}
	if len(counters) == 1 {
		counter = counters[0]
	}
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": "https://identity.example", "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("identity.example"))
	data := binary.BigEndian.AppendUint32(append(append([]byte{}, rp[:]...), 0x05), counter)
	hash := sha256.Sum256(client)
	message := sha256.Sum256(append(bytes.Clone(data), hash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, message[:])
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	wire, err := json.Marshal(map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "authenticatorData": b64(data), "signature": b64(signature), "userHandle": b64(handle)}, "clientExtensionResults": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
