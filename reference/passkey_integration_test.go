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
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
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

func TestReferencePostgresPasskeyPopulatedUpgrade(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyUpgrade: true}, true)
}

func TestReferencePostgresPasskeyDiscoverable(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyDiscovery: true}, true)
}

func TestReferencePostgresPasskeyDiscoverablePopulatedUpgrade(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyDiscovery: true, passkeyUpgrade: true}, true)
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

func proveReferencePasskey(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, user identity.UserID, cookies []*http.Cookie, csrfWire string, discoverable bool) {
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
	options, err := owner.RegistrationOptions(ctx, request)
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
	if discoverable {
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
	foreign := read
	foreign.TenantID = "foreign-tenant"
	if got, err := owner.Get(ctx, foreign); err == nil || got.Authenticated {
		t.Fatal("foreign tenant read selected passkey session")
	}
	listCaller := caller.Clone()
	listCaller.Request.Action = "identity.passkey.list"
	listCaller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}
	attempt, _ := identity.NewCommandID()
	if page, err := owner.List(ctx, native.InventoryRequest{Credential: browser, Caller: listCaller, AttemptID: attempt, Limit: 10}); err != nil || len(page.Credentials) != 1 || page.Credentials[0].Label != "Reference key" {
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
	csrfOut, err := issued.CSRF.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	csrfToken, err := session.ParseCSRFToken(csrfOut)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := owner.SignOut(ctx, logout, csrfToken); err != nil || !result.SignedOut || !result.ClearCookie {
		t.Fatal("real reference passkey logout", err)
	}
	if got, err := owner.Get(ctx, read); err != nil || got.Authenticated {
		t.Fatal("logged-out passkey authenticated", err)
	}
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

func referencePasskeyAssertion(t *testing.T, key *ecdsa.PrivateKey, id, handle []byte, challenge string) []byte {
	t.Helper()
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": "https://identity.example", "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("identity.example"))
	data := binary.BigEndian.AppendUint32(append(append([]byte{}, rp[:]...), 0x05), 1)
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
