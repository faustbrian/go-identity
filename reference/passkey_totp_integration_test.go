//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	native "github.com/faustbrian/go-passkey/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

func TestReferencePasskeyTOTPFromRealEnrollment(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		name := "identified"
		if discoverable {
			name = "discoverable"
		}
		t.Run(name, func(t *testing.T) {
			for _, upgrade := range []bool{false, true} {
				t.Run(map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
					proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySessionHTTP: true, passkeyDiscovery: discoverable, passkeyTOTP: true, passkeyUpgrade: upgrade}, true)
				})
			}
		})
	}
}

func TestReferencePasskeyTOTPInventoryAndFreshUVRename(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "discoverable"}[discoverable], func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySessionHTTP: true, passkeyDiscovery: discoverable, passkeyTOTP: true, passkeyTOTPManagement: true}, true)
		})
	}
}

func TestReferencePasskeyTOTPAdditionalKeyEnrollment(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "discoverable"}[discoverable], func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySessionHTTP: true, passkeyDiscovery: discoverable, passkeyTOTP: true, passkeyTOTPEnrollment: true}, true)
		})
	}
}

func TestReferencePasskeyTOTPKeyRemoval(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "discoverable"}[discoverable], func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySessionHTTP: true, passkeyDiscovery: discoverable, passkeyTOTP: true, passkeyTOTPDeletion: true}, true)
		})
	}
}

func TestReferencePasskeyTOTPHTTPSFromRealEnrollment(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "discoverable"}[discoverable], func(t *testing.T) {
			for _, upgrade := range []bool{false, true} {
				t.Run(map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
					proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySessionHTTP: true, passkeyHTTP: true, passkeyDiscovery: discoverable, passkeyTOTP: true, passkeyUpgrade: upgrade}, true)
				})
			}
		})
	}
}

func TestReferencePasskeyTOTPHTTPInventoryAndFreshUVRename(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "discoverable"}[discoverable], func(t *testing.T) {
			for _, upgrade := range []bool{false, true} {
				t.Run(map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
					proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySessionHTTP: true, passkeyHTTP: true, passkeyDiscovery: discoverable, passkeyTOTP: true, passkeyTOTPManagement: true, passkeyUpgrade: upgrade}, true)
				})
			}
		})
	}
}

func TestReferencePasskeyTOTPHTTPAdditionalKeyEnrollment(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "discoverable"}[discoverable], func(t *testing.T) {
			for _, upgrade := range []bool{false, true} {
				t.Run(map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
					proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySessionHTTP: true, passkeyHTTP: true, passkeyDiscovery: discoverable, passkeyTOTP: true, passkeyTOTPEnrollment: true, passkeyUpgrade: upgrade}, true)
				})
			}
		})
	}
}

func TestReferencePasskeyTOTPHTTPKeyRemoval(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		t.Run(map[bool]string{false: "identified", true: "discoverable"}[discoverable], func(t *testing.T) {
			for _, upgrade := range []bool{false, true} {
				t.Run(map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
					proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySessionHTTP: true, passkeyHTTP: true, passkeyDiscovery: discoverable, passkeyTOTP: true, passkeyTOTPDeletion: true, passkeyUpgrade: upgrade}, true)
				})
			}
		})
	}
}

func configureReferencePasskeyTOTP(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	issuer := c.PasswordSignup.Issuer
	issuer.Audience = c.Session.Native.Execution.Profile.Audience
	issuer.Crypto.Issuer = c.Passkey.Flow.Origin
	issuer.Crypto.Limits.MaxCaveats = 16
	// The selected signer is the synthetic registration key. Its matching
	// resolver must bind this separately configured passkey issuer, not the
	// registration fixture's dynamic HTTPS origin.
	verifier, err := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{119}, 32))
	if err != nil {
		t.Fatal(err)
	}
	issuer.Crypto.Resolver, err = capability.NewKeySet([]capability.Key{{Issuer: issuer.Crypto.Issuer, ID: "reference-signup", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	counters := c.PasswordSignup.Counters
	policy := *counters.CommandCounters
	policy.Policy, policy.Keys = c.Velocity.Native.Policy, c.Velocity.Native.Keys
	counters.CommandCounters = &policy
	admitted, err := policy.Policy.Admit("identity.mfa.totp-verify")
	if err != nil {
		t.Fatal(err)
	}
	counters.PolicyVersion = admitted.PolicyVersion
	c.Passkey.SessionPredecessor = "session_issuances_purpose_v6"
	c.Passkey.Flow.CallbackURL = c.Passkey.Flow.Origin + "/complete"
	c.Passkey.TOTP = &reference.PasskeyTOTPConfiguration{Challenge: native.SigninMFAConfig{Lifetime: time.Minute, MaxAttempts: 3, IssuerURL: c.Passkey.Flow.Origin, Issuer: issuer, Custody: c.PasswordSignup.Preparation, EnvelopeKeyID: "issue-envelope"}, Completion: reference.MagicLinkTOTPConfiguration{MaximumDuration: c.OTP.Timeout, ConfigurationID: "reference-passkey-totp-v1", PolicyID: "passkey-totp", Counters: counters, RiskKeys: c.OTP.RiskKeys, ComparisonKey: [32]byte{197}, ComparisonKeyVersion: 1, ActiveEnvelopeKeyID: "issue-envelope"}}
	if c.HTTPPasskey != nil {
		c.HTTPPasskey.MFAContinuation = true
		c.HTTPMFA = &reference.HTTPMFAConfiguration{PasskeyTOTPVerify: true, ActorID: c.Passkey.Flow.ActorID, PolicyRevision: authorization.Revision(c.Passkey.Flow.PolicyVersion), VerificationNamespace: "reference-mfa-verify", VerificationKey: [32]byte{198}}
	}
}

// Registration, key enrollment and confirmed TOTP all use their actual public
// owners. Only authenticator bytes are controlled; no account, key mapping,
// factor secret, original challenge, session or successful receipt is seeded.
func proveReferencePasskeyTOTPFromEnrollment(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, c reference.StoreConfiguration, client *http.Client, base, enrollmentOrigin string, user identity.UserID, cookies []*http.Cookie, csrf string, discoverable bool, sessionHandler http.Handler, document []byte) {
	t.Helper()
	// A populated upgrade closes the baseline graph. Enrollment and logout
	// must reach the actual successor, not its retired HTTP handlers. Origins
	// remain the exact configured allowlist; only this owned loopback listener
	// and its client transport change.
	network := httptest.NewTLSServer(sessionHandler)
	defer network.Close()
	transport := network.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, networkName, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, networkName, network.Listener.Addr().String())
	}
	client = &http.Client{Transport: transport, Timeout: 5 * time.Second}
	if c.HTTPPasskey != nil {
		client.Transport = passkeyFixtureHostTransport{next: transport}
	}
	defer transport.CloseIdleConnections()
	proveReferencePasskey(t, ctx, features, c, user, cookies, csrf, discoverable, sessionHandler, func(credential webauthn.Credential, key *ecdsa.PrivateKey, id []byte) {
		local := f
		local.afterTOTPEnrollment = func(factor mfa.FactorID, secret []byte) {
			if c.HTTPPasskey != nil && c.HTTPPasskey.MFAContinuation {
				proveReferencePasskeyTOTPHTTPS(t, ctx, f, features, c, client, base, enrollmentOrigin, user, credential, key, id, factor, secret, discoverable, sessionHandler, document)
			} else {
				proveReferencePasskeyTOTP(t, ctx, f, features, c, client, base, enrollmentOrigin, user, credential, key, id, factor, secret, discoverable, sessionHandler)
			}
		}
		token, err := session.ParseToken(cookies[0].Value)
		if err != nil {
			t.Fatal(err)
		}
		browser, _ := session.NewCredential(session.CredentialCookie, token)
		reader, err := features.Sessions()
		if err != nil {
			t.Fatal(err)
		}
		original, err := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: browser})
		if err != nil || !original.Authenticated {
			t.Fatal("genuine password session unavailable before factor enrollment", err)
		}
		current, _ := original.Session.Bindings()
		proveReferenceMFAEnrollment(t, ctx, local, features, client, base, enrollmentOrigin, cookies, csrf, current.SessionID, false)
	})
}

func proveReferencePasskeyTOTP(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, c reference.StoreConfiguration, client *http.Client, base, logoutOrigin string, user identity.UserID, credential webauthn.Credential, key *ecdsa.PrivateKey, id []byte, factor mfa.FactorID, secret []byte, discoverable bool, sessionHandler http.Handler) {
	t.Helper()
	owner, err := features.Passkeys()
	if err != nil {
		t.Fatal(err)
	}
	remember, _ := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	flowID, _ := identity.NewCommandID()
	prepared, err := owner.PrepareFlow(ctx, session.PreAuthPrepareInput{CommandID: flowID, TenantID: otpTenant, CorrelationID: "reference-passkey-totp", Remember: remember})
	if err != nil {
		t.Fatal("genuine MFA browser preparation", err)
	}
	flow, err := owner.IssueFlow(ctx, prepared)
	if err != nil {
		t.Fatal("genuine MFA browser issuance", err)
	}
	flowSpec, _ := flow.Flow.Bindings()
	// Transport owns the original revealed cookie. Each submitted request
	// reparses it into fresh local custody, as the real HTTP boundary does.
	cookie, err := flow.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	browserToken, err := session.ParseToken(cookie)
	if err != nil {
		t.Fatal(err)
	}
	optionsID, _ := identity.NewCommandID()
	input := native.SigninRequest{CommandID: optionsID, FlowID: flowSpec.Binding.ID, Cookie: browserToken, Identifier: "registered@example.invalid", Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1", Device: "reference-passkey-totp", CorrelationID: "reference-passkey-totp"}
	discovery := native.DiscoverableSigninRequest{CommandID: optionsID, FlowID: input.FlowID, Cookie: input.Cookie, Origin: input.Origin, Network: input.Network, Device: input.Device, CorrelationID: input.CorrelationID}
	var options webauthn.AssertionOptions
	if discoverable {
		options, err = owner.DiscoverableAuthenticationOptions(ctx, discovery)
	} else {
		options, err = owner.AuthenticationOptions(ctx, input)
	}
	if err != nil {
		t.Fatal("genuine enrolled-factor assertion options", err)
	}
	ceremony, _ := options.Ceremony()
	primaryID, _ := identity.NewCommandID()
	input.CommandID, discovery.CommandID = primaryID, primaryID
	response := referencePasskeyAssertion(t, key, id, credential.UserHandle, referencePasskeyChallenge(t, ctx, options.TransferJSON))
	var challenge native.SigninResult
	if discoverable {
		challenge, err = owner.DiscoverableSignin(ctx, native.DiscoverableSigninCompletion{DiscoverableSigninRequest: discovery, CeremonyID: ceremony.ID, Response: response})
	} else {
		challenge, err = owner.Signin(ctx, native.SigninCompletion{SigninRequest: input, CeremonyID: ceremony.ID, Response: response})
	}
	if err != nil || challenge.Challenge == nil || challenge.Challenge.Method != "totp" || challenge.Receipt.Outcome != identity.CommitOutcomeCommitted || challenge.Session.Token != (session.Token{}) || challenge.CSRF != (session.CSRFToken{}) {
		t.Fatal("genuine assertion did not produce only the original independent-factor challenge", err)
	}
	defer func() {
		_ = challenge.Challenge.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	}()
	completion, err := features.PasskeyTOTP()
	if err != nil {
		t.Fatal("selected real passkey TOTP owner unavailable", err)
	}
	command, _ := identity.NewCommandID()
	code, _ := auth.NewOneTimeCode(passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second)))
	request := mfa.TotpVerifyRequest{TenantID: otpTenant, CommandID: command, ChallengeID: mfa.ChallengeID(challenge.Challenge.ID), FactorID: factor, Proof: challenge.Challenge.Proof, Code: code, PreAuthID: input.FlowID, Cookie: auth.NewBearerCredential(cookie), Origin: input.Origin, Callback: c.Passkey.Flow.CallbackURL, Network: input.Network, Device: input.Device, Caller: authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(challenge.Challenge.ID)}}}}
	if request.Validate() != nil {
		t.Fatal("real native completion fixture is structurally invalid")
	}
	rate := completion.(interface {
		TotpVerificationRateSource(context.Context, mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error)
	})
	if subject, challengeID, lifetime, err := rate.TotpVerificationRateSource(ctx, request); err != nil || subject != user || challengeID != string(request.ChallengeID) || lifetime <= 0 || lifetime > time.Minute {
		t.Fatalf("genuine primary did not admit original completion rate source: %T", err)
	}
	type effects struct{ attempts, uses, sessions, charges, consumedFlows int }
	observe := func() effects {
		t.Helper()
		var e effects
		if err := f.pool.Raw().QueryRow(ctx, `SELECT c.attempts_remaining,(SELECT uses FROM public.capability_identity_one_use WHERE tenant_id=c.tenant_id AND capability_id=c.continuation_id),(SELECT count(*) FROM session_store.session_issuances WHERE purpose='identity.mfa.totp-verify'),(SELECT count(*) FROM risk_store.counter_charges WHERE operation='identity.mfa.totp-verify'),(SELECT count(*) FROM session_store.preauth_transactions f JOIN identity.commands j ON j.command_id=f.command_id AND j.tenant_id=f.tenant_id JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose WHERE f.tenant_id=c.tenant_id AND f.flow_id=c.source_preauth_id AND f.state='consumed' AND j.purpose='identity.mfa.totp-verify' AND j.state='committed' AND j.generation=f.generation AND k.fingerprint=f.fingerprint AND NOT k.retired) FROM identity_mfa.continuations c WHERE c.tenant_id=$1 AND c.continuation_id=$2`, otpTenant, string(request.ChallengeID)).Scan(&e.attempts, &e.uses, &e.sessions, &e.charges, &e.consumedFlows); err != nil {
			t.Fatal("native completion effect observation unavailable", err)
		}
		return e
	}
	before := observe()
	foreign := request
	foreign.CommandID, _ = identity.NewCommandID()
	foreign.Cookie = auth.NewBearerCredential(strings.Repeat("A", 43))
	var denied identity.ForbiddenError
	if result, err := completion.TotpVerify(ctx, foreign); !errors.As(err, &denied) || result.Session.Token != (session.Token{}) {
		t.Fatal("foreign browser completed passkey TOTP")
	}
	if after := observe(); after != before {
		t.Fatal("foreign browser spent native factor/counter authority", before, after)
	}
	blocked := request
	blocked.CommandID, _ = identity.NewCommandID()
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user)); err != nil {
		t.Fatal("block current native account", err)
	}
	blockedResult, blockedError := completion.TotpVerify(ctx, blocked)
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user)); err != nil {
		t.Fatal("restore owned account fault injection", err)
	}
	if !errors.As(blockedError, &denied) || blockedResult.Session.Token != (session.Token{}) || blockedResult.CSRFToken != (session.CSRFToken{}) || observe() != before {
		t.Fatal("blocked original account retained MFA/session authority or spent a budget")
	}
	wrong := request
	wrong.CommandID, _ = identity.NewCommandID()
	bad := "000000"
	for candidate := 0; ; candidate++ {
		bad = fmt.Sprintf("%06d", candidate)
		matches := false
		for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
			matches = matches || bad == passwordMFAFixtureCode(secret, time.Now().Add(offset))
		}
		if !matches {
			break
		}
	}
	wrong.Code, _ = auth.NewOneTimeCode(bad)
	if result, err := completion.TotpVerify(ctx, wrong); !errors.As(err, &denied) || result.Session.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) {
		t.Fatalf("wrong code did not produce a credential-free native denial: %T", err)
	}
	if after := observe(); after.attempts != before.attempts-1 || after.uses != before.uses || after.sessions != before.sessions || after.charges != before.charges+1 || after.consumedFlows != before.consumedFlows {
		t.Fatal("wrong code did not atomically charge one native attempt", before, after)
	}
	result, err := completion.TotpVerify(ctx, request)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Session.Token == (session.Token{}) || result.CSRFToken == (session.CSRFToken{}) {
		t.Fatal("genuine assertion -> real TOTP -> committed session failed", err)
	}
	record, err := result.Session.Session.Bindings()
	metadata, metadataErr := result.Session.Session.MFAAuthentication().Bindings()
	if err != nil || metadataErr != nil || record.UserID != user || record.Authentication.Proof.Method != "passkey" || metadata.Method != "totp" || metadata.PrimaryCommandID != primaryID || metadata.CommandID != request.CommandID {
		t.Fatal("completion changed original primary or independent factor")
	}
	if retry, err := completion.TotpVerify(ctx, request); err != nil || retry.Outcome != identity.CommitOutcomeCommitted || !retry.Session.Replayed || retry.Session.Token != (session.Token{}) || retry.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("exact passkey TOTP retry redelivered authentication", err)
	}
	query := identity.RecoveryQuery{TenantID: otpTenant, CommandID: request.CommandID, AnonymousFlowID: string(input.FlowID), ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.mfa.totp-verify"}
	if recovered, err := completion.RecoverTotpVerify(ctx, query, request.Caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("original passkey TOTP recovery lost outcome or disclosed credentials", err)
	}
	if after := observe(); after.attempts != before.attempts-2 || after.uses != 1 || after.sessions != before.sessions+1 || after.charges != before.charges+2 || after.consumedFlows != before.consumedFlows+1 {
		t.Fatal("completion/retry/recovery did not preserve one native child/session effect", before, after)
	}
	reuse, _ := session.ParseToken(cookie)
	input.CommandID, _ = identity.NewCommandID()
	input.Cookie = reuse
	if _, err := owner.AuthenticationOptions(ctx, input); err == nil {
		t.Fatal("completed browser started another assertion ceremony")
	}
	csrfWire, _ := result.CSRFToken.Reveal()
	issuedCookie := result.Session.Cookie
	issuedCookie.Value, err = result.Session.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if c.Passkey.SessionManagement != nil {
		// The genuine signin assertion consumed counter1. This next assertion
		// must advance the same synthetic authenticator, not replay its counter.
		proveReferenceSessionRename(t, ctx, features, c, user, issuedCookie.Value, csrfWire, key, id, credential.UserHandle, 2)
	}
	if c.Passkey.SessionEnrollment != nil {
		token, _ := session.ParseToken(issuedCookie.Value)
		browserCredential, err := session.NewCredential(session.CredentialCookie, token)
		if err != nil {
			t.Fatal(err)
		}
		csrf, _ := session.ParseCSRFToken(csrfWire)
		enrollment, err := owner.SessionEnrollment()
		if err != nil {
			t.Fatal(err)
		}
		caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "mfa-enrollment-withdrawal", Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.passkey.register-options", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
		withdrawn := passkey.NewSessionEnrollmentRequest(passkey.SessionEnrollmentRequestSpec{Credential: browserCredential, CSRFToken: csrf, Caller: caller, Label: "Additional reference key", Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1"})
		for _, table := range []string{"factor_authorities", "totp_factors"} {
			column := "version"
			if table == "totp_factors" {
				column = "enrollment_version"
			}
			// Controlled withdrawal uses only this owned account's real rows.
			if _, err := f.pool.Raw().Exec(ctx, "UPDATE identity_mfa."+table+" SET "+column+"="+column+"+1 WHERE tenant_id=$1 AND user_id=$2", otpTenant, string(user)); err != nil {
				t.Fatal(err)
			}
			key, _ := identity.NewIdempotencyKey([]byte("mfa-enrollment-withdrawal-" + table))
			out, denied := enrollment.EnrollmentAssertionOptions(ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: withdrawn, IdempotencyKey: key})
			if _, err := f.pool.Raw().Exec(ctx, "UPDATE identity_mfa."+table+" SET "+column+"="+column+"-1 WHERE tenant_id=$1 AND user_id=$2", otpTenant, string(user)); err != nil {
				t.Fatal(err)
			}
			if _, options := out.Options.Ceremony(); denied == nil || out.CommandID != "" || options {
				t.Fatal("withdrawn original MFA authority admitted enrollment", table)
			}
		}
		proveReferenceSessionEnrollment(t, ctx, features, c, nil, user, issuedCookie.Value, csrfWire, key, id, credential.UserHandle, 2, func(second crypto.Signer, secondID []byte, secondMetadata passkey.CredentialMetadata) {
			if c.Passkey.SessionDeletion != nil {
				finish := referenceRemovalTOTPCompletion(t, ctx, f, features, c, user, factor, secret, discoverable)
				proveReferenceSessionDeletion(t, ctx, features, c, sessionHandler, user, issuedCookie.Value, csrfWire, key, id, credential.UserHandle, 2, second, secondID, secondMetadata, finish)
				return
			}
			// The new credential must be usable, but may not bypass the account's
			// independent factor. Exercise the actual selected primary owner.
			flowID, _ := identity.NewCommandID()
			prepared, err := owner.PrepareFlow(ctx, session.PreAuthPrepareInput{CommandID: flowID, TenantID: otpTenant, CorrelationID: "additional-key-mfa", Remember: remember})
			if err != nil {
				t.Fatal(err)
			}
			flow, err := owner.IssueFlow(ctx, prepared)
			if err != nil {
				t.Fatal(err)
			}
			flowSpec, _ := flow.Flow.Bindings()
			wire, err := flow.Token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			cookie, _ := session.ParseToken(wire)
			command, _ := identity.NewCommandID()
			r := native.SigninRequest{CommandID: command, FlowID: flowSpec.Binding.ID, Cookie: cookie, Identifier: "registered@example.invalid", Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1", Device: "additional-key-mfa", CorrelationID: "additional-key-mfa"}
			discovery := native.DiscoverableSigninRequest{CommandID: r.CommandID, FlowID: r.FlowID, Cookie: r.Cookie, Origin: r.Origin, Network: r.Network, Device: r.Device, CorrelationID: r.CorrelationID}
			var options webauthn.AssertionOptions
			if discoverable {
				options, err = owner.DiscoverableAuthenticationOptions(ctx, discovery)
			} else {
				options, err = owner.AuthenticationOptions(ctx, r)
			}
			if err != nil {
				t.Fatal("new key MFA options", err)
			}
			ceremony, ok := options.Ceremony()
			if !ok {
				t.Fatal("new key assertion options absent")
			}
			r.CommandID, _ = identity.NewCommandID()
			discovery.CommandID = r.CommandID
			response := referencePasskeyAssertion(t, second, secondID, credential.UserHandle, referencePasskeyChallenge(t, ctx, options.TransferJSON), 1)
			var out native.SigninResult
			if discoverable {
				out, err = owner.DiscoverableSignin(ctx, native.DiscoverableSigninCompletion{DiscoverableSigninRequest: discovery, CeremonyID: ceremony.ID, Response: response})
			} else {
				out, err = owner.Signin(ctx, native.SigninCompletion{SigninRequest: r, CeremonyID: ceremony.ID, Response: response})
			}
			if err != nil || out.Challenge == nil || out.Challenge.Method != "totp" || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Session.Token != (session.Token{}) || out.CSRF != (session.CSRFToken{}) {
				t.Fatal("additional credential bypassed or lost independent MFA", err)
			}
			_ = out.Challenge.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		})
	}
	if c.Passkey.SessionDeletion != nil {
		// The genuine removal helper already proves old-session denial and
		// surviving-key TOTP completion, original recovery and read/logout.
		return
	}
	proveRegistrationSessionLogout(t, ctx, client, base, logoutOrigin, []*http.Cookie{&issuedCookie}, csrfWire, record.SessionID, f, features)
}
