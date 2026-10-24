//go:build integration

package reference_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
)

func TestReferencePostgresPasskeySignup(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySignup: true, passkeyUpgrade: upgrade, passkeyDiscovery: true, passkeySessionHTTP: true}, true)
		})
	}
}

func proveReferencePasskeySignupReadiness(t *testing.T, ctx context.Context, server *reference.Server, pool *database.Pool) {
	t.Helper()
	if status := server.Readiness(ctx); !status.Ready {
		t.Fatal("selected signup readiness", status.Failures)
	}
	for _, fence := range []struct{ table, constraint string }{
		{"session_store.session_issuances", "session_issuances_purpose_passkey_signup_v1"},
		{"identity_mfa.factor_authorities", "factor_authorities_initialized_purpose_v4"},
		{"identity.registration_bindings", "identity_registration_purpose_v4"},
		{"identity.registration_bindings", "identity_registration_disposition_v4"},
	} {
		t.Run(fence.constraint, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, "ALTER TABLE "+fence.table+" RENAME CONSTRAINT "+fence.constraint+" TO signup_fixture_missing"); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := pool.Raw().Exec(ctx, "ALTER TABLE "+fence.table+" RENAME CONSTRAINT signup_fixture_missing TO "+fence.constraint); err != nil {
					t.Fatal("restore signup readiness fence", err)
				}
			}()
			if status := server.Readiness(ctx); status.Ready {
				t.Fatal("signup readiness accepted missing selected fence")
			}
		})
	}
	if status := server.Readiness(ctx); !status.Ready {
		t.Fatal("restored signup readiness", status.Failures)
	}
}

func proveReferencePasskeySignup(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, pool *database.Pool) {
	t.Helper()
	owner, err := features.Passkeys()
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	command, _ := identity.NewCommandID()
	prepared, err := owner.PrepareSignupFlow(ctx, session.PreAuthPrepareInput{CommandID: command, TenantID: otpTenant, CorrelationID: "reference-passkey-signup", Remember: remember})
	if err != nil {
		t.Fatal("reference signup preparation", err)
	}
	flow, err := owner.IssueSignupFlow(ctx, prepared)
	if err != nil {
		t.Fatal("reference signup flow", err)
	}
	original, err := flow.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	request := passkey.SignupRequest{FlowID: original.Binding.ID, Cookie: flow.Token, Origin: c.Passkey.Signup.Flow.Origin, Network: "127.0.0.1", Device: "reference-signup-browser"}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.Passkey.Signup.Flow.ActorID)}, Action: "identity.passkey.register-options", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(request.FlowID)}}}
	key, _ := identity.NewIdempotencyKey([]byte("reference-passkey-signup-options"))
	var before int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	keyed := passkey.KeyedSignupOptionsRequest{SignupRequest: request, IdempotencyKey: key, Caller: caller}
	options, err := owner.KeyedSignupOptions(ctx, keyed)
	if err != nil {
		t.Fatal("reference keyed signup options", err)
	}
	ceremony, present := options.Options.Ceremony()
	if !present || ceremony.Intent.Context.UserID == "" || options.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original prospective signup ceremony absent")
	}
	var after int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users`).Scan(&after); err != nil || after != before {
		t.Fatal("options created an account before proof", err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	response := referencePasskeyRegistration(t, private, id, referencePasskeyChallenge(t, ctx, options.Options.TransferJSON))
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(response, &wire); err != nil {
		t.Fatal(err)
	}
	wire["clientExtensionResults"] = json.RawMessage(`{"credProps":{"rk":true}}`)
	response, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	request.CommandID, _ = identity.NewCommandID()
	request.CorrelationID = string(request.CommandID)
	completion := passkey.SignupCompletion{SignupRequest: request, CeremonyID: ceremony.ID, Response: response, Label: "Reference signup key"}
	foreign := completion
	foreign.Cookie, _ = session.NewToken(32)
	if got, err := owner.Signup(ctx, foreign); err == nil || got.Session.Token != (session.Token{}) {
		t.Fatal("foreign browser received signup session")
	}
	issued, err := owner.Signup(ctx, completion)
	if err != nil || issued.Session.CommitOutcome != identity.CommitOutcomeCommitted || issued.Session.Replayed {
		t.Fatal("reference signup completion", err)
	}
	spec, err := issued.Session.Session.Bindings()
	if err != nil || spec.UserID != ceremony.Intent.Context.UserID {
		t.Fatal("reference signup changed prospective identity", err)
	}
	var events, identifiers, passwords int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$1 AND topic IN ('identity.passkey.create_credential','user.created.v1','session.created.v1')),(SELECT count(*) FROM identity.identifiers WHERE user_id=$2),(SELECT count(*) FROM identity_password.credentials WHERE user_id=$2)`, string(request.CommandID), string(spec.UserID)).Scan(&events, &identifiers, &passwords); err != nil || events != 3 || identifiers != 0 || passwords != 0 {
		t.Fatal("reference signup lost atomic effects or invented fallback", err, events, identifiers, passwords)
	}
	if replay, err := owner.Signup(ctx, completion); err == nil || replay.Session.Token != (session.Token{}) || replay.CSRF != (session.CSRFToken{}) {
		t.Fatal("signup replay delivered authentication")
	}
	if replay, err := owner.KeyedSignupOptions(ctx, keyed); err != nil || !replay.Replayed || replay.CommandID != options.CommandID {
		t.Fatal("consumed signup lost original options metadata", err)
	} else if _, present := replay.Options.Ceremony(); present {
		t.Fatal("signup retry revealed another challenge")
	}
	caller.Request.Action = "identity.passkey.register-verify"
	if recovered, err := owner.RecoverSignup(ctx, request, ceremony.ID, caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding.CommandID != request.CommandID {
		t.Fatal("reference original signup recovery", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, issued.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	common, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	read := session.GetRequest{TenantID: otpTenant, Credential: credential}
	if got, err := common.Get(ctx, read); err != nil || !got.Authenticated {
		t.Fatal("common session cannot read actual signup", err)
	}
	wrong := read
	wrong.TenantID = "foreign-tenant"
	if got, err := owner.Get(ctx, wrong); err == nil || got.Authenticated {
		t.Fatal("foreign tenant read signup")
	}
	logoutID, _ := identity.NewCommandID()
	logout := session.SignOutRequest{TenantID: otpTenant, CommandID: logoutID, CorrelationID: "reference-signup-logout", Transport: session.CredentialCookie, Credential: credential}
	if got, err := owner.SignOut(ctx, logout, issued.CSRF); err != nil || !got.SignedOut {
		t.Fatal("reference signup logout", err)
	}
	if got, err := common.Get(ctx, read); err != nil || got.Authenticated {
		t.Fatal("signup session survived logout", err)
	}
	command, _ = identity.NewCommandID()
	signinPrepared, err := owner.PrepareFlow(ctx, session.PreAuthPrepareInput{CommandID: command, TenantID: otpTenant, CorrelationID: "reference-signup-signin", Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	signinFlow, err := owner.IssueFlow(ctx, signinPrepared)
	if err != nil {
		t.Fatal(err)
	}
	signinBinding, err := signinFlow.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	command, _ = identity.NewCommandID()
	signin := passkey.DiscoverableSigninRequest{CommandID: command, FlowID: signinBinding.Binding.ID, Cookie: signinFlow.Token, Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1", Device: request.Device, CorrelationID: "reference-signup-signin"}
	assertion, err := owner.DiscoverableAuthenticationOptions(ctx, signin)
	if err != nil {
		t.Fatal("signup fresh discoverable options", err)
	}
	assertionCeremony, present := assertion.Ceremony()
	if !present {
		t.Fatal("signup fresh assertion missing")
	}
	signin.CommandID, _ = identity.NewCommandID()
	fresh, err := owner.DiscoverableSignin(ctx, passkey.DiscoverableSigninCompletion{DiscoverableSigninRequest: signin, CeremonyID: assertionCeremony.ID, Response: referencePasskeyAssertion(t, private, id, ceremony.Intent.UserHandle, referencePasskeyChallenge(t, ctx, assertion.TransferJSON))})
	if err != nil {
		t.Fatal("fresh signup identity signin", err)
	}
	freshSpec, err := fresh.Session.Session.Bindings()
	if err != nil || freshSpec.UserID != spec.UserID || freshSpec.SessionID == spec.SessionID {
		t.Fatal("fresh signin changed signup identity", err)
	}
	freshCredential, err := session.NewCredential(session.CredentialCookie, fresh.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := common.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: freshCredential}); err != nil || !got.Authenticated {
		t.Fatal("fresh signup signin unreadable", err)
	}
}
