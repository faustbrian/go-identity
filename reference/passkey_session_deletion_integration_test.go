//go:build integration

package reference_test

import (
	"context"
	"crypto"
	"net/http"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

func TestReferencePostgresPasskeySessionDeletion(t *testing.T) {
	for _, transport := range []struct {
		name string
		kind session.CredentialKind
	}{{"cookie", session.CredentialCookie}, {"bearer", session.CredentialBearer}} {
		t.Run(transport.name, func(t *testing.T) {
			for _, upgrade := range []bool{false, true} {
				t.Run(map[bool]string{false: "fresh", true: "populated-kernel-upgrade"}[upgrade], func(t *testing.T) {
					proveReferencePasskeyStandalone(t, upgrade, standalonePasskeyJourney{enrollment: true, enrollmentTransport: transport.kind, sessionDeletion: true})
				})
			}
		})
	}
}

func referenceRemovalCredential(t *testing.T, kind session.CredentialKind, token, csrf string) (session.Credential, session.CSRFToken) {
	t.Helper()
	parsed, err := session.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(kind, parsed)
	if err != nil {
		t.Fatal(err)
	}
	var synchronizer session.CSRFToken
	if kind == session.CredentialCookie {
		synchronizer, err = session.ParseCSRFToken(csrf)
		if err != nil {
			t.Fatal(err)
		}
	}
	return credential, synchronizer
}

type removalSessionResult struct {
	Session session.IssueResult
	CSRF    session.CSRFToken
}

type removalSessionCompletion struct {
	discoverable bool
	finish       func(passkey.SigninResult, passkey.DiscoverableSigninRequest, string) removalSessionResult
}

func referenceRemovalSignin(t *testing.T, ctx context.Context, owner *reference.PasskeyService, c reference.StoreConfiguration, key crypto.Signer, id, handle []byte, count uint32, finish ...removalSessionCompletion) removalSessionResult {
	t.Helper()
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, c.HTTPPreAuth.Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := owner.PrepareFlow(ctx, session.PreAuthPrepareInput{CommandID: command, TenantID: otpTenant, CorrelationID: "removal-survivor-signin", Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := owner.IssueFlow(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	cookieWire, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	browserCookie, err := session.ParseToken(cookieWire)
	if err != nil {
		t.Fatal(err)
	}
	optionsID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r := passkey.DiscoverableSigninRequest{CommandID: optionsID, FlowID: flow.Binding.ID, Cookie: browserCookie, Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1", Device: "reference-passkey", CorrelationID: "removal-survivor-signin"}
	discoverable := len(finish) == 0 || finish[0].discoverable
	identified := passkey.SigninRequest{CommandID: r.CommandID, FlowID: r.FlowID, Cookie: r.Cookie, Identifier: "registered@example.invalid", Origin: r.Origin, Network: r.Network, Device: r.Device, CorrelationID: r.CorrelationID}
	var options webauthn.AssertionOptions
	if discoverable {
		options, err = owner.DiscoverableAuthenticationOptions(ctx, r)
	} else {
		options, err = owner.AuthenticationOptions(ctx, identified)
	}
	if err != nil {
		t.Fatal("surviving-key discovery options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("surviving-key discovery ceremony absent")
	}
	challenge := referencePasskeyChallenge(t, ctx, options.TransferJSON)
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	identified.CommandID = r.CommandID
	response := referencePasskeyAssertion(t, key, id, handle, challenge, count)
	var out passkey.SigninResult
	if discoverable {
		out, err = owner.DiscoverableSignin(ctx, passkey.DiscoverableSigninCompletion{DiscoverableSigninRequest: r, CeremonyID: ceremony.ID, Response: response})
	} else {
		out, err = owner.Signin(ctx, passkey.SigninCompletion{SigninRequest: identified, CeremonyID: ceremony.ID, Response: response})
	}
	if err != nil {
		t.Fatal("surviving key cannot obtain a genuine new session", err)
	}
	if len(finish) != 0 {
		return finish[0].finish(out, r, cookieWire)
	}
	return removalSessionResult{Session: out.Session, CSRF: out.CSRF}
}

// Signup and both resident keys are created by their actual public owners.
// The controlled external authenticator supplies only genuine protocol crypto.
func proveReferenceSessionDeletion(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, handler http.Handler, user identity.UserID, bearer, csrf string, firstKey crypto.Signer, firstID, handle []byte, firstCounter uint32, secondKey crypto.Signer, secondID []byte, second passkey.CredentialMetadata, finish ...removalSessionCompletion) {
	t.Helper()
	owner, err := features.Passkeys()
	if err != nil {
		t.Fatal(err)
	}
	removal, err := owner.SessionDeletion()
	if err != nil {
		t.Fatal("selected native removal handle absent", err)
	}
	transport := c.Passkey.SessionDeletion.Transport
	credential, synchronizer := referenceRemovalCredential(t, transport, bearer, csrf)
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "standalone-passkey-removal", Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Tenant: authorization.TenantID(otpTenant), Action: "identity.passkey.list", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	attempt, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	page, err := owner.List(ctx, passkey.InventoryRequest{Credential: credential, Caller: caller, AttemptID: attempt, Limit: 10})
	if err != nil || len(page.Credentials) != 2 {
		t.Fatal("genuine two-key inventory unavailable", err)
	}
	target := second
	remainingKey, remainingID, remainingCounter := firstKey, firstID, firstCounter+2
	remaining := page.Credentials[0]
	for _, item := range page.Credentials {
		if item.ReferenceID != second.ReferenceID {
			remaining = item
		}
	}
	if transport == session.CredentialCookie {
		// Exercise the authenticating target for cookies and its sibling for
		// bearer composition; the protocol/native suites cover both independently.
		target, remaining = remaining, second
		remainingKey, remainingID, remainingCounter = secondKey, secondID, 1
	}
	caller.Request.Action = "identity.passkey.delete"
	origin := c.Passkey.Flow.Origin
	if c.Passkey.Signup != nil {
		origin = c.Passkey.Signup.Flow.Origin
	}
	intent := passkey.SessionDeleteRequestSpec{Credential: credential, CSRFToken: synchronizer, Caller: caller, ReferenceID: identity.CredentialID(target.ReferenceID), ExpectedVersion: target.Version, Origin: origin, Network: "127.0.0.1"}
	keyA, _ := identity.NewIdempotencyKey([]byte("reference-removal-A"))
	keyB, _ := identity.NewIdempotencyKey([]byte("reference-removal-B"))
	a := passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(intent), IdempotencyKey: keyA}
	options, err := removal.DeleteOptions(ctx, a)
	if err != nil || options.Replayed || options.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("graph did not issue genuine removal UV options", err)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("original removal challenge absent")
	}
	if retry, err := removal.DeleteOptions(ctx, a); err != nil || !retry.Replayed || retry.CommandID != options.CommandID {
		t.Fatal("graph lost original options retry", err)
	} else if _, disclosed := retry.Options.Ceremony(); disclosed {
		t.Fatal("removal retry disclosed replacement challenge")
	}
	challenge := referencePasskeyChallenge(t, ctx, options.Options.TransferJSON)
	completion := passkey.NewSessionDeleteCompletion(passkey.SessionDeleteCompletionSpec{SessionDeleteRequest: a.SessionDeleteRequest, IdempotencyKey: keyB, CeremonyID: ceremony.ID, Response: referencePasskeyAssertion(t, firstKey, firstID, handle, challenge, firstCounter+1)})
	result, err := removal.Delete(ctx, completion)
	metadata, projected := result.Bindings()
	if err != nil || projected != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.Replayed {
		t.Fatal("graph did not commit exact removal", err)
	}
	common, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := common.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err == nil && got.Authenticated {
		t.Fatal("old passkey session retained removed generation")
	}
	if retry, err := removal.DeleteOptions(ctx, a); err == nil || retry.CommandID != "" {
		t.Fatal("revoked original source regained removal metadata")
	}
	query := identity.RecoveryQuery{CommandID: metadata.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.passkey.delete", RecordID: target.ReferenceID}
	if _, err := removal.RecoverDelete(ctx, a.SessionDeleteRequest, query); err == nil {
		t.Fatal("revoked original source obtained recovery metadata")
	}
	next := referenceRemovalSignin(t, ctx, owner, c, remainingKey, remainingID, handle, remainingCounter, finish...)
	newBearer, err := next.Session.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	newCSRF, err := next.CSRF.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	intent.Credential, intent.CSRFToken = referenceRemovalCredential(t, transport, newBearer, newCSRF)
	recovered, err := removal.RecoverDelete(ctx, passkey.NewSessionDeleteRequest(intent), query)
	observed, projected := recovered.Bindings()
	if err != nil || projected != nil || observed.CommandID != metadata.CommandID || !observed.Replayed || observed.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine surviving-key session lost original recovery metadata", err)
	}
	intent.ReferenceID, intent.ExpectedVersion = identity.CredentialID(remaining.ReferenceID), remaining.Version
	lastKey, err := identity.NewIdempotencyKey([]byte("reference-last-key-removal"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := removal.DeleteOptions(ctx, passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: passkey.NewSessionDeleteRequest(intent), IdempotencyKey: lastKey}); err == nil {
		t.Fatal("graph permitted last independently usable key removal")
	}
	proveReferencePasskeySessionHTTP(t, ctx, handler, c, user, newBearer, newCSRF, func() bool {
		got, err := common.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: intent.Credential})
		if err != nil {
			t.Fatal(err)
		}
		return got.Authenticated
	})
}
