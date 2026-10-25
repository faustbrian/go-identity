//go:build integration

package reference_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// The original account and cookie come from genuine HTTP passkey-only signup.
// Only the external authenticator is controlled; all graph/domain owners and
// discovery/session/logout operations remain real and public.
func proveReferenceSessionEnrollment(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, handler http.Handler, user identity.UserID, bearer, csrf string, firstKey crypto.Signer, firstID, handle []byte, firstCounter uint32, after ...func(crypto.Signer, []byte, passkey.CredentialMetadata)) {
	t.Helper()
	owner, err := features.Passkeys()
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := owner.SessionEnrollment()
	if err != nil {
		t.Fatal("selected native enrollment handle absent", err)
	}
	token, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(c.Passkey.SessionEnrollment.Transport, token)
	if err != nil {
		t.Fatal(err)
	}
	var synchronizer session.CSRFToken
	if c.Passkey.SessionEnrollment.Transport == session.CredentialCookie {
		synchronizer, err = session.ParseCSRFToken(csrf)
		if err != nil {
			t.Fatal(err)
		}
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "standalone-additional-enrollment", Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Tenant: authorization.TenantID(otpTenant), Action: "identity.passkey.register-options", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	origin := c.Passkey.Flow.Origin
	if c.Passkey.Signup != nil {
		origin = c.Passkey.Signup.Flow.Origin
	}
	intent := passkey.SessionEnrollmentRequestSpec{Credential: credential, CSRFToken: synchronizer, Caller: caller, Label: "Additional reference key", Origin: origin, Network: "127.0.0.1"}
	keyA, err := identity.NewIdempotencyKey([]byte("reference-enrollment-A"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"foreign-tenant", "foreign-csrf"} {
		r := intent
		r.Caller = r.Caller.Clone()
		if mode == "foreign-tenant" {
			r.Caller.Request.Tenant = "foreign"
		} else {
			r.CSRFToken, err = session.NewCSRFToken()
			if err != nil {
				t.Fatal(err)
			}
		}
		out, err := enrollment.EnrollmentAssertionOptions(ctx, passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(r), IdempotencyKey: keyA})
		if err == nil || out.CommandID != "" {
			t.Fatal("foreign custody reached native enrollment", mode, err)
		}
	}
	request := passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), IdempotencyKey: keyA}
	a, err := enrollment.EnrollmentAssertionOptions(ctx, request)
	if err != nil || a.Replayed || a.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("graph did not issue genuine enrollment assertion options", err)
	}
	aCeremony, ok := a.Options.Ceremony()
	if !ok {
		t.Fatal("enrollment assertion options absent")
	}
	aChallenge := referencePasskeyChallenge(t, ctx, a.Options.TransferJSON)
	if out, err := enrollment.EnrollmentAssertionOptions(ctx, request); err != nil || !out.Replayed || out.CommandID != a.CommandID {
		t.Fatal("graph lost original assertion retry", err)
	} else if _, present := out.Options.Ceremony(); present {
		t.Fatal("graph replay revealed replacement assertion")
	}
	keyB, err := identity.NewIdempotencyKey([]byte("reference-enrollment-B"))
	if err != nil {
		t.Fatal(err)
	}
	approved := passkey.NewSessionEnrollmentAuthorization(passkey.SessionEnrollmentAuthorizationSpec{SessionEnrollmentRequest: request.SessionEnrollmentRequest, IdempotencyKey: keyB, CeremonyID: aCeremony.ID, Response: referencePasskeyAssertion(t, firstKey, firstID, handle, aChallenge, firstCounter)})
	b, expiry, err := enrollment.RegistrationOptionsForDelivery(ctx, approved)
	if err != nil || b.Replayed || b.Receipt.Outcome != identity.CommitOutcomeCommitted || !expiry.Equal(aCeremony.ExpiresAt) {
		t.Fatal("genuine session UV did not authorize registration through graph", err)
	}
	bCeremony, ok := b.Options.Ceremony()
	if !ok || !bCeremony.ExpiresAt.After(expiry) {
		t.Fatal("authorized registration options absent")
	}
	bChallenge := referencePasskeyChallenge(t, ctx, b.Options.TransferJSON)
	if out, err := enrollment.RegistrationOptions(ctx, approved); err != nil || !out.Replayed || out.CommandID != b.CommandID {
		t.Fatal("graph lost original authorization retry", err)
	} else if _, present := out.Options.Ceremony(); present {
		t.Fatal("graph replay revealed replacement registration")
	}
	secondKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondID := make([]byte, 32)
	if _, err := rand.Read(secondID); err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	intent.Caller = intent.Caller.Clone()
	intent.Caller.Request.Action = "identity.passkey.register-verify"
	source, err := enrollment.SessionRegistrationRateSource(ctx, passkey.NewSessionEnrollmentRequest(intent), bCeremony.ID)
	if err != nil || source.CeremonyID != bCeremony.ID || source.Kind != passkey.RateSourceUser || source.UserID != user || source.Identifier != "" || source.AnonymousFlowID != "" {
		t.Fatal("graph lost original authenticated rate metadata", err)
	}
	completion := passkey.NewSessionEnrollmentCompletion(passkey.SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: passkey.NewSessionEnrollmentRequest(intent), CommandID: command, CeremonyID: bCeremony.ID, Response: referencePasskeyRegistration(t, secondKey, secondID, bChallenge)})
	out, err := enrollment.Register(ctx, completion)
	if err != nil {
		t.Fatal("graph did not persist second actual credential", err)
	}
	fields, err := out.Bindings()
	if err != nil || fields.Replayed || fields.Outcome != identity.CommitOutcomeCommitted || fields.Credential == nil || fields.Credential.Label != intent.Label {
		t.Fatal("second credential committed metadata absent", err)
	}
	retry, err := enrollment.Register(ctx, completion)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := retry.Bindings()
	if err != nil || !replayed.Replayed || replayed.CommandID != command || replayed.Credential != nil {
		t.Fatal("graph repeated enrollment or lost original C metadata", err)
	}
	caller = caller.Clone()
	caller.Request.Action = "identity.passkey.list"
	attempt, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	page, err := owner.List(ctx, passkey.InventoryRequest{Credential: credential, Caller: caller, AttemptID: attempt, Limit: 10})
	if err != nil || len(page.Credentials) != 2 {
		t.Fatal("original session cannot inspect both enrolled credentials", err)
	}
	if len(after) != 0 {
		// A successor journey continues with this genuine registration and its
		// original session, rather than seeding keys or inventing fresh authority.
		after[0](secondKey, secondID, *fields.Credential)
		return
	}
	for _, authenticator := range []struct {
		key     crypto.Signer
		id      []byte
		counter uint32
	}{{firstKey, firstID, firstCounter + 1}, {secondKey, secondID, 1}} {
		flowCommand, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		remember, err := session.ResolveRememberPolicy(session.BrowserSession, c.HTTPPreAuth.Lifetime)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := owner.PrepareFlow(ctx, session.PreAuthPrepareInput{CommandID: flowCommand, TenantID: otpTenant, CorrelationID: "enrollment-key-signin", Remember: remember})
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
		optionsID, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		r := passkey.DiscoverableSigninRequest{CommandID: optionsID, FlowID: flow.Binding.ID, Cookie: issued.Token, Origin: c.Passkey.Flow.Origin, Network: "127.0.0.1", Device: "reference-passkey", CorrelationID: "enrollment-key-signin"}
		options, err := owner.DiscoverableAuthenticationOptions(ctx, r)
		if err != nil {
			t.Fatal("either key discovery options", err)
		}
		ceremony, ok := options.Ceremony()
		if !ok {
			t.Fatal("genuine discovery ceremony absent")
		}
		challenge := referencePasskeyChallenge(t, ctx, options.TransferJSON)
		r.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		signedIn, err := owner.DiscoverableSignin(ctx, passkey.DiscoverableSigninCompletion{DiscoverableSigninRequest: r, CeremonyID: ceremony.ID, Response: referencePasskeyAssertion(t, authenticator.key, authenticator.id, handle, challenge, authenticator.counter)})
		if err != nil {
			t.Fatal("either actual key failed discoverable signin", err)
		}
		bearer, err := signedIn.Session.Token.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		csrf, err := signedIn.CSRF.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		common, err := features.Sessions()
		if err != nil {
			t.Fatal(err)
		}
		read := func() bool {
			t.Helper()
			token, err := session.ParseToken(bearer)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := session.NewCredential(session.CredentialCookie, token)
			if err != nil {
				t.Fatal(err)
			}
			got, err := common.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
			if err != nil {
				t.Fatal(err)
			}
			return got.Authenticated
		}
		proveReferencePasskeySessionHTTP(t, ctx, handler, c, user, bearer, csrf, read)
	}
}
