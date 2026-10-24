//go:build integration

package reference_test

import (
	"context"
	"crypto"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// Use only the public graph and original HTTP-issued custody. The controlled
// authenticator signs the actual challenge; no account/proof/store is seeded.
func proveReferenceSessionRename(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, user identity.UserID, bearer, csrf string, key crypto.Signer, id, handle []byte) {
	t.Helper()
	owner, err := features.Passkeys()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := owner.SessionManagement()
	if err != nil {
		t.Fatal("explicit native session management absent", err)
	}
	token, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	synchronizer, err := session.ParseCSRFToken(csrf)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "standalone-session-rename", Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Tenant: authorization.TenantID(otpTenant), Action: "identity.passkey.list", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	attempt, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	listing := passkey.InventoryRequest{Credential: credential, Caller: caller, AttemptID: attempt, Limit: 10}
	page, err := owner.List(ctx, listing)
	if err != nil || len(page.Credentials) != 1 {
		t.Fatal("actual safe native inventory", err)
	}
	caller.Request.Action = "identity.passkey.update"
	r := passkey.SessionUpdateRequest{Credential: credential, CSRFToken: synchronizer, Caller: caller, ReferenceID: identity.CredentialID(page.Credentials[0].ReferenceID), ExpectedVersion: page.Credentials[0].Version, Name: "Passkey-only renamed key", Origin: c.Passkey.Signup.Flow.Origin, Network: "127.0.0.1"}
	optionsKey, err := identity.NewIdempotencyKey([]byte("standalone-rename-options"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"foreign-tenant", "foreign-csrf"} {
		bad := r
		bad.Caller = r.Caller.Clone()
		if mode == "foreign-tenant" {
			bad.Caller.Request.Tenant = "another-tenant"
		} else {
			bad.CSRFToken, err = session.NewCSRFToken()
			if err != nil {
				t.Fatal(err)
			}
		}
		if out, err := manager.UpdateOptions(ctx, passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: bad, IdempotencyKey: optionsKey}); err == nil || out.CommandID != "" {
			t.Fatal("public graph admitted foreign update custody", mode, err)
		}
	}
	options, err := manager.UpdateOptions(ctx, passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: r, IdempotencyKey: optionsKey})
	if err != nil {
		t.Fatal("genuine graph-bound update options", err)
	}
	ceremony, ok := options.Options.Ceremony()
	if !ok {
		t.Fatal("action-bound ceremony absent")
	}
	challenge := referencePasskeyChallenge(t, ctx, options.Options.TransferJSON)
	completionKey, err := identity.NewIdempotencyKey([]byte("standalone-rename-completion"))
	if err != nil {
		t.Fatal(err)
	}
	completion := passkey.SessionUpdateCompletion{SessionUpdateRequest: r, IdempotencyKey: completionKey, CeremonyID: ceremony.ID, Response: referencePasskeyAssertion(t, key, id, handle, challenge)}
	out, err := manager.Update(ctx, completion)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || out.Credential == nil || out.Credential.Label != r.Name || out.Credential.Version != r.ExpectedVersion+1 {
		t.Fatal("public graph did not atomically rename", err)
	}
	retry, err := manager.Update(ctx, completion)
	if err != nil || !retry.Replayed || retry.CommandID != out.CommandID || retry.Credential != nil || retry.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("public graph lost metadata-only original retry", err)
	}
	listing.AttemptID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	page, err = owner.List(ctx, listing)
	if err != nil || len(page.Credentials) != 1 || page.Credentials[0].Label != r.Name || page.Credentials[0].Version != r.ExpectedVersion+1 {
		t.Fatal("renamed graph inventory did not preserve current session", err)
	}
}
