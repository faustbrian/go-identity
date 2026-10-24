//go:build integration

package reference_test

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	passkeyhttp "github.com/faustbrian/go-identity/http/passkey"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

type passkeyDeletionHTTPObservation struct {
	code    int
	header  http.Header
	body    []byte
	cookies []*http.Cookie
}

func TestReferencePostgresPasskeyHTTPSessionDeletion(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-kernel-upgrade"}[upgrade], func(t *testing.T) {
			proveReferencePasskeyStandalone(t, upgrade, standalonePasskeyJourney{enrollment: true, enrollmentTransport: session.CredentialCookie, sessionDeletion: true, httpEnrollment: true, httpDeletion: true})
		})
	}
}

// call/flow are the parent's actual TLS client plus OpenAPI request/result
// validation, not domain doubles. All registration, UV, policy, effects,
// recovery, session reads and logout cross their real graph owners.
func proveReferenceHTTPSessionDeletion(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, handler http.Handler, user identity.UserID, original []*http.Cookie, csrf string, key crypto.Signer, id, handle []byte, counter uint32, first, second passkeyhttp.CredentialMetadata, remainingKey crypto.Signer, remainingID []byte, call func(string, any, string, []*http.Cookie, string, string) passkeyDeletionHTTPObservation, flow func(string) (string, []*http.Cookie)) {
	t.Helper()
	origin := c.Passkey.Signup.Flow.Origin
	intent := map[string]any{"phase": "options", "referenceID": first.ReferenceID, "expectedVersion": first.Version}
	for _, denied := range []struct{ csrf, origin string }{{strings.Repeat("A", 43), origin}, {csrf, "https://foreign.example"}} {
		got := call("/v1/passkey/delete", intent, "http-removal-denied-A", original, denied.csrf, denied.origin)
		if got.code != 403 {
			t.Fatal("removal ignored original cookie synchronizer/Origin", got.code)
		}
	}
	options := call("/v1/passkey/delete", intent, "http-removal-A", original, csrf, origin)
	var assertion struct {
		CommandID identity.CommandID `json:"commandID"`
		Replayed  bool               `json:"replayed"`
		Options   json.RawMessage    `json:"options"`
	}
	if options.code != 200 || json.Unmarshal(options.body, &assertion) != nil || assertion.CommandID == "" || assertion.Replayed || len(assertion.Options) == 0 || len(options.cookies) != 0 || options.header.Get("X-CSRF-Token") != "" {
		t.Fatal("actual HTTP removal UV options absent", options.code)
	}
	retry := call("/v1/passkey/delete", intent, "http-removal-A", original, csrf, origin)
	var replay = assertion
	replay.Options = nil
	if retry.code != 200 || json.Unmarshal(retry.body, &replay) != nil || !replay.Replayed || replay.CommandID != assertion.CommandID || len(replay.Options) != 0 {
		t.Fatal("removal options retry renewed a challenge", retry.code)
	}
	challenge := referencePasskeyChallenge(t, ctx, func(ctx context.Context, transfer func(context.Context, []byte) error) error {
		return transfer(ctx, assertion.Options)
	})
	intent["phase"], intent["ceremonyID"], intent["response"] = "complete", assertion.CommandID, json.RawMessage(referencePasskeyAssertion(t, key, id, handle, challenge, counter+1))
	intent["expectedVersion"] = first.Version + 1
	if denied := call("/v1/passkey/delete", intent, "http-removal-stale-B", original, csrf, origin); denied.code != 409 {
		t.Fatal("HTTP removal silently rebased target metadata", denied.code)
	}
	intent["expectedVersion"] = first.Version
	completed := call("/v1/passkey/delete", intent, "http-removal-B", original, csrf, origin)
	var result passkeyhttp.DeleteResponse
	if completed.code != 200 || json.Unmarshal(completed.body, &result) != nil || result.CommandID == "" || result.Replayed || result.CommitOutcome != "committed" || len(completed.cookies) != 0 || completed.header.Get("X-CSRF-Token") != "" {
		t.Fatal("HTTP genuine removal did not commit", completed.code)
	}
	common, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	oldCredential, _ := referenceRemovalCredential(t, session.CredentialCookie, original[0].Value, csrf)
	if got, err := common.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: oldCredential}); err == nil && got.Authenticated {
		t.Fatal("HTTP removal left original passkey session usable")
	}
	if denied := call("/v1/passkey/delete", intent, "http-removal-B", original, csrf, origin); denied.code != 401 || len(denied.cookies) != 0 || denied.header.Get("X-CSRF-Token") != "" {
		t.Fatal("invalidated HTTP source repeated removal or recovered metadata", denied.code)
	}
	recovery := map[string]any{"phase": "recover", "referenceID": first.ReferenceID, "expectedVersion": first.Version, "commandID": result.CommandID}
	if denied := call("/v1/passkey/delete", recovery, "http-removal-B", original, csrf, origin); denied.code != 401 {
		t.Fatal("invalidated HTTP source regained recovery authority", denied.code)
	}
	removedFlow, removedCookies := flow("passkey")
	removedOptions := call("/v1/passkey/signin-options", map[string]any{"mode": "discoverable", "flowID": removedFlow}, "http-removal-revoked-options", removedCookies, "", origin)
	var removedAssertion = assertion
	removedAssertion.Options = nil
	if removedOptions.code != 200 || json.Unmarshal(removedOptions.body, &removedAssertion) != nil || len(removedAssertion.Options) == 0 {
		t.Fatal("removed-key discovery exposed account existence", removedOptions.code)
	}
	removedChallenge := referencePasskeyChallenge(t, ctx, func(ctx context.Context, transfer func(context.Context, []byte) error) error {
		return transfer(ctx, removedAssertion.Options)
	})
	removedCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	removedSignin := call("/v1/passkey/signin-verify", map[string]any{"mode": "discoverable", "flowID": removedFlow, "commandID": removedCommand, "ceremonyID": removedAssertion.CommandID, "response": json.RawMessage(referencePasskeyAssertion(t, key, id, handle, removedChallenge, counter+2))}, "", removedCookies, "", origin)
	if removedSignin.code < 400 || len(removedSignin.cookies) != 0 || removedSignin.header.Get("X-CSRF-Token") != "" {
		t.Fatal("removed authenticator issued fresh HTTP authentication", removedSignin.code)
	}
	flowID, flowCookies := flow("passkey")
	options = call("/v1/passkey/signin-options", map[string]any{"mode": "discoverable", "flowID": flowID}, "http-removal-survivor-options", flowCookies, "", origin)
	assertion.Options = nil
	if options.code != 200 || json.Unmarshal(options.body, &assertion) != nil || assertion.Replayed || len(assertion.Options) == 0 {
		t.Fatal("surviving-key HTTP discovery options", options.code)
	}
	challenge = referencePasskeyChallenge(t, ctx, func(ctx context.Context, transfer func(context.Context, []byte) error) error {
		return transfer(ctx, assertion.Options)
	})
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	signedIn := call("/v1/passkey/signin-verify", map[string]any{"mode": "discoverable", "flowID": flowID, "commandID": command, "ceremonyID": assertion.CommandID, "response": json.RawMessage(referencePasskeyAssertion(t, remainingKey, remainingID, handle, challenge, 1))}, "", flowCookies, "", origin)
	var login struct {
		SignedIn bool `json:"signedIn"`
	}
	if signedIn.code != 200 || json.Unmarshal(signedIn.body, &login) != nil || !login.SignedIn || len(signedIn.cookies) != 1 || signedIn.header.Get("X-CSRF-Token") == "" {
		t.Fatal("surviving key cannot obtain a genuine HTTP session", signedIn.code)
	}
	newCSRF := signedIn.header.Get("X-CSRF-Token")
	recovered := call("/v1/passkey/delete", recovery, "http-removal-B", signedIn.cookies, newCSRF, origin)
	var metadata passkeyhttp.DeleteResponse
	if recovered.code != 200 || json.Unmarshal(recovered.body, &metadata) != nil || !metadata.Replayed || metadata.CommandID != result.CommandID || metadata.CommitOutcome != "committed" || len(recovered.cookies) != 0 || recovered.header.Get("X-CSRF-Token") != "" {
		t.Fatal("new genuine HTTP session lost original removal metadata", recovered.code)
	}
	recovery["commandID"] = assertion.CommandID
	if denied := call("/v1/passkey/delete", recovery, "http-removal-foreign-history", signedIn.cookies, newCSRF, origin); denied.code < 400 {
		t.Fatal("signin/options history substituted for removal completion")
	}
	last := map[string]any{"phase": "options", "referenceID": second.ReferenceID, "expectedVersion": second.Version}
	if denied := call("/v1/passkey/delete", last, "http-removal-last-key", signedIn.cookies, newCSRF, origin); denied.code != 403 {
		t.Fatal("HTTP graph permitted last usable key removal", denied.code)
	}
	credential, _ := referenceRemovalCredential(t, session.CredentialCookie, signedIn.cookies[0].Value, newCSRF)
	proveReferencePasskeySessionHTTP(t, ctx, handler, c, user, signedIn.cookies[0].Value, newCSRF, func() bool {
		got, err := common.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil {
			t.Fatal(err)
		}
		return got.Authenticated
	})
}
