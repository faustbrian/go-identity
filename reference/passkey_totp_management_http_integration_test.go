//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	passkeyhttp "github.com/faustbrian/go-identity/http/passkey"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// The caller has just completed genuine HTTP passkey/TOTP authentication. These
// requests reuse that exact browser cookie/CSRF and the real selected owners;
// only authenticator signatures and reversible withdrawal faults are controlled.
func proveReferencePasskeyTOTPHTTPRename(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, client *http.Client, base string, user identity.UserID, key *ecdsa.PrivateKey, id, handle []byte, factor mfa.FactorID, issued passkeyTOTPHTTPObservation, document []byte, call func(string, map[string]any, []*http.Cookie, string, string, string, ...string) passkeyTOTPHTTPObservation) func() {
	t.Helper()
	origin := c.Passkey.Flow.Origin
	csrf := issued.header.Get("X-CSRF-Token")
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	list := func() passkeyhttp.CredentialMetadata {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/passkey/list", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = strings.TrimPrefix(origin, "https://")
		for _, cookie := range issued.cookies {
			r.AddCookie(cookie)
		}
		out, err := client.Do(r)
		if err != nil {
			t.Fatal("completed-MFA HTTP inventory request failed")
		}
		defer out.Body.Close()
		wire, err := io.ReadAll(io.LimitReader(out.Body, 16385))
		var result passkeyhttp.InventoryResponse
		if err != nil || len(wire) > 16384 || out.StatusCode != 200 || json.Unmarshal(wire, &result) != nil || len(result.Credentials) != 1 || result.Credentials[0].ReferenceID == "" || len(out.Cookies()) != 0 || out.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("completed-MFA inventory lost safe original credential", out.StatusCode)
		}
		node := parsed.Raw()
		for _, field := range []string{"paths", "/v1/passkey/list", "get", "responses", "200", "content", "application/json", "schema"} {
			var found bool
			node, found = node.Lookup(field)
			if !found {
				t.Fatal("selected inventory response schema missing")
			}
		}
		instance, err := parse.JSON(ctx, bytes.NewReader(wire), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(ctx, parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || !report.Valid() {
			t.Fatal("actual MFA inventory violates OpenAPI", err)
		}
		if bytes.Contains(wire, []byte(base64.RawURLEncoding.EncodeToString(id))) || bytes.Contains(wire, []byte(base64.RawURLEncoding.EncodeToString(handle))) || bytes.Contains(wire, []byte(user)) {
			t.Fatal("safe MFA inventory disclosed protocol or subject custody")
		}
		return result.Credentials[0]
	}
	original := list()
	intent := map[string]any{"phase": "options", "referenceID": original.ReferenceID, "expectedVersion": original.Version, "name": "HTTP completed-MFA renamed key"}
	options := func(key, trusted, token string) passkeyTOTPHTTPObservation {
		return call("/v1/passkey/update", intent, issued.cookies, "", key, trusted, token)
	}
	for _, denied := range []struct{ csrf, origin string }{{strings.Repeat("A", 43), origin}, {csrf, "https://foreign.example"}} {
		out := options("mfa-http-rename-denied", denied.origin, denied.csrf)
		if out.status != 403 || len(out.cookies) != 0 || out.header.Get("X-CSRF-Token") != "" || !reflect.DeepEqual(list(), original) {
			t.Fatal("MFA rename ignored original CSRF/Origin", out.status)
		}
	}
	// Withdraw only the genuinely confirmed original enrollment. The current
	// session must not fall back to the ordinary known-empty-factor profile.
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET enrollment_version=enrollment_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(user), string(factor)); err != nil {
		t.Fatal(err)
	}
	withdrawn := options("mfa-http-rename-withdrawn", origin, csrf)
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET enrollment_version=enrollment_version-1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(user), string(factor)); err != nil {
		t.Fatal("restore owned enrollment withdrawal", err)
	}
	if withdrawn.status < 400 || len(withdrawn.cookies) != 0 || withdrawn.header.Get("X-CSRF-Token") != "" || !reflect.DeepEqual(list(), original) {
		t.Fatal("withdrawn original factor retained HTTP rename authority", withdrawn.status)
	}
	fresh := options("mfa-http-rename-A", origin, csrf)
	var assertion struct {
		CommandID identity.CommandID `json:"commandID"`
		Replayed  bool               `json:"replayed"`
		Options   json.RawMessage    `json:"options"`
	}
	if fresh.status != 200 || json.Unmarshal(fresh.body, &assertion) != nil || assertion.CommandID == "" || assertion.Replayed || len(assertion.Options) == 0 || len(fresh.cookies) != 0 || fresh.header.Get("X-CSRF-Token") != "" {
		t.Fatal("genuine MFA HTTP UV rename options missing", fresh.status)
	}
	retry := options("mfa-http-rename-A", origin, csrf)
	var historical = assertion
	historical.Options = nil
	if retry.status != 200 || json.Unmarshal(retry.body, &historical) != nil || !historical.Replayed || historical.CommandID != assertion.CommandID || len(historical.Options) != 0 {
		t.Fatal("MFA HTTP options retry renewed a challenge", retry.status)
	}
	challenge := referencePasskeyChallenge(t, ctx, func(ctx context.Context, transfer func(context.Context, []byte) error) error {
		return transfer(ctx, assertion.Options)
	})
	intent["phase"], intent["ceremonyID"], intent["response"] = "complete", assertion.CommandID, json.RawMessage(referencePasskeyAssertion(t, key, id, handle, challenge, 2))
	intent["name"] = "Changed original MFA intent"
	if denied := options("mfa-http-rename-changed", origin, csrf); denied.status != 403 || !reflect.DeepEqual(list(), original) {
		t.Fatal("MFA HTTP completion replaced original intent", denied.status)
	}
	intent["name"] = "HTTP completed-MFA renamed key"
	intent["expectedVersion"] = original.Version + 1
	if denied := options("mfa-http-rename-stale", origin, csrf); denied.status != 409 || !reflect.DeepEqual(list(), original) {
		t.Fatal("MFA HTTP completion silently rebased metadata", denied.status)
	}
	intent["expectedVersion"] = original.Version
	completed := options("mfa-http-rename-B", origin, csrf)
	var renamed passkeyhttp.UpdateResponse
	if completed.status != 200 || json.Unmarshal(completed.body, &renamed) != nil || renamed.Replayed || renamed.CommitOutcome != "committed" || renamed.Credential == nil || renamed.Credential.ReferenceID != original.ReferenceID || renamed.Credential.Version != original.Version+1 || renamed.Credential.Label != intent["name"] || len(completed.cookies) != 0 || completed.header.Get("X-CSRF-Token") != "" {
		t.Fatal("fresh genuine MFA HTTP rename did not commit", completed.status)
	}
	if got := list(); got.ReferenceID != original.ReferenceID || got.Version != renamed.Credential.Version || got.Label != renamed.Credential.Label {
		t.Fatal("MFA HTTP rename was not durably listed")
	}
	retry = options("mfa-http-rename-B", origin, csrf)
	var replay passkeyhttp.UpdateResponse
	if retry.status != 200 || json.Unmarshal(retry.body, &replay) != nil || !replay.Replayed || replay.CommandID != renamed.CommandID || replay.Credential != nil || len(retry.cookies) != 0 || retry.header.Get("X-CSRF-Token") != "" {
		t.Fatal("MFA HTTP mutation retry redisclosed projection", retry.status)
	}
	return func() {
		t.Helper()
		if denied := options("mfa-http-rename-B", origin, csrf); denied.status != 401 || len(denied.cookies) != 0 || denied.header.Get("X-CSRF-Token") != "" {
			t.Fatal("logged-out MFA session retained HTTP mutation authority", denied.status)
		}
	}
}
