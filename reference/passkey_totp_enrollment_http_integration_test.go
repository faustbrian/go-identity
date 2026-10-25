//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
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
)

// All authority and registration effects use the selected public HTTP graph.
// Only authenticator signatures and reversible factor withdrawals are controlled.
func proveReferencePasskeyTOTPHTTPEnrollment(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, client *http.Client, base string, user identity.UserID, first *ecdsa.PrivateKey, firstID, handle []byte, factor mfa.FactorID, issued passkeyTOTPHTTPObservation, discoverable bool, call func(string, map[string]any, []*http.Cookie, string, string, string, ...string) passkeyTOTPHTTPObservation, after ...func(crypto.Signer, []byte, passkeyhttp.CredentialMetadata, passkeyhttp.CredentialMetadata)) func() {
	t.Helper()
	origin, csrf := c.Passkey.Flow.Origin, issued.header.Get("X-CSRF-Token")
	list := func() []passkeyhttp.CredentialMetadata {
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
			t.Fatal("HTTP MFA enrollment inventory unavailable")
		}
		defer out.Body.Close()
		wire, err := io.ReadAll(io.LimitReader(out.Body, 16385))
		var result passkeyhttp.InventoryResponse
		if err != nil || len(wire) > 16384 || out.StatusCode != 200 || json.Unmarshal(wire, &result) != nil || len(out.Cookies()) != 0 || out.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("HTTP MFA enrollment safe inventory failed", out.StatusCode)
		}
		return result.Credentials
	}
	original := list()
	if len(original) != 1 {
		t.Fatal("genuine initial credential absent")
	}
	withdraw := func(table, column string) func() {
		t.Helper()
		where := "tenant_id=$1 AND user_id=$2"
		arguments := []any{otpTenant, string(user)}
		if table == "totp_factors" {
			where += " AND factor_id=$3"
			arguments = append(arguments, string(factor))
		}
		var version string
		if err := f.pool.Raw().QueryRow(ctx, "UPDATE identity_mfa."+table+" SET "+column+"="+column+"+1 WHERE "+where+" RETURNING ("+column+"-1)::text", arguments...).Scan(&version); err != nil {
			t.Fatal("withdraw original enrolled factor authority", err)
		}
		return func() {
			t.Helper()
			arguments = append(arguments, version)
			placeholder := "$3"
			if table == "totp_factors" {
				placeholder = "$4"
			}
			tag, err := f.pool.Raw().Exec(ctx, "UPDATE identity_mfa."+table+" SET "+column+"="+placeholder+"::numeric WHERE "+where+" AND "+column+"="+placeholder+"::numeric+1", arguments...)
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatal("restore exact original factor authority", err)
			}
		}
	}
	intent := map[string]any{"mode": "session", "phase": "assertion", "label": "HTTP MFA additional key"}
	options := func(key, trusted, token string) passkeyTOTPHTTPObservation {
		return call("/v1/passkey/register-options", intent, issued.cookies, "", key, trusted, token)
	}
	for _, denied := range []struct{ csrf, origin string }{{strings.Repeat("A", 43), origin}, {csrf, "https://foreign.example"}} {
		out := options("mfa-http-enrollment-denied", denied.origin, denied.csrf)
		if out.status != 403 || len(out.cookies) != 0 || !reflect.DeepEqual(list(), original) {
			t.Fatal("HTTP MFA enrollment ignored CSRF/Origin", out.status)
		}
	}
	for _, selected := range []struct{ table, column string }{{"factor_authorities", "version"}, {"totp_factors", "enrollment_version"}} {
		restore := withdraw(selected.table, selected.column)
		out := options("mfa-http-enrollment-withdrawn-"+selected.table, origin, csrf)
		restore()
		if out.status < 400 || len(out.cookies) != 0 || !reflect.DeepEqual(list(), original) {
			t.Fatal("withdrawn MFA authority retained HTTP enrollment", selected.table, out.status)
		}
	}
	type optionsResponse struct {
		CommandID identity.CommandID `json:"commandID"`
		Replayed  bool               `json:"replayed"`
		Options   json.RawMessage    `json:"options"`
	}
	fresh := options("mfa-http-enrollment-A", origin, csrf)
	var assertion optionsResponse
	if fresh.status != 200 || json.Unmarshal(fresh.body, &assertion) != nil || assertion.CommandID == "" || assertion.Replayed || len(assertion.Options) == 0 || len(fresh.cookies) != 0 {
		t.Fatal("HTTP MFA genuine enrollment UV unavailable", fresh.status)
	}
	retry := options("mfa-http-enrollment-A", origin, csrf)
	var historical optionsResponse
	if retry.status != 200 || json.Unmarshal(retry.body, &historical) != nil || !historical.Replayed || historical.CommandID != assertion.CommandID || len(historical.Options) != 0 {
		t.Fatal("HTTP MFA enrollment retry renewed UV", retry.status)
	}
	challenge := referencePasskeyChallenge(t, ctx, func(ctx context.Context, transfer func(context.Context, []byte) error) error {
		return transfer(ctx, assertion.Options)
	})
	intent["phase"], intent["ceremonyID"], intent["response"] = "registration", assertion.CommandID, json.RawMessage(referencePasskeyAssertion(t, first, firstID, handle, challenge, 2))
	intent["label"] = "Changed original enrollment"
	if denied := options("mfa-http-enrollment-changed", origin, csrf); denied.status != 403 || !reflect.DeepEqual(list(), original) {
		t.Fatal("HTTP MFA UV changed its original registration intent", denied.status)
	}
	intent["label"] = "HTTP MFA additional key"
	authorized := options("mfa-http-enrollment-B", origin, csrf)
	var registration optionsResponse
	if authorized.status != 200 || json.Unmarshal(authorized.body, &registration) != nil || registration.CommandID == "" || registration.CommandID == assertion.CommandID || registration.Replayed || len(registration.Options) == 0 || len(authorized.cookies) != 0 {
		t.Fatal("HTTP MFA authorized registration options unavailable", authorized.status)
	}
	retry = options("mfa-http-enrollment-B", origin, csrf)
	historical = optionsResponse{}
	if retry.status != 200 || json.Unmarshal(retry.body, &historical) != nil || !historical.Replayed || historical.CommandID != registration.CommandID || len(historical.Options) != 0 {
		t.Fatal("HTTP MFA retry renewed registration", retry.status)
	}
	challenge = referencePasskeyChallenge(t, ctx, func(ctx context.Context, transfer func(context.Context, []byte) error) error {
		return transfer(ctx, registration.Options)
	})
	second := referencePasskeyTestSigner(t, c.Passkey.Protocol.Algorithms, 1)
	secondID := make([]byte, 32)
	if _, err := rand.Read(secondID); err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	completion := map[string]any{"mode": "session", "label": intent["label"], "commandID": command, "ceremonyID": registration.CommandID, "response": json.RawMessage(referencePasskeyRegistration(t, second, secondID, challenge))}
	complete := func(trusted, token string) passkeyTOTPHTTPObservation {
		return call("/v1/passkey/register-verify", completion, issued.cookies, "", "", trusted, token)
	}
	for _, denied := range []struct{ csrf, origin string }{{strings.Repeat("A", 43), origin}, {csrf, "https://foreign.example"}} {
		out := complete(denied.origin, denied.csrf)
		if out.status != 403 || len(out.cookies) != 0 || !reflect.DeepEqual(list(), original) {
			t.Fatal("HTTP MFA registration ignored CSRF/Origin", out.status)
		}
	}
	restore := withdraw("totp_factors", "enrollment_version")
	withdrawn := complete(origin, csrf)
	restore()
	if withdrawn.status < 400 || len(withdrawn.cookies) != 0 || !reflect.DeepEqual(list(), original) {
		t.Fatal("late original factor withdrawal retained HTTP registration authority", withdrawn.status)
	}
	completed := complete(origin, csrf)
	var result struct {
		Registered bool                            `json:"registered"`
		CommandID  identity.CommandID              `json:"commandID"`
		Replayed   bool                            `json:"replayed"`
		Credential *passkeyhttp.CredentialMetadata `json:"credential"`
	}
	if completed.status != 200 || json.Unmarshal(completed.body, &result) != nil || !result.Registered || result.CommandID != command || result.Replayed || result.Credential == nil || result.Credential.Label != intent["label"] || result.Credential.Version != 1 || len(completed.cookies) != 0 || completed.header.Get("X-CSRF-Token") != "" {
		t.Fatal("HTTP MFA second-key registration did not commit", completed.status)
	}
	listed := list()
	if len(listed) != 2 {
		t.Fatal("HTTP MFA second key was not durably listed")
	}
	var retained, added bool
	sameMetadata := func(a, b passkeyhttp.CredentialMetadata) bool {
		// PostgreSQL inventory and the direct UTC receipt can encode the same
		// instant with different offsets; Go location/pointer identity is not
		// part of the public credential metadata contract.
		if !a.CreatedAt.Equal(b.CreatedAt) || (a.LastUsedAt == nil) != (b.LastUsedAt == nil) {
			return false
		}
		if a.LastUsedAt != nil && !a.LastUsedAt.Equal(*b.LastUsedAt) {
			return false
		}
		a.CreatedAt, a.LastUsedAt = b.CreatedAt, b.LastUsedAt
		return reflect.DeepEqual(a, b)
	}
	for _, item := range listed {
		retained = retained || sameMetadata(item, original[0])
		added = added || sameMetadata(item, *result.Credential)
	}
	if !retained || !added {
		t.Fatal("HTTP MFA enrollment replaced original credential metadata")
	}
	addedMetadata := *result.Credential
	retry = complete(origin, csrf)
	result.Credential = nil
	if retry.status != 200 || json.Unmarshal(retry.body, &result) != nil || !result.Replayed || result.CommandID != command || result.Credential != nil || len(retry.cookies) != 0 || !reflect.DeepEqual(list(), listed) {
		t.Fatal("HTTP MFA registration retry repeated projection/effects", retry.status)
	}
	if len(after) > 1 {
		t.Fatal("ambiguous HTTP enrollment successor")
	}
	if len(after) == 1 {
		after[0](second, secondID, original[0], addedMetadata)
		return nil
	}
	// The independently enrolled key must reach the same real challenge-only
	// primary. Registration cannot manufacture a factor-free signin profile.
	flow := call("/v1/session/preauth-issue", map[string]any{"method": "passkey", "remember": false}, nil, "", "", origin)
	var browser struct {
		Issued bool   `json:"issued"`
		FlowID string `json:"flowID"`
	}
	if flow.status != 200 || json.Unmarshal(flow.body, &browser) != nil || !browser.Issued || browser.FlowID == "" {
		t.Fatal("second-key HTTP browser flow unavailable", flow.status)
	}
	input := map[string]any{"mode": "identified", "flowID": browser.FlowID, "identifier": "registered@example.invalid"}
	if discoverable {
		input["mode"] = "discoverable"
		delete(input, "identifier")
	}
	out := call("/v1/passkey/signin-options", input, flow.cookies, "", "mfa-http-added-key-signin", origin)
	var signin optionsResponse
	if out.status != 200 || json.Unmarshal(out.body, &signin) != nil || len(signin.Options) == 0 {
		t.Fatal("second-key HTTP assertion options unavailable", out.status)
	}
	challenge = referencePasskeyChallenge(t, ctx, func(ctx context.Context, transfer func(context.Context, []byte) error) error {
		return transfer(ctx, signin.Options)
	})
	primary, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	input["commandID"], input["ceremonyID"], input["response"] = primary, signin.CommandID, json.RawMessage(referencePasskeyAssertion(t, second, secondID, handle, challenge, 1))
	out = call("/v1/passkey/signin-verify", input, flow.cookies, "", "", origin)
	var child struct {
		SignedIn bool   `json:"signedIn"`
		Required bool   `json:"challengeRequired"`
		ID       string `json:"challengeID"`
		Method   string `json:"challengeMethod"`
	}
	if out.status != 200 || json.Unmarshal(out.body, &child) != nil || child.SignedIn || !child.Required || child.ID == "" || child.Method != "totp" || out.header.Get("X-MFA-Token") == "" || len(out.cookies) != 0 || out.header.Get("X-CSRF-Token") != "" {
		t.Fatal("HTTP additional key bypassed or lost independent MFA", out.status)
	}
	if bytes.Contains(out.body, []byte(out.header.Get("X-MFA-Token"))) {
		t.Fatal("second-key HTTP child disclosed proof in body")
	}
	return func() {
		t.Helper()
		if denied := complete(origin, csrf); denied.status != 401 || len(denied.cookies) != 0 || denied.header.Get("X-CSRF-Token") != "" {
			t.Fatal("logged-out original MFA session retained enrollment authority", denied.status)
		}
	}
}
