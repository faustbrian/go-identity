//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	webauthn "github.com/faustbrian/go-webauthn"
)

type passkeyTOTPHTTPObservation struct {
	status  int
	header  http.Header
	body    []byte
	cookies []*http.Cookie
}

// Registration, the credential and confirmed factor come from their real public
// owners. This consumer controls only authenticator bytes and HTTP inputs; SQL
// below observes durable effects or injects a reversible account suspension.
func proveReferencePasskeyTOTPHTTPS(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, c reference.StoreConfiguration, logoutClient *http.Client, base, logoutOrigin string, user identity.UserID, credential webauthn.Credential, key *ecdsa.PrivateKey, id []byte, factor mfa.FactorID, secret []byte, discoverable bool, handler http.Handler, document []byte) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	defer client.CloseIdleConnections()
	origin := c.Passkey.Flow.Origin
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document), parse.DefaultLimits())
	if err != nil {
		t.Fatal("selected HTTP document invalid", err)
	}
	request := func(path string, body map[string]any, selected []*http.Cookie, variant, key, trusted string, csrf ...string) passkeyTOTPHTTPObservation {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = strings.TrimPrefix(origin, "https://")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", trusted)
		if len(csrf) == 1 {
			r.Header.Set("X-CSRF-Token", csrf[0])
		}
		if variant != "" {
			r.Header.Set("X-MFA-Variant", variant)
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range selected {
			r.AddCookie(cookie)
		}
		out, err := client.Do(r)
		if err != nil {
			t.Fatal("owned passkey/TOTP HTTPS request failed")
		}
		defer out.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(out.Body, 65537))
		if err != nil || len(payload) > 65536 {
			t.Fatal("bounded passkey/TOTP response unavailable")
		}
		// Match real selected HTTP exchanges to the concrete public document,
		// including both enrollment and passkey variants on the shared route.
		check := func(fields []string, wire []byte, request bool) {
			t.Helper()
			direction := validate.DirectionResponse
			if request {
				direction = validate.DirectionRequest
			}
			node := parsed.Raw()
			for _, field := range fields {
				var found bool
				node, found = node.Lookup(field)
				if !found {
					t.Fatal("actual HTTP exchange has no declared schema", path, out.StatusCode, field)
				}
			}
			instance, err := parse.JSON(ctx, bytes.NewReader(wire), parse.DefaultLimits())
			if err != nil {
				t.Fatal("actual HTTP JSON invalid", path, out.StatusCode)
			}
			report, err := validate.SchemaInstance(ctx, parsed, node, instance, validate.InstanceOptions{Direction: direction})
			if err != nil || !report.Valid() {
				t.Fatal("actual HTTP exchange violates declared schema", path, out.StatusCode, err)
			}
		}
		if out.StatusCode == 200 {
			check([]string{"paths", path, "post", "requestBody", "content", "application/json", "schema"}, wire, true)
		}
		media, responseWire := "application/json", payload
		if strings.HasPrefix(out.Header.Get("Content-Type"), "text/plain") {
			// The shared CORS owner denies foreign origins before dispatch, with
			// its separately declared plaintext response rather than MFA JSON.
			media = "text/plain"
			responseWire, err = json.Marshal(string(payload))
			if err != nil {
				t.Fatal(err)
			}
		}
		check([]string{"paths", path, "post", "responses", strconv.Itoa(out.StatusCode), "content", media, "schema"}, responseWire, false)
		return passkeyTOTPHTTPObservation{out.StatusCode, out.Header, payload, out.Cookies()}
	}
	flow := request("/v1/session/preauth-issue", map[string]any{"method": "passkey", "remember": false}, nil, "", "", origin)
	var original struct {
		Issued bool   `json:"issued"`
		FlowID string `json:"flowID"`
	}
	if flow.status != 200 || json.Unmarshal(flow.body, &original) != nil || !original.Issued || original.FlowID == "" {
		t.Fatal("genuine HTTP original browser issuance", flow.status)
	}
	var cookies []*http.Cookie
	for _, cookie := range flow.cookies {
		if cookie.Name == "__Host-identity_flow" || cookie.Name == "__Host-identity_device" {
			cookies = append(cookies, cookie)
		}
	}
	if len(cookies) != 2 {
		t.Fatal("original flow/device custody missing")
	}
	input := map[string]any{"mode": "identified", "flowID": original.FlowID, "identifier": "registered@example.invalid"}
	if discoverable {
		input["mode"] = "discoverable"
		delete(input, "identifier")
	}
	options := request("/v1/passkey/signin-options", input, cookies, "", "reference-http-passkey-totp", origin)
	var challenge struct {
		CommandID string          `json:"commandID"`
		Options   json.RawMessage `json:"options"`
	}
	if options.status != 200 || json.Unmarshal(options.body, &challenge) != nil || challenge.CommandID == "" || len(challenge.Options) == 0 {
		t.Fatal("genuine HTTP assertion options", options.status)
	}
	var assertion struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(challenge.Options, &assertion) != nil || assertion.PublicKey.Challenge == "" {
		t.Fatal("actual assertion challenge missing")
	}
	primaryID, _ := identity.NewCommandID()
	input["commandID"], input["ceremonyID"] = primaryID, challenge.CommandID
	input["response"] = json.RawMessage(referencePasskeyAssertion(t, key, id, credential.UserHandle, assertion.PublicKey.Challenge))
	first := request("/v1/passkey/signin-verify", input, cookies, "", "", origin)
	var child struct {
		SignedIn bool      `json:"signedIn"`
		Required bool      `json:"challengeRequired"`
		ID       string    `json:"challengeID"`
		Method   string    `json:"challengeMethod"`
		Expires  time.Time `json:"challengeExpiresAt"`
	}
	if first.status != 200 || json.Unmarshal(first.body, &child) != nil || child.SignedIn || !child.Required || child.Method != "totp" || child.ID == "" || !child.Expires.After(time.Now()) || len(first.cookies) != 0 || first.header.Get("X-CSRF-Token") != "" || first.header.Get("X-MFA-Token") == "" {
		t.Fatal("HTTP assertion must return only its original MFA challenge", first.status)
	}
	proof := first.header.Get("X-MFA-Token")
	if bytes.Contains(first.body, []byte(proof)) || bytes.Contains(first.body, []byte(user)) {
		t.Fatal("HTTP child disclosed proof/subject in JSON")
	}
	primaryRetry := request("/v1/passkey/signin-verify", input, cookies, "", "", origin)
	if primaryRetry.header.Get("X-MFA-Token") != "" || len(primaryRetry.cookies) != 0 {
		t.Fatal("original assertion retry redisclosed credentials")
	}
	type effects struct{ attempts, uses, sessions, consumed, charges int }
	observe := func() effects {
		t.Helper()
		var e effects
		err := f.pool.Raw().QueryRow(ctx, `SELECT c.attempts_remaining,(SELECT uses FROM public.capability_identity_one_use WHERE tenant_id=c.tenant_id AND capability_id=c.continuation_id),(SELECT count(*) FROM session_store.session_issuances WHERE purpose='identity.mfa.totp-verify'),(SELECT count(*) FROM session_store.preauth_transactions f JOIN identity.commands j ON j.command_id=f.command_id AND j.tenant_id=f.tenant_id JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose WHERE f.tenant_id=c.tenant_id AND f.flow_id=c.source_preauth_id AND f.state='consumed' AND j.purpose='identity.mfa.totp-verify' AND j.state='committed' AND j.generation=f.generation AND k.fingerprint=f.fingerprint AND NOT k.retired),(SELECT count(*) FROM risk_store.counter_charges WHERE operation='identity.mfa.totp-verify') FROM identity_mfa.continuations c WHERE c.tenant_id=$1 AND c.continuation_id=$2`, otpTenant, child.ID).Scan(&e.attempts, &e.uses, &e.sessions, &e.consumed, &e.charges)
		if err != nil {
			t.Fatal("durable HTTP completion observation", err)
		}
		return e
	}
	before := observe()
	command, _ := identity.NewCommandID()
	completion := map[string]any{"commandID": command, "preAuthID": original.FlowID, "challengeID": child.ID, "factorID": factor, "token": proof, "code": passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second)), "callbackURL": c.Passkey.Flow.CallbackURL, "trustDevice": false}
	deny := func(name, variant, trusted string, selected []*http.Cookie, want int) {
		t.Helper()
		out := request("/v1/mfa/totp-verify", completion, selected, variant, "", trusted)
		if out.status != want || len(out.cookies) != 0 || out.header.Get("X-CSRF-Token") != "" || observe() != before {
			t.Fatal(name, "spent original authority or disclosed session", out.status)
		}
	}
	deny("missing explicit variant", "", origin, cookies, 400)
	deny("wrong primary variant", "password", origin, cookies, 400)
	deny("foreign origin", "passkey", "https://foreign.example", cookies, 403)
	foreign := append([]*http.Cookie(nil), cookies...)
	for i, cookie := range foreign {
		if cookie.Name == "__Host-identity_flow" {
			copy := *cookie
			copy.Value = strings.Repeat("A", 43)
			foreign[i] = &copy
		}
	}
	deny("foreign original browser", "passkey", origin, foreign, 403)
	originalFactor := completion["factorID"]
	completion["factorID"], _ = identity.NewCommandID()
	completion["commandID"], _ = identity.NewCommandID()
	foreignFactor := request("/v1/mfa/totp-verify", completion, cookies, "passkey", "", origin)
	afterFactor := observe()
	// RecordMissingTOTPAttemptDenial deliberately charges an authenticated
	// original challenge. Unlike a foreign browser, a wrong factor must spend
	// one attempt/counter but cannot consume the child or issue a session.
	if foreignFactor.status != 403 || len(foreignFactor.cookies) != 0 || foreignFactor.header.Get("X-CSRF-Token") != "" || afterFactor.attempts != before.attempts-1 || afterFactor.charges != before.charges+1 || afterFactor.uses != before.uses || afterFactor.sessions != before.sessions || afterFactor.consumed != before.consumed {
		t.Fatal("foreign factor did not preserve bounded native denial", foreignFactor.status, before, afterFactor)
	}
	completion["factorID"] = originalFactor
	completion["commandID"], _ = identity.NewCommandID()
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user)); err != nil {
		t.Fatal(err)
	}
	blocked := request("/v1/mfa/totp-verify", completion, cookies, "passkey", "", origin)
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user)); err != nil {
		t.Fatal("restore owned suspension injection", err)
	}
	if blocked.status != 403 || len(blocked.cookies) != 0 || blocked.header.Get("X-CSRF-Token") != "" || observe() != afterFactor {
		t.Fatal("blocked account retained HTTP authentication authority", blocked.status)
	}
	wrong := ""
	for candidate := 0; ; candidate++ {
		wrong = fmt.Sprintf("%06d", candidate)
		matches := false
		for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
			matches = matches || wrong == passwordMFAFixtureCode(secret, time.Now().Add(offset))
		}
		if !matches {
			break
		}
	}
	completion["code"] = wrong
	completion["commandID"], _ = identity.NewCommandID()
	bad := request("/v1/mfa/totp-verify", completion, cookies, "passkey", "", origin)
	afterWrong := observe()
	if bad.status != 403 || len(bad.cookies) != 0 || bad.header.Get("X-CSRF-Token") != "" || afterWrong.attempts != before.attempts-2 || afterWrong.charges != before.charges+2 || afterWrong.uses != before.uses || afterWrong.sessions != before.sessions || afterWrong.consumed != before.consumed {
		t.Fatal("wrong TOTP HTTP code effects", bad.status)
	}
	completion["commandID"], _ = identity.NewCommandID()
	completion["code"] = passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second))
	issued := request("/v1/mfa/totp-verify", completion, cookies, "passkey", "", origin)
	var result struct {
		SignedIn  bool   `json:"signedIn"`
		SessionID string `json:"sessionID"`
		Outcome   string `json:"commitOutcome"`
	}
	if issued.status != 200 || json.Unmarshal(issued.body, &result) != nil || !result.SignedIn || result.SessionID == "" || result.Outcome != "committed" || len(issued.cookies) != 1 || issued.header.Get("X-CSRF-Token") == "" {
		t.Fatal("genuine HTTP assertion -> TOTP -> session", issued.status)
	}
	after := observe()
	if after.attempts != before.attempts-3 || after.charges != before.charges+3 || after.uses != 1 || after.sessions != before.sessions+1 || after.consumed != before.consumed+1 {
		t.Fatal("HTTP completion lost atomic one-use/session/browser effects", before, after)
	}
	retry := request("/v1/mfa/totp-verify", completion, cookies, "passkey", "", origin)
	if retry.status != 409 || len(retry.cookies) != 0 || retry.header.Get("X-CSRF-Token") != "" || observe() != after {
		t.Fatal("HTTP completion retry redisclosed credentials or repeated effects", retry.status)
	}
	var afterLogout func()
	if c.HTTPPasskey.SessionUpdate {
		afterLogout = proveReferencePasskeyTOTPHTTPRename(t, ctx, f, c, client, server.URL, user, key, id, credential.UserHandle, factor, issued, document, request)
	}
	if c.HTTPPasskey.SessionEnrollment {
		afterLogout = proveReferencePasskeyTOTPHTTPEnrollment(t, ctx, f, c, client, server.URL, user, key, id, credential.UserHandle, factor, issued, discoverable, request)
	}
	proveRegistrationSessionLogout(t, ctx, logoutClient, base, logoutOrigin, issued.cookies, issued.header.Get("X-CSRF-Token"), result.SessionID, f, features)
	if afterLogout != nil {
		afterLogout()
	}
}
