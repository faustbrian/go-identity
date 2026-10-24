//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	passkeyhttp "github.com/faustbrian/go-identity/http/passkey"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
)

func TestReferencePostgresPasskeyHTTPSignup(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySignup: true, passkeySignupHTTP: true, passkeyHTTP: true, passkeyDiscovery: true, passkeySessionHTTP: true, passkeyUpgrade: upgrade}, true)
		})
	}
}

func proveReferencePasskeySignupHTTP(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, handler http.Handler, document []byte, pool *database.Pool) {
	t.Helper()
	proveReferencePasskeySignupHTTPRemember(t, ctx, features, c, handler, document, pool, false)
}

func proveReferencePasskeySignupHTTPRemember(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, handler http.Handler, document []byte, pool *database.Pool, persistent bool) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	origin := c.Passkey.Signup.Flow.Origin
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	type response = passkeyDeletionHTTPObservation
	call := func(path string, body any, key string, cookies []*http.Cookie, csrf, selectedOrigin string) response {
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
		r.Header.Set("Origin", selectedOrigin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		got, err := client.Do(r)
		if err != nil {
			t.Fatal("signup HTTPS request failed")
		}
		defer got.Body.Close()
		data, err := io.ReadAll(io.LimitReader(got.Body, 65537))
		if err != nil || len(data) > 65536 {
			t.Fatal("signup response bound")
		}
		if strings.HasPrefix(path, "/v1/passkey/") {
			check := func(parts []string, instance []byte, direction validate.InstanceDirection) {
				t.Helper()
				node := parsed.Raw()
				for _, part := range parts {
					var found bool
					node, found = node.Lookup(part)
					if !found {
						t.Fatal("signup wire missing", part)
					}
				}
				value, err := parse.JSON(ctx, bytes.NewReader(instance), parse.DefaultLimits())
				if err != nil {
					t.Fatal("signup wire instance invalid")
				}
				report, err := validate.SchemaInstance(ctx, parsed, node, value, validate.InstanceOptions{Direction: direction})
				if err != nil || !report.Valid() {
					t.Fatal("signup wire mismatch", path, got.StatusCode)
				}
			}
			if got.StatusCode == 200 {
				check([]string{"paths", path, "post", "requestBody", "content", "application/json", "schema"}, wire, validate.DirectionRequest)
			}
			media, instance := "application/json", data
			if strings.HasPrefix(got.Header.Get("Content-Type"), "text/plain") {
				media = "text/plain"
				instance, err = json.Marshal(string(data))
				if err != nil {
					t.Fatal(err)
				}
			}
			check([]string{"paths", path, "post", "responses", strconv.Itoa(got.StatusCode), "content", media, "schema"}, instance, validate.DirectionResponse)
		}
		return response{got.StatusCode, got.Header, data, got.Cookies()}
	}
	var device *http.Cookie
	flow := func(method string) (string, []*http.Cookie) {
		t.Helper()
		var retained []*http.Cookie
		if device != nil {
			retained = []*http.Cookie{device}
		}
		got := call("/v1/session/preauth-issue", map[string]any{"method": method, "remember": persistent}, "", retained, "", origin)
		var out struct {
			Issued bool   `json:"issued"`
			FlowID string `json:"flowID"`
		}
		if got.code != 200 || json.Unmarshal(got.body, &out) != nil || !out.Issued || out.FlowID == "" {
			t.Fatal("actual signup HTTP flow", got.code)
		}
		var cookies []*http.Cookie
		for _, cookie := range got.cookies {
			if cookie.Name == "__Host-identity_flow" {
				cookies = append(cookies, cookie)
			}
			if cookie.Name == "__Host-identity_device" {
				device = cookie
			}
		}
		if len(cookies) != 1 || device == nil {
			t.Fatal("original HTTP browser custody absent")
		}
		return out.FlowID, append(cookies, device)
	}
	flowID, cookies := flow("passkey-signup")
	var before int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"mode": "signup", "flowID": flowID}
	options := call("/v1/passkey/register-options", body, "reference-http-signup", cookies, "", origin)
	var created struct {
		CommandID string          `json:"commandID"`
		Replayed  bool            `json:"replayed"`
		Options   json.RawMessage `json:"options"`
	}
	if options.code != 200 || json.Unmarshal(options.body, &created) != nil || created.CommandID == "" || len(created.Options) == 0 || created.Replayed || len(options.cookies) != 0 {
		t.Fatal("actual HTTP signup options", options.code)
	}
	retry := call("/v1/passkey/register-options", body, "reference-http-signup", cookies, "", origin)
	var historical struct {
		CommandID string          `json:"commandID"`
		Replayed  bool            `json:"replayed"`
		Options   json.RawMessage `json:"options"`
	}
	if retry.code != 200 || json.Unmarshal(retry.body, &historical) != nil || !historical.Replayed || historical.CommandID != created.CommandID || len(historical.Options) != 0 {
		t.Fatal("signup options retry repeated challenge", retry.code)
	}
	var after int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users`).Scan(&after); err != nil || after != before {
		t.Fatal("HTTP options created user before proof", err)
	}
	var protocol struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(created.Options, &protocol) != nil || protocol.PublicKey.Challenge == "" {
		t.Fatal("signup protocol options absent")
	}
	handle, err := base64.RawURLEncoding.DecodeString(protocol.PublicKey.User.ID)
	if err != nil || len(handle) != 32 {
		t.Fatal("opaque signup handle invalid")
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	var attestation map[string]json.RawMessage
	if json.Unmarshal(referencePasskeyRegistration(t, private, id, protocol.PublicKey.Challenge), &attestation) != nil {
		t.Fatal("controlled authenticator response invalid")
	}
	attestation["clientExtensionResults"] = json.RawMessage(`{"credProps":{"rk":true}}`)
	raw, err := json.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}
	command, _ := identity.NewCommandID()
	completion := map[string]any{"mode": "signup", "flowID": flowID, "commandID": command, "ceremonyID": created.CommandID, "response": json.RawMessage(raw), "label": "HTTP signup key"}
	if denied := call("/v1/passkey/register-verify", completion, "", cookies, "", "https://foreign.example"); denied.code != 403 || len(denied.cookies) != 0 {
		t.Fatal("HTTP signup bypassed origin", denied.code)
	}
	issued := call("/v1/passkey/register-verify", completion, "", cookies, "", origin)
	var signed struct {
		Registered bool   `json:"registered"`
		SignedIn   bool   `json:"signedIn"`
		SessionID  string `json:"sessionID"`
	}
	if issued.code != 200 || json.Unmarshal(issued.body, &signed) != nil || !signed.Registered || !signed.SignedIn || signed.SessionID == "" || len(issued.cookies) != 1 || issued.header.Get("X-CSRF-Token") == "" {
		t.Fatal("actual HTTP signup session", issued.code)
	}
	// Like retained enrollment/signin, replay guarantees fail-closed, no secret
	// and no repeated effect, not a single status for all native terminal states.
	// The declared error schema above independently checks the actual envelope.
	replay := call("/v1/passkey/register-verify", completion, "", cookies, "", origin)
	var denied struct {
		Error      string `json:"error"`
		SignedIn   bool   `json:"signedIn"`
		Registered bool   `json:"registered"`
		SessionID  string `json:"sessionID"`
	}
	if replay.code < 400 || json.Unmarshal(replay.body, &denied) != nil || denied.Error == "" || denied.SignedIn || denied.Registered || denied.SessionID != "" || len(replay.cookies) != 0 || replay.header.Get("X-CSRF-Token") != "" {
		t.Fatal("HTTP signup replay redelivered authentication", replay.code)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users`).Scan(&after); err != nil || after != before+1 {
		t.Fatal("HTTP signup replay created another identity", err)
	}
	common, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	read := func(got response) session.GetResult {
		t.Helper()
		token, err := session.ParseToken(got.cookies[0].Value)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.NewCredential(session.CredentialCookie, token)
		if err != nil {
			t.Fatal(err)
		}
		out, err := common.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	sessionRead := read(issued)
	if !sessionRead.Authenticated {
		t.Fatal("common read rejected actual signup")
	}
	record, err := sessionRead.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	choice := session.BrowserSession
	if persistent {
		choice = session.PersistentSession
	}
	if record.Remember.Choice() != choice || (issued.cookies[0].MaxAge > 0) != persistent || !persistent && !issued.cookies[0].Expires.IsZero() {
		t.Fatal("signup changed original browser remember choice")
	}
	var events, identifiers int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$1 AND topic IN ('identity.passkey.create_credential','user.created.v1','session.created.v1')),(SELECT count(*) FROM identity.identifiers WHERE user_id=$2)`, string(command), string(record.UserID)).Scan(&events, &identifiers); err != nil || events != 3 || identifiers != 0 {
		t.Fatal("HTTP signup lost atomic effects or invented identifier", err, events, identifiers)
	}
	if c.Passkey.Standalone != nil {
		var passwordOwner bool
		if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity_password.credentials') IS NOT NULL`).Scan(&passwordOwner); err != nil || passwordOwner {
			t.Fatal("standalone signup installed an unselected password owner", err)
		}
	} else {
		var passwords int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_password.credentials WHERE user_id=$1`, string(record.UserID)).Scan(&passwords); err != nil || passwords != 0 {
			t.Fatal("HTTP signup invented password fallback", err, passwords)
		}
	}
	var managedCredential passkeyhttp.CredentialMetadata
	if c.HTTPPasskey.Inventory {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/passkey/list", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = strings.TrimPrefix(origin, "https://")
		r.AddCookie(issued.cookies[0])
		got, err := client.Do(r)
		if err != nil {
			t.Fatal("signup inventory HTTPS request failed")
		}
		wire, readErr := io.ReadAll(io.LimitReader(got.Body, 16385))
		closeErr := got.Body.Close()
		var listed passkeyhttp.InventoryResponse
		if readErr != nil || closeErr != nil || len(wire) > 16384 || got.StatusCode != 200 || json.Unmarshal(wire, &listed) != nil || len(listed.Credentials) != 1 || listed.Credentials[0].Label != "HTTP signup key" || listed.Credentials[0].ReferenceID == "" || len(got.Cookies()) != 0 || got.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("signup session failed safe HTTP inventory", got.StatusCode)
		}
		if bytes.Contains(wire, []byte(base64.RawURLEncoding.EncodeToString(id))) || bytes.Contains(wire, []byte(protocol.PublicKey.User.ID)) {
			t.Fatal("safe signup inventory exposed protocol credential or user handle")
		}
		managedCredential = listed.Credentials[0]
	}
	var checkUpdateAfterLogout func()
	if c.HTTPPasskey.SessionUpdate {
		intent := map[string]any{"phase": "options", "referenceID": managedCredential.ReferenceID, "expectedVersion": managedCredential.Version, "name": "HTTP passkey-only renamed key"}
		for _, mode := range []string{"wrong-csrf", "foreign-origin"} {
			csrf, selectedOrigin := issued.header.Get("X-CSRF-Token"), origin
			if mode == "wrong-csrf" {
				csrf = strings.Repeat("A", 43)
			} else {
				selectedOrigin = "https://foreign.example"
			}
			denied := call("/v1/passkey/update", intent, "denied-rename-options-"+mode, issued.cookies, csrf, selectedOrigin)
			if denied.code != 403 {
				t.Fatal("HTTP update ignored original cookie/Origin/CSRF", mode, denied.code)
			}
		}
		options := call("/v1/passkey/update", intent, "http-session-rename-options", issued.cookies, issued.header.Get("X-CSRF-Token"), origin)
		var projected struct {
			CommandID identity.CommandID `json:"commandID"`
			Replayed  bool               `json:"replayed"`
			Options   json.RawMessage    `json:"options"`
		}
		if options.code != 200 || json.Unmarshal(options.body, &projected) != nil || projected.CommandID == "" || len(projected.Options) == 0 || len(options.cookies) != 0 || options.header.Get("X-CSRF-Token") != "" {
			t.Fatal("HTTP genuine action-bound UV options", options.code)
		}
		challenge := referencePasskeyChallenge(t, ctx, func(ctx context.Context, fn func(context.Context, []byte) error) error {
			return fn(ctx, projected.Options)
		})
		retried := call("/v1/passkey/update", intent, "http-session-rename-options", issued.cookies, issued.header.Get("X-CSRF-Token"), origin)
		var historical struct {
			CommandID identity.CommandID `json:"commandID"`
			Replayed  bool               `json:"replayed"`
			Options   json.RawMessage    `json:"options"`
		}
		if retried.code != 200 || json.Unmarshal(retried.body, &historical) != nil || !historical.Replayed || historical.CommandID != projected.CommandID || len(historical.Options) != 0 {
			t.Fatal("HTTP options retry disclosed renewed challenge", retried.code)
		}
		intent["phase"], intent["ceremonyID"], intent["response"] = "complete", string(projected.CommandID), json.RawMessage(referencePasskeyAssertion(t, private, id, handle, challenge))
		intent["name"] = "Changed original intent"
		denied := call("/v1/passkey/update", intent, "http-session-rename-tampered", issued.cookies, issued.header.Get("X-CSRF-Token"), origin)
		if denied.code != 403 {
			t.Fatal("HTTP completion changed original protected intent", denied.code)
		}
		intent["name"] = "HTTP passkey-only renamed key"
		completed := call("/v1/passkey/update", intent, "http-session-rename-completion", issued.cookies, issued.header.Get("X-CSRF-Token"), origin)
		var renamed passkeyhttp.UpdateResponse
		if completed.code != 200 || json.Unmarshal(completed.body, &renamed) != nil || renamed.Replayed || renamed.Credential == nil || renamed.Credential.Version != managedCredential.Version+1 || renamed.Credential.Label != intent["name"] || len(completed.cookies) != 0 || completed.header.Get("X-CSRF-Token") != "" {
			t.Fatal("HTTP atomic session rename", completed.code)
		}
		retried = call("/v1/passkey/update", intent, "http-session-rename-completion", issued.cookies, issued.header.Get("X-CSRF-Token"), origin)
		var replay passkeyhttp.UpdateResponse
		if retried.code != 200 || json.Unmarshal(retried.body, &replay) != nil || !replay.Replayed || replay.CommandID != renamed.CommandID || replay.Credential != nil {
			t.Fatal("HTTP completion retry disclosed new projection", retried.code)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/passkey/list", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = strings.TrimPrefix(origin, "https://")
		r.AddCookie(issued.cookies[0])
		got, err := client.Do(r)
		if err != nil {
			t.Fatal("renamed inventory request")
		}
		wire, readErr := io.ReadAll(io.LimitReader(got.Body, 16385))
		closeErr := got.Body.Close()
		var listed passkeyhttp.InventoryResponse
		if readErr != nil || closeErr != nil || got.StatusCode != 200 || len(wire) > 16384 || json.Unmarshal(wire, &listed) != nil || len(listed.Credentials) != 1 || listed.Credentials[0].Label != intent["name"] || listed.Credentials[0].Version != managedCredential.Version+1 {
			t.Fatal("HTTP rename was not durable in inventory", got.StatusCode)
		}
		checkUpdateAfterLogout = func() {
			denied := call("/v1/passkey/update", intent, "http-session-rename-completion", issued.cookies, issued.header.Get("X-CSRF-Token"), origin)
			if denied.code != 401 || len(denied.cookies) != 0 || denied.header.Get("X-CSRF-Token") != "" {
				t.Fatal("revoked session recovered update authority", denied.code)
			}
		}
	} else if c.Passkey.SessionManagement != nil {
		proveReferenceSessionRename(t, ctx, features, c, record.UserID, issued.cookies[0].Value, issued.header.Get("X-CSRF-Token"), private, id, handle)
	}
	var additionalKey *ecdsa.PrivateKey
	var additionalID []byte
	var checkEnrollmentAfterLogout func()
	if c.HTTPPasskey.SessionEnrollment {
		label := "HTTP additional passkey"
		intent := map[string]any{"mode": "session", "phase": "assertion", "label": label}
		csrf := issued.header.Get("X-CSRF-Token")
		for _, denied := range []struct{ csrf, origin string }{{strings.Repeat("A", 43), origin}, {csrf, "https://foreign.example"}} {
			got := call("/v1/passkey/register-options", intent, "denied-enrollment-options", issued.cookies, denied.csrf, denied.origin)
			if got.code != 403 {
				t.Fatal("HTTP enrollment ignored original session CSRF/Origin", got.code)
			}
		}
		options := call("/v1/passkey/register-options", intent, "http-enrollment-A", issued.cookies, csrf, origin)
		var assertion struct {
			CommandID string          `json:"commandID"`
			Replayed  bool            `json:"replayed"`
			Options   json.RawMessage `json:"options"`
		}
		if options.code != 200 || json.Unmarshal(options.body, &assertion) != nil || assertion.CommandID == "" || assertion.Replayed || len(assertion.Options) == 0 || len(options.cookies) != 0 || options.header.Get("X-CSRF-Token") != "" {
			t.Fatal("HTTP enrollment genuine UV options", options.code)
		}
		retry := call("/v1/passkey/register-options", intent, "http-enrollment-A", issued.cookies, csrf, origin)
		var replay = assertion
		replay.Options = nil
		if retry.code != 200 || json.Unmarshal(retry.body, &replay) != nil || !replay.Replayed || replay.CommandID != assertion.CommandID || len(replay.Options) != 0 {
			t.Fatal("HTTP enrollment A retry renewed challenge", retry.code)
		}
		challenge := referencePasskeyChallenge(t, ctx, func(ctx context.Context, transfer func(context.Context, []byte) error) error {
			return transfer(ctx, assertion.Options)
		})
		counter := uint32(1)
		if c.Passkey.SessionManagement != nil {
			counter++
		}
		intent["phase"], intent["ceremonyID"], intent["response"] = "registration", assertion.CommandID, json.RawMessage(referencePasskeyAssertion(t, private, id, handle, challenge, counter))
		intent["label"] = "Changed original enrollment"
		denied := call("/v1/passkey/register-options", intent, "http-enrollment-B-tampered", issued.cookies, csrf, origin)
		if denied.code != 403 {
			t.Fatal("HTTP enrollment changed original intended label", denied.code)
		}
		intent["label"] = label
		authorized := call("/v1/passkey/register-options", intent, "http-enrollment-B", issued.cookies, csrf, origin)
		var registration = assertion
		if authorized.code != 200 || json.Unmarshal(authorized.body, &registration) != nil || registration.CommandID == assertion.CommandID || registration.Replayed || len(registration.Options) == 0 || len(authorized.cookies) != 0 || authorized.header.Get("X-CSRF-Token") != "" {
			t.Fatal("HTTP enrollment genuine registration options", authorized.code)
		}
		replay.Options = nil
		retry = call("/v1/passkey/register-options", intent, "http-enrollment-B", issued.cookies, csrf, origin)
		if retry.code != 200 || json.Unmarshal(retry.body, &replay) != nil || !replay.Replayed || replay.CommandID != registration.CommandID || len(replay.Options) != 0 {
			t.Fatal("HTTP enrollment B retry renewed registration", retry.code)
		}
		challenge = referencePasskeyChallenge(t, ctx, func(ctx context.Context, transfer func(context.Context, []byte) error) error {
			return transfer(ctx, registration.Options)
		})
		additionalKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		additionalID = make([]byte, 32)
		if _, err := rand.Read(additionalID); err != nil {
			t.Fatal(err)
		}
		command, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		completion := map[string]any{"mode": "session", "label": label, "commandID": command, "ceremonyID": registration.CommandID, "response": json.RawMessage(referencePasskeyRegistration(t, additionalKey, additionalID, challenge))}
		if denied := call("/v1/passkey/register-verify", completion, "", issued.cookies, strings.Repeat("A", 43), origin); denied.code != 403 {
			t.Fatal("HTTP enrollment completion ignored original CSRF", denied.code)
		}
		completed := call("/v1/passkey/register-verify", completion, "", issued.cookies, csrf, origin)
		var result struct {
			Registered bool                            `json:"registered"`
			CommandID  identity.CommandID              `json:"commandID"`
			Replayed   bool                            `json:"replayed"`
			Credential *passkeyhttp.CredentialMetadata `json:"credential"`
		}
		if completed.code != 200 || json.Unmarshal(completed.body, &result) != nil || !result.Registered || result.CommandID != command || result.Replayed || result.Credential == nil || result.Credential.Label != label || result.Credential.Version != 1 || len(completed.cookies) != 0 || completed.header.Get("X-CSRF-Token") != "" {
			t.Fatal("HTTP enrollment atomic second credential", completed.code)
		}
		retry = call("/v1/passkey/register-verify", completion, "", issued.cookies, csrf, origin)
		result.Credential = nil
		if retry.code != 200 || json.Unmarshal(retry.body, &result) != nil || !result.Replayed || result.CommandID != command || result.Credential != nil {
			t.Fatal("HTTP enrollment C retry disclosed fresh credential", retry.code)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/passkey/list", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = strings.TrimPrefix(origin, "https://")
		r.AddCookie(issued.cookies[0])
		got, err := client.Do(r)
		if err != nil {
			t.Fatal("HTTP second-key inventory request")
		}
		wire, readErr := io.ReadAll(io.LimitReader(got.Body, 16385))
		closeErr := got.Body.Close()
		var listed passkeyhttp.InventoryResponse
		if readErr != nil || closeErr != nil || len(wire) > 16384 || got.StatusCode != 200 || json.Unmarshal(wire, &listed) != nil || len(listed.Credentials) != 2 {
			t.Fatal("HTTP second credential was not durably listed", got.StatusCode)
		}
		if c.HTTPPasskey.SessionDeletion {
			var second passkeyhttp.CredentialMetadata
			for _, item := range listed.Credentials {
				if item.ReferenceID != managedCredential.ReferenceID {
					second = item
				}
			}
			if second.ReferenceID == "" {
				t.Fatal("HTTP additional credential metadata absent")
			}
			proveReferenceHTTPSessionDeletion(t, ctx, features, c, handler, record.UserID, issued.cookies, csrf, private, id, handle, counter, managedCredential, second, additionalKey, additionalID, call, flow)
			return
		}
		checkEnrollmentAfterLogout = func() {
			denied := call("/v1/passkey/register-verify", completion, "", issued.cookies, csrf, origin)
			if denied.code != 401 || len(denied.cookies) != 0 || denied.header.Get("X-CSRF-Token") != "" {
				t.Fatal("revoked original session recovered enrollment", denied.code)
			}
		}
	} else if c.Passkey.SessionEnrollment != nil {
		counter := uint32(1)
		if c.Passkey.SessionManagement != nil {
			counter++
		}
		if c.Passkey.SessionDeletion != nil {
			proveReferenceSessionEnrollment(t, ctx, features, c, handler, record.UserID, issued.cookies[0].Value, issued.header.Get("X-CSRF-Token"), private, id, handle, counter, func(secondKey *ecdsa.PrivateKey, secondID []byte, metadata passkey.CredentialMetadata) {
				proveReferenceSessionDeletion(t, ctx, features, c, handler, record.UserID, issued.cookies[0].Value, issued.header.Get("X-CSRF-Token"), private, id, handle, counter, secondKey, secondID, metadata)
			})
			return
		}
		proveReferenceSessionEnrollment(t, ctx, features, c, handler, record.UserID, issued.cookies[0].Value, issued.header.Get("X-CSRF-Token"), private, id, handle, counter)
	}
	proveReferencePasskeySessionHTTP(t, ctx, handler, c, record.UserID, issued.cookies[0].Value, issued.header.Get("X-CSRF-Token"), func() bool { return read(issued).Authenticated })
	if checkUpdateAfterLogout != nil {
		checkUpdateAfterLogout()
	}
	if checkEnrollmentAfterLogout != nil {
		checkEnrollmentAfterLogout()
	}
	signinKey := func(private *ecdsa.PrivateKey, id []byte, count uint32) {
		t.Helper()
		flowID, cookies = flow("passkey")
		key := "reference-http-signup-signin-" + flowID
		assertionOptions := call("/v1/passkey/signin-options", map[string]any{"mode": "discoverable", "flowID": flowID}, key, cookies, "", origin)
		var assertionProtocol struct {
			Mediation string `json:"mediation"`
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		if assertionOptions.code != 200 || json.Unmarshal(assertionOptions.body, &created) != nil || json.Unmarshal(created.Options, &assertionProtocol) != nil {
			t.Fatal("fresh HTTP signup-key signin options", assertionOptions.code)
		}
		if c.HTTPPasskey.Conditional && assertionProtocol.Mediation != "conditional" || !c.HTTPPasskey.Conditional && assertionProtocol.Mediation != "" {
			t.Fatal("signin options disagree with selected presentation")
		}
		optionsRetry := call("/v1/passkey/signin-options", map[string]any{"mode": "discoverable", "flowID": flowID}, key, cookies, "", origin)
		var original struct {
			CommandID string          `json:"commandID"`
			Replayed  bool            `json:"replayed"`
			Options   json.RawMessage `json:"options"`
		}
		if optionsRetry.code != 200 || json.Unmarshal(optionsRetry.body, &original) != nil || !original.Replayed || original.CommandID != created.CommandID || len(original.Options) != 0 || len(optionsRetry.cookies) != 0 {
			t.Fatal("signin options retry disclosed a new challenge or authentication", optionsRetry.code)
		}
		command, _ = identity.NewCommandID()
		signinBody := map[string]any{"mode": "discoverable", "flowID": flowID, "commandID": command, "ceremonyID": created.CommandID, "response": json.RawMessage(referencePasskeyAssertion(t, private, id, handle, assertionProtocol.PublicKey.Challenge, count))}
		signin := call("/v1/passkey/signin-verify", signinBody, "", cookies, "", origin)
		if signin.code != 200 || len(signin.cookies) != 1 || signin.header.Get("X-CSRF-Token") == "" {
			t.Fatal("signup key fresh HTTP signin", signin.code)
		}
		signinReplay := call("/v1/passkey/signin-verify", signinBody, "", cookies, "", origin)
		if signinReplay.code < 400 || len(signinReplay.cookies) != 0 || signinReplay.header.Get("X-CSRF-Token") != "" {
			t.Fatal("signin replay redelivered authentication", signinReplay.code)
		}
		again := read(signin)
		if !again.Authenticated {
			t.Fatal("new HTTP passkey session inactive")
		}
		spec, err := again.Session.Bindings()
		if err != nil || spec.UserID != record.UserID {
			t.Fatal("signup key resolved different identity")
		}
		if spec.Remember.Choice() != choice || (signin.cookies[0].MaxAge > 0) != persistent || !persistent && !signin.cookies[0].Expires.IsZero() || spec.Remember.AbsoluteTTL() > c.HTTPPreAuth.Lifetime.AbsoluteTTL {
			t.Fatal("signin presentation changed original remember choice or expiry")
		}
		proveReferencePasskeySessionHTTP(t, ctx, handler, c, record.UserID, signin.cookies[0].Value, signin.header.Get("X-CSRF-Token"), func() bool { return read(signin).Authenticated })
	}
	count := uint32(1)
	if c.Passkey.SessionManagement != nil {
		count++
	}
	if c.HTTPPasskey.SessionEnrollment {
		count++
	} else if c.Passkey.SessionEnrollment != nil {
		count += 2
	}
	signinKey(private, id, count)
	if additionalKey != nil {
		signinKey(additionalKey, additionalID, 1)
	}
}
