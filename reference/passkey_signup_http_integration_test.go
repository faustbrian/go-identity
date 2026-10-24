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
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
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
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	origin := c.Passkey.Signup.Flow.Origin
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	type response struct {
		code    int
		header  http.Header
		body    []byte
		cookies []*http.Cookie
	}
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
		got := call("/v1/session/preauth-issue", map[string]any{"method": method, "remember": false}, "", retained, "", origin)
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
	var events, identifiers, passwords int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$1 AND topic IN ('identity.passkey.create_credential','user.created.v1','session.created.v1')),(SELECT count(*) FROM identity.identifiers WHERE user_id=$2),(SELECT count(*) FROM identity_password.credentials WHERE user_id=$2)`, string(command), string(record.UserID)).Scan(&events, &identifiers, &passwords); err != nil || events != 3 || identifiers != 0 || passwords != 0 {
		t.Fatal("HTTP signup lost atomic effects or invented fallback", err, events, identifiers, passwords)
	}
	proveReferencePasskeySessionHTTP(t, ctx, handler, c, record.UserID, issued.cookies[0].Value, issued.header.Get("X-CSRF-Token"), func() bool { return read(issued).Authenticated })
	flowID, cookies = flow("passkey")
	assertionOptions := call("/v1/passkey/signin-options", map[string]any{"mode": "discoverable", "flowID": flowID}, "reference-http-signup-signin", cookies, "", origin)
	if assertionOptions.code != 200 || json.Unmarshal(assertionOptions.body, &created) != nil || json.Unmarshal(created.Options, &protocol) != nil {
		t.Fatal("fresh HTTP signup-key signin options", assertionOptions.code)
	}
	command, _ = identity.NewCommandID()
	signin := call("/v1/passkey/signin-verify", map[string]any{"mode": "discoverable", "flowID": flowID, "commandID": command, "ceremonyID": created.CommandID, "response": json.RawMessage(referencePasskeyAssertion(t, private, id, handle, protocol.PublicKey.Challenge))}, "", cookies, "", origin)
	if signin.code != 200 || len(signin.cookies) != 1 || signin.header.Get("X-CSRF-Token") == "" {
		t.Fatal("signup key fresh HTTP signin", signin.code)
	}
	again := read(signin)
	if !again.Authenticated {
		t.Fatal("new HTTP passkey session inactive")
	}
	spec, err := again.Session.Bindings()
	if err != nil || spec.UserID != record.UserID {
		t.Fatal("signup key resolved different identity")
	}
	proveReferencePasskeySessionHTTP(t, ctx, handler, c, record.UserID, signin.cookies[0].Value, signin.header.Get("X-CSRF-Token"), func() bool { return read(signin).Authenticated })
}
