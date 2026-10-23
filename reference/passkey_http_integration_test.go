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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// Route the TLS socket to the disposable loopback listener without changing
// the real RP/origin/tenant authority exercised by the server and authenticator.
type passkeyFixtureHostTransport struct{ next http.RoundTripper }

func (p passkeyFixtureHostTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	owned := r.Clone(r.Context())
	owned.Host = "identity.example"
	return p.next.RoundTrip(owned)
}

func TestReferencePostgresPasskeyHTTP(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		for _, upgrade := range []bool{false, true} {
			name := "identified"
			if discoverable {
				name = "discoverable"
			}
			if upgrade {
				name += "/populated-upgrade"
			} else {
				name += "/fresh"
			}
			t.Run(name, func(t *testing.T) {
				proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passkey: true, passkeyKeyed: true, passkeySessionHTTP: true, passkeyHTTP: true, passkeyUpgrade: upgrade, passkeyDiscovery: discoverable}, true)
			})
		}
	}
}

func proveReferencePasskeyHTTPPrimarySelection(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies) {
	t.Helper()
	for _, options := range []bool{true, false} {
		selected := c
		native := *c.Passkey
		selected.Passkey = &native
		if options {
			native.OptionsPrimary.Transport = session.CredentialBearer
		} else {
			native.RegistrationPrimary.Transport = session.CredentialBearer
		}
		// The otherwise valid native bearer profile remains available. Only the
		// separately selected cookie-only transport must reject this mismatch.
		selected.HTTPPasskey = nil
		graph, err := reference.ComposeStores(selected, deps)
		if err != nil {
			t.Fatal("valid native bearer primary was removed", err)
		}
		bounded, stop := context.WithTimeout(t.Context(), time.Second)
		closeErr := graph.Close(bounded)
		stop()
		if closeErr != nil {
			t.Fatal("native primary selection cleanup", closeErr)
		}
		selected.HTTPPasskey = c.HTTPPasskey
		graph, err = reference.ComposeStores(selected, deps)
		if err == nil {
			bounded, stop = context.WithTimeout(t.Context(), time.Second)
			_ = graph.Close(bounded)
			stop()
			t.Fatal("cookie HTTP registration accepted a bearer action primary", "options", options)
		}
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) || invalid.Field != "reference_http_passkey" {
			t.Fatal("incompatible primary did not reach HTTP selection guard", err)
		}
	}
	selected := c
	native := *c.Passkey
	native.Flow.Origin = "https://identity.example:8443"
	native.Flow.CallbackURL = native.Flow.Origin + "/callback"
	native.Protocol.RelyingParty.Origins = append(append([]string(nil), native.Protocol.RelyingParty.Origins...), native.Flow.Origin)
	selected.Passkey = &native
	selected.HTTPPasskey = nil
	graph, err := reference.ComposeStores(selected, deps)
	if err != nil {
		t.Fatal("valid independent native RP origin was removed", err)
	}
	bounded, stop := context.WithTimeout(t.Context(), time.Second)
	closeErr := graph.Close(bounded)
	stop()
	if closeErr != nil {
		t.Fatal("native origin selection cleanup", closeErr)
	}
	selected.HTTPPasskey = &reference.HTTPPasskeyConfiguration{Registration: true}
	graph, err = reference.ComposeStores(selected, deps)
	if err == nil {
		bounded, stop = context.WithTimeout(t.Context(), time.Second)
		_ = graph.Close(bounded)
		stop()
		t.Fatal("registration-only HTTP accepted an incompatible shared device origin")
	}
	var invalid identity.InvalidInputError
	if !errors.As(err, &invalid) || invalid.Field != "reference_http_passkey" {
		t.Fatal("incompatible device origin did not reach HTTP selection guard", err)
	}
}

// Only authenticator bytes are controlled. The actual graph owns registration,
// verification delivery, password sessions, signed proofs, ceremony, rate,
// mapping, inventory and passkey session effects. No SQL or fake workflow seam.
func proveReferencePasskeyHTTP(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, user identity.UserID, cookies []*http.Cookie, csrfWire string, discoverable bool, handler http.Handler, document []byte) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document), parse.DefaultLimits())
	if err != nil {
		t.Fatal("selected immutable HTTP document invalid", err)
	}
	origin := c.Passkey.Flow.Origin
	var deviceCookie *http.Cookie
	type wireResult struct {
		code    int
		header  http.Header
		body    []byte
		cookies []*http.Cookie
	}
	request := func(method, path string, body any, key, csrf string, selected []*http.Cookie, trustedOrigin string) wireResult {
		t.Helper()
		var payload io.Reader
		if body != nil {
			wire, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			payload = bytes.NewReader(wire)
		}
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, payload)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = strings.TrimPrefix(origin, "https://")
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if trustedOrigin != "" {
			r.Header.Set("Origin", trustedOrigin)
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		for _, cookie := range selected {
			r.AddCookie(cookie)
		}
		if deviceCookie != nil {
			r.AddCookie(deviceCookie)
		}
		out, err := client.Do(r)
		if err != nil {
			t.Fatal("passkey HTTPS request failed")
		}
		defer out.Body.Close()
		wire, err := io.ReadAll(io.LimitReader(out.Body, 65537))
		if err != nil || len(wire) > 65536 {
			t.Fatal("passkey response bound")
		}
		if strings.HasPrefix(path, "/v1/passkey/") {
			if method == http.MethodPost && out.StatusCode == http.StatusOK {
				node := parsed.Raw()
				for _, field := range []string{"paths", path, "post", "requestBody", "content", "application/json", "schema"} {
					var found bool
					node, found = node.Lookup(field)
					if !found {
						t.Fatal("successful HTTP input has no declared schema", path, field)
					}
				}
				actual, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				instance, err := parse.JSON(ctx, bytes.NewReader(actual), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				report, err := validate.SchemaInstance(ctx, parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionRequest})
				if err != nil || !report.Valid() {
					t.Fatal("successful HTTP request violates declared wire", path, err)
				}
			}
			media := "application/json"
			instanceWire := wire
			if strings.HasPrefix(out.Header.Get("Content-Type"), "text/plain") {
				media = "text/plain"
				instanceWire, err = json.Marshal(string(wire))
				if err != nil {
					t.Fatal(err)
				}
			}
			node := parsed.Raw()
			pathOnly, _, _ := strings.Cut(path, "?")
			for _, field := range []string{"paths", pathOnly, strings.ToLower(method), "responses", strconv.Itoa(out.StatusCode), "content", media, "schema"} {
				var found bool
				node, found = node.Lookup(field)
				if !found {
					t.Fatal("actual HTTP result has no declared schema", path, out.StatusCode, field)
				}
			}
			instance, err := parse.JSON(ctx, bytes.NewReader(instanceWire), parse.DefaultLimits())
			if err != nil {
				t.Fatal("actual passkey JSON invalid", path, out.StatusCode)
			}
			report, err := validate.SchemaInstance(ctx, parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatal("actual passkey result violates declared wire", path, out.StatusCode, err)
			}
		}
		return wireResult{out.StatusCode, out.Header, wire, out.Cookies()}
	}
	// Obtain the real device and original flow together through the selected
	// HTTP issuer. Signing a device directly here would miss deployment-origin
	// mismatches between that issuer and the enrollment transport.
	flow := request(http.MethodPost, "/v1/session/preauth-issue", map[string]any{"method": "passkey", "remember": false}, "", "", nil, origin)
	var flowOut struct {
		Issued bool   `json:"issued"`
		FlowID string `json:"flowID"`
	}
	if flow.code != 200 || json.Unmarshal(flow.body, &flowOut) != nil || !flowOut.Issued || flowOut.FlowID == "" {
		t.Fatal("actual HTTP passkey original flow", flow.code, "bytes", len(flow.body))
	}
	var flowCookies []*http.Cookie
	for _, cookie := range flow.cookies {
		switch cookie.Name {
		case "__Host-identity_flow":
			flowCookies = append(flowCookies, cookie)
		case "__Host-identity_device":
			if deviceCookie != nil {
				t.Fatal("HTTP initiation repeated device cookie")
			}
			deviceCookie = cookie
		}
	}
	if len(flowCookies) != 1 || deviceCookie == nil {
		t.Fatal("original HTTP flow/device cookies missing")
	}
	proof := func(action string) string {
		t.Helper()
		got := request(http.MethodPost, "/v1/password/verify", map[string]string{"password": "synthetic-registration-password", "purpose": "identity.password.verify", "action": action, "audience": "reference-passkey"}, "", csrfWire, cookies, origin)
		var out passwordhttp.VerificationResponse
		if got.code != 200 || json.Unmarshal(got.body, &out) != nil || !out.Verified || out.Proof == nil || out.Proof.ProofID == "" || out.CommitOutcome != "committed" || len(got.cookies) != 0 {
			t.Fatal("genuine HTTP enrollment action proof", got.code)
		}
		return out.Proof.ProofID
	}
	type optionsResult struct {
		CommandID     string          `json:"commandID"`
		CommitOutcome string          `json:"commitOutcome"`
		Replayed      bool            `json:"replayed"`
		Options       json.RawMessage `json:"options"`
	}
	options := func(path string, body any, key string, selected []*http.Cookie, csrf string) optionsResult {
		t.Helper()
		first := request(http.MethodPost, path, body, key, csrf, selected, origin)
		var out optionsResult
		if first.code != 200 || json.Unmarshal(first.body, &out) != nil || out.CommandID == "" || out.CommitOutcome != "committed" || out.Replayed || len(out.Options) == 0 || len(first.cookies) != 0 {
			t.Fatal("fresh original HTTP options", path, first.code, "bytes", len(first.body))
		}
		retry := request(http.MethodPost, path, body, key, csrf, selected, origin)
		var replay optionsResult
		if retry.code != 200 || json.Unmarshal(retry.body, &replay) != nil || !replay.Replayed || replay.CommandID != out.CommandID || replay.CommitOutcome != "committed" || len(replay.Options) != 0 || len(retry.cookies) != 0 {
			t.Fatal("HTTP options replay repeated challenge or lost metadata", path, retry.code)
		}
		return out
	}
	registrationProof := proof("identity.passkey.register-options")
	registrationBody := map[string]any{"proofID": registrationProof}
	for _, denied := range []struct{ origin, csrf string }{{origin, "wrong"}, {"https://foreign.example", csrfWire}} {
		got := request(http.MethodPost, "/v1/passkey/register-options", registrationBody, "denied-enrollment", denied.csrf, cookies, denied.origin)
		if got.code != 403 || len(got.cookies) != 0 || bytes.Contains(got.body, []byte("challenge")) {
			t.Fatal("enrollment origin/CSRF denial", got.code)
		}
	}
	registrationOptions := options("/v1/passkey/register-options", registrationBody, "reference-http-enrollment", cookies, csrfWire)
	var creation struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(registrationOptions.Options, &creation) != nil || creation.PublicKey.Challenge == "" || creation.PublicKey.User.ID == "" {
		t.Fatal("native registration transfer absent")
	}
	userHandle, err := base64.RawURLEncoding.DecodeString(creation.PublicKey.User.ID)
	if err != nil {
		t.Fatal("native user handle encoding")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	completionID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	registrationCompletion := map[string]any{"proofID": registrationProof, "commandID": completionID, "ceremonyID": registrationOptions.CommandID, "label": "HTTP key", "response": json.RawMessage(referencePasskeyRegistration(t, key, id, creation.PublicKey.Challenge))}
	wrongPhase := request(http.MethodPost, "/v1/passkey/register-verify", registrationCompletion, "", csrfWire, cookies, origin)
	if wrongPhase.code != 403 || len(wrongPhase.cookies) != 0 {
		t.Fatal("options proof crossed HTTP enrollment phases", wrongPhase.code)
	}
	registrationCompletion["proofID"] = proof("identity.passkey.register-verify")
	registered := request(http.MethodPost, "/v1/passkey/register-verify", registrationCompletion, "", csrfWire, cookies, origin)
	var registeredOut struct {
		Registered    bool   `json:"registered"`
		CommitOutcome string `json:"commitOutcome"`
	}
	if registered.code != 200 || json.Unmarshal(registered.body, &registeredOut) != nil || !registeredOut.Registered || registeredOut.CommitOutcome != "committed" || len(registered.cookies) != 0 {
		t.Fatal("actual HTTP enrollment", registered.code, "bytes", len(registered.body))
	}
	registrationReplay := request(http.MethodPost, "/v1/passkey/register-verify", registrationCompletion, "", csrfWire, cookies, origin)
	var replayedRegistration struct {
		Registered bool `json:"registered"`
	}
	if json.Unmarshal(registrationReplay.body, &replayedRegistration) != nil || replayedRegistration.Registered || len(registrationReplay.cookies) != 0 {
		t.Fatal("enrollment replay repeated verification")
	}
	signinBody := map[string]any{"mode": "identified", "flowID": flowOut.FlowID, "identifier": "registered@example.invalid"}
	if discoverable {
		signinBody["mode"] = "discoverable"
		delete(signinBody, "identifier")
	}
	assertionOptions := options("/v1/passkey/signin-options", signinBody, "reference-http-signin", flowCookies, "")
	var assertion struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(assertionOptions.Options, &assertion) != nil || assertion.PublicKey.Challenge == "" {
		t.Fatal("native assertion transfer absent")
	}
	signinID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	signinBody["commandID"], signinBody["ceremonyID"] = signinID, assertionOptions.CommandID
	signinBody["response"] = json.RawMessage(referencePasskeyAssertion(t, key, id, userHandle, assertion.PublicKey.Challenge))
	foreign, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	foreignWire, err := foreign.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	wrongBrowser := request(http.MethodPost, "/v1/passkey/signin-verify", signinBody, "", "", []*http.Cookie{{Name: "__Host-identity_flow", Value: foreignWire}}, origin)
	if wrongBrowser.code != 403 || len(wrongBrowser.cookies) != 0 {
		t.Fatal("foreign original browser reached HTTP signin", wrongBrowser.code)
	}
	if discoverable {
		signinBody["mode"], signinBody["identifier"] = "identified", "registered@example.invalid"
	} else {
		signinBody["mode"] = "discoverable"
		delete(signinBody, "identifier")
	}
	wrongMode := request(http.MethodPost, "/v1/passkey/signin-verify", signinBody, "", "", flowCookies, origin)
	wantModeStatus := http.StatusForbidden
	if !discoverable {
		// Identifier-free input is outside the selected transport schema. When
		// enabled, changing an original discovery flow instead reaches the
		// native source-owner denial without consuming the genuine ceremony.
		wantModeStatus = http.StatusBadRequest
	}
	if wrongMode.code != wantModeStatus || len(wrongMode.cookies) != 0 {
		t.Fatal("original HTTP signin changed mode", wrongMode.code)
	}
	if discoverable {
		signinBody["mode"] = "discoverable"
		delete(signinBody, "identifier")
	} else {
		signinBody["mode"], signinBody["identifier"] = "identified", "registered@example.invalid"
	}
	signed := request(http.MethodPost, "/v1/passkey/signin-verify", signinBody, "", "", flowCookies, origin)
	var signinOut struct {
		SignedIn      bool   `json:"signedIn"`
		CommitOutcome string `json:"commitOutcome"`
	}
	if signed.code != 200 || json.Unmarshal(signed.body, &signinOut) != nil || !signinOut.SignedIn || signinOut.CommitOutcome != "committed" {
		t.Fatal("actual HTTP passkey signin", signed.code, "bytes", len(signed.body))
	}
	sessionCookie, err := c.Session.Native.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	var issued []*http.Cookie
	for _, cookie := range signed.cookies {
		if cookie.Name == sessionCookie.Name {
			issued = append(issued, cookie)
		}
	}
	if len(issued) != 1 || issued[0].Value == "" || issued[0].MaxAge != 0 || !issued[0].Expires.IsZero() || !issued[0].Secure || !issued[0].HttpOnly {
		t.Fatal("browser remember policy or cookie custody changed")
	}
	signinReplay := request(http.MethodPost, "/v1/passkey/signin-verify", signinBody, "", "", flowCookies, origin)
	var replayedSignin struct {
		SignedIn bool `json:"signedIn"`
	}
	if json.Unmarshal(signinReplay.body, &replayedSignin) != nil || replayedSignin.SignedIn || len(signinReplay.cookies) != 0 || signinReplay.header.Get("X-CSRF-Token") != "" {
		t.Fatal("HTTP signin replay redelivered authentication")
	}
	foreignInventory := request(http.MethodGet, "/v1/passkey/list?userID=foreign", nil, "", "", issued, "")
	if foreignInventory.code != 400 || len(foreignInventory.cookies) != 0 {
		t.Fatal("HTTP inventory selected a foreign owner", foreignInventory.code)
	}
	inventory := request(http.MethodGet, "/v1/passkey/list", nil, "", "", issued, "")
	var page struct {
		Credentials []struct {
			Label string `json:"label"`
		} `json:"credentials"`
	}
	if inventory.code != 200 || json.Unmarshal(inventory.body, &page) != nil || len(page.Credentials) != 1 || page.Credentials[0].Label != "HTTP key" || bytes.Contains(inventory.body, []byte(creation.PublicKey.User.ID)) || bytes.Contains(inventory.body, []byte(base64.RawURLEncoding.EncodeToString(id))) {
		t.Fatal("safe HTTP inventory", inventory.code)
	}
	common, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(issued[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	proveReferencePasskeySessionHTTP(t, ctx, handler, c, user, issued[0].Value, signed.header.Get("X-CSRF-Token"), func() bool {
		out, err := common.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		return err == nil && out.Authenticated
	})
}
