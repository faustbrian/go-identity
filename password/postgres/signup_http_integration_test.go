//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// Real selected transport, native workflow and strict primary rate owner. The
// parent fixture supplies explicit policy/provider callbacks, not domain stores;
// this is not live-provider, durable-risk or real-browser qualification.
func testNativeSignupHTTP(t *testing.T, ctx context.Context, service *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest, screens *atomic.Int32) {
	t.Helper()
	for _, migration := range []ratepg.Migration{ratepg.SchemaMigration(), ratepg.AtomicSchemaMigration()} {
		if _, err := service.pool.Raw().Exec(ctx, migration.Up); err != nil {
			t.Fatal("signup rate migration", err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := service.pool.Raw().Exec(cleanup, migration.Down); err != nil {
				t.Error("signup rate cleanup", err)
			}
		}()
	}
	backend, err := ratepg.NewStrict(service.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "signup-native", IdentifierKey: [32]byte{94}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rate.Close()
	original := fresh("http-signup@example.test", 'H')
	flowCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	deviceKey, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{95}, 32))
	deviceConfig := session.BrowserDeviceConfig{Namespace: "signup-native", Keys: []session.BrowserDeviceKey{deviceKey}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	codec, err := session.NewBrowserDeviceCodec(deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(ctx, time.Now(), original.TenantID, original.Origin)
	if err != nil {
		t.Fatal("original signup device", err)
	}
	deviceResponse := &http.Response{Header: http.Header{"Set-Cookie": []string{device.CookieHeader()}}}
	if len(deviceResponse.Cookies()) != 1 {
		t.Fatal("device fixture")
	}
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "identity.test", TenantID: original.TenantID}}}
	config := passwordhttp.SignupConfig{Network: network, Service: service, Rate: rate, Origin: identityhttp.Origin(original.Origin), CallbackURL: original.CallbackURL, Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, FlowCookie: flowCookie, Device: deviceConfig, FieldSchema: c.FieldSchema, ActorID: identity.ActorID(original.Caller.Request.Subject.ID), PolicyRevision: original.Caller.PolicyRevision, Now: time.Now, MaximumDuration: 5 * time.Second}
	build := func(selected *SignupService) (http.Handler, openapi.Document) {
		t.Helper()
		configuration := config
		configuration.Service = selected
		feature, err := passwordhttp.NewSignupFeature(configuration)
		if err != nil {
			t.Fatal("native signup feature", err)
		}
		ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		handler, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: network, HandlerTimeout: 5 * time.Second, Document: identityhttp.DocumentConfig{Title: "Native signup", Version: "1"}}, ops, nil)
		if err != nil || len(document.Operations()) != 1 || document.Version() != "3.1.1" {
			t.Fatal("selected signup router", err)
		}
		parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document.JSON()), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		return handler, parsed
	}
	handler, parsed := build(service)
	invoke := func(r password.SignupRequest, origin, address, key, ip string) (*httptest.ResponseRecorder, passwordhttp.SignupResponse) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"flowID": string(r.PreAuthID), "email": address, "password": " synthetic-password ", "callbackURL": r.CallbackURL, "remember": false, "allowedFields": []any{map[string]any{"name": "name", "kind": "string", "value": "http-requested-name"}}})
		if err != nil {
			t.Fatal("signup input fixture")
		}
		defer clear(body)
		request := httptest.NewRequest(http.MethodPost, "/v1/password/signup", bytes.NewReader(body)).WithContext(ctx)
		request.Host, request.RemoteAddr, request.TLS = "identity.test", ip+":1234", &tls.ConnectionState{}
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		request.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: r.Cookie.Token()})
		request.AddCookie(deviceResponse.Cookies()[0])
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request)
		if len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || bytes.Contains(w.Body.Bytes(), []byte("synthetic-password")) || bytes.Contains(w.Body.Bytes(), []byte(address)) || bytes.Contains(w.Body.Bytes(), []byte(key)) || bytes.Contains(w.Body.Bytes(), []byte(r.Cookie.Token())) || bytes.Contains(w.Body.Bytes(), []byte("http-requested-name")) {
			t.Fatal("signup disclosed submitted custody or issued credentials")
		}
		var out passwordhttp.SignupResponse
		if w.Header().Get("Content-Type") == "application/json" {
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal("signup response JSON", err)
			}
			schema := parsed.Raw()
			for _, name := range []string{"paths", "/v1/password/signup", "post", "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
				var ok bool
				schema, ok = schema.Lookup(name)
				if !ok {
					t.Fatal("undocumented signup response", w.Code)
				}
			}
			instance, err := parse.JSON(ctx, bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(ctx, parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatal("signup response violates wire schema", err)
			}
		}
		return w, out
	}
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := service.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity_password.credentials),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM capability_identity_one_use),(SELECT count(*) FROM signin_sessions.sessions)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal("primary signup observation", err)
		}
		return n
	}
	before := counts()
	if w, _ := invoke(original, "https://foreign.test", string(original.Email), "native-http-signup-key", "192.0.2.1"); w.Code != 403 {
		t.Fatal("foreign origin entered signup", w.Code)
	}
	var buckets int
	if err := service.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM rate_limit_states`).Scan(&buckets); err != nil || buckets != 0 || counts() != before {
		t.Fatal("foreign origin changed primary state", err)
	}
	w, out := invoke(original, original.Origin, string(original.Email), "native-http-signup-key", "192.0.2.1")
	if w.Code != 200 || !out.VerificationRequired || out.CommitOutcome != "committed" || out.Replayed || out.Recovery == nil || out.CommandID == "" {
		t.Fatal("native signup HTTP failed", w.Code, out.CommitOutcome, out.Error)
	}
	after := counts()
	if screens.Load() != 1 {
		t.Fatal("fresh signup did not screen exactly once")
	}
	if after != [5]int{before[0] + 1, before[1] + 1, before[2] + 1, before[3] + 1, before[4]} {
		t.Fatal("signup effects were not exactly one atomic creation")
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(out.CommandID))
	if err != nil {
		t.Fatal("command fixture")
	}
	var user string
	if err := service.pool.Raw().QueryRow(ctx, `SELECT user_id FROM identity.registration_bindings WHERE command_id=$1`, command).Scan(&user); err != nil {
		t.Fatal(err)
	}
	var document []byte
	// Independent version-one CBOR vector: [1, [["name", {kind: "string",
	// value: "http-requested-name"}]]]. Check the complete typed persisted value,
	// not merely whether a submitted substring occurs somewhere in the document.
	wantDocument := []byte("\x82\x01\x81\x82\x64name\xa2\x64kind\x66string\x65value\x73http-requested-name")
	if err := service.pool.Raw().QueryRow(ctx, `SELECT document FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2 AND schema_id=$3 AND schema_version=$4`, string(original.TenantID), user, c.FieldSchema.ID, c.FieldSchema.Version).Scan(&document); err != nil || !bytes.Equal(document, wantDocument) {
		t.Fatal("requested signup field was not preserved", err)
	}
	var bindings, messages, grants int
	if err := service.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.registration_bindings WHERE command_id=$1),(SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, command, string(out.CommandID)).Scan(&bindings, &messages, &grants); err != nil || bindings != 1 || messages != 1 || grants != 1 {
		t.Fatal("signup effects diverged from original command", err)
	}
	var state string
	if err := service.pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(original.PreAuthID)).Scan(&state); err != nil || state != "consumed" {
		t.Fatal("signup did not consume original flow atomically", err)
	}
	if _, err := service.pool.Raw().Exec(ctx, `DELETE FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(original.PreAuthID)); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewSignupService(service.pool, c, keys)
	if err != nil {
		t.Fatal(err)
	}
	handler, parsed = build(restarted)
	w, replay := invoke(original, original.Origin, string(original.Email), "native-http-signup-key", "192.0.2.1")
	if w.Code != 200 || !replay.VerificationRequired || !replay.Replayed || replay.CommandID != out.CommandID || replay.Recovery == nil || *replay.Recovery != *out.Recovery || counts() != after || screens.Load() != 1 {
		t.Fatal("restart/deleted-flow retry lost original history", w.Code, replay.Error)
	}
	q := out.Recovery
	if q.TenantID != original.TenantID || q.FlowID != original.PreAuthID || q.ActorID != config.ActorID || q.ActorKind != original.Caller.Request.Subject.Kind {
		t.Fatal("HTTP recovery retargeted original signup")
	}
	recovery, err := password.NewSignupRecovery(identity.RecoveryQuery{CommandID: q.CommandID, TenantID: q.TenantID, AnonymousFlowID: string(q.FlowID), ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: "identity.password.signup"}, q.FlowID)
	if err != nil {
		t.Fatal(err)
	}
	history, err := restarted.RecoverSignup(ctx, password.SignupRecoveryRequest{Recovery: recovery, Cookie: original.Cookie, Caller: original.Caller, Origin: original.Origin, Network: "192.0.2.1", Device: device.DeviceID()})
	if err != nil || history.Validate() != nil || history.Outcome != identity.CommitOutcomeCommitted || !history.VerificationRequired || !history.Replayed || history.SubjectID != "" || history.SessionID != "" || history.Session.Token != (session.Token{}) || screens.Load() != 1 || counts() != after {
		t.Fatal("restart recovery lost credential-free original history", err)
	}
	w, conflict := invoke(original, original.Origin, "changed-http@example.test", "native-http-signup-key", "192.0.2.3")
	if w.Code != 409 || conflict.Error != "conflict" || conflict.CommandID != "" || conflict.Recovery != nil || counts() != after {
		t.Fatal("changed keyed intent fabricated or replaced history", w.Code, conflict.Error)
	}
	occupied := fresh(string(original.Email), 'O')
	w, neutral := invoke(occupied, occupied.Origin, "http-signup@EXAMPLE.test", "native-http-occupied-key", "192.0.2.4")
	if w.Code != 200 || neutral.VerificationRequired != out.VerificationRequired || neutral.CommitOutcome != out.CommitOutcome || neutral.Replayed || neutral.Recovery == nil || neutral.CommandID == out.CommandID || counts() != after {
		t.Fatal("occupied signup disclosed or regenerated material", w.Code, neutral.Error)
	}
	// Canonical domain case shares the same three-per-day identifier bucket;
	// the new IP has budget and cannot bypass it. No fourth native attempt runs.
	w, limited := invoke(occupied, occupied.Origin, string(original.Email), "native-http-fourth-key", "192.0.2.5")
	if w.Code != 429 || limited.Error != "rate_limited" || limited.CommandID != "" || w.Header().Get("Retry-After") == "" || counts() != after {
		t.Fatal("canonical signup identifier budget diverged", w.Code, limited.Error)
	}
	if err := service.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM rate_limit_states`).Scan(&buckets); err != nil || buckets != 6 {
		t.Fatal("native signup admission did not use primary shared buckets", err, buckets)
	}
}
