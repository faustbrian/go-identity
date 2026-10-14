//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
)

// This fixture composes real selected routes with the parent's real primary
// reset/delivery/session owners and native strict rate adapter. It adds no
// workflow double or consumer-written domain glue. External provider/risk
// callbacks retain the parent's explicit fixture boundary.
type resetHTTPFixture struct {
	t        *testing.T
	ctx      context.Context
	handler  http.Handler
	document openapi.Document
	device   *http.Cookie
}

func newResetHTTPFixture(t *testing.T, ctx context.Context, service *ResetService, r password.ResetRequestRequest) (*resetHTTPFixture, password.ResetRequestRequest) {
	t.Helper()
	for _, migration := range []ratepg.Migration{ratepg.SchemaMigration(), ratepg.AtomicSchemaMigration()} {
		if _, err := service.pool.Raw().Exec(ctx, migration.Up); err != nil {
			t.Fatal("reset HTTP rate history", err)
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := service.pool.Raw().Exec(cleanup, migration.Down); err != nil {
				t.Error("reset HTTP rate cleanup", err)
			}
		})
	}
	backend, err := ratepg.NewStrict(service.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	requestRate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "reset-native-delivery", IdentifierKey: [32]byte{111}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { requestRate.Close() })
	completionRate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "reset-native-verify", Key: [32]byte{112}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { completionRate.Close() })
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	key, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{113}, 32))
	deviceConfig := session.BrowserDeviceConfig{Namespace: "reset-native", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: cookie}
	codec, err := session.NewBrowserDeviceCodec(deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(ctx, time.Now(), r.TenantID, r.Origin)
	if err != nil {
		t.Fatal(err)
	}
	response := http.Response{Header: http.Header{"Set-Cookie": []string{device.CookieHeader()}}}
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatal("reset device fixture")
	}
	r.Device = device.DeviceID()
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "identity.test", TenantID: r.TenantID}}}
	requestConfig := passwordhttp.ResetRequestConfig{Network: network, Service: service, Rate: requestRate, Origin: identityhttp.Origin(r.Origin), CallbackURL: r.CallbackURL, Device: deviceConfig, ActorID: signinTestActor, PolicyRevision: r.Caller.PolicyRevision, Now: time.Now, MaximumDuration: 5 * time.Second}
	completionConfig := passwordhttp.ResetCompleteConfig{Network: network, Service: service, Rate: completionRate, Origin: identityhttp.Origin(r.Origin), Device: deviceConfig, ActorID: signinTestActor, PolicyRevision: r.Caller.PolicyRevision, Now: time.Now, MaximumDuration: 5 * time.Second}
	feature, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{ResetRequest: &requestConfig, ResetComplete: &completionConfig})
	if err != nil {
		t.Fatal("native reset feature", err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	handler, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: network, HandlerTimeout: 5 * time.Second, Document: identityhttp.DocumentConfig{Title: "Native reset", Version: "1"}}, ops, nil)
	if err != nil || len(document.Operations()) != 2 {
		t.Fatal("native reset selected router", err)
	}
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return &resetHTTPFixture{t: t, ctx: ctx, handler: handler, document: parsed, device: cookies[0]}, r
}

func (f *resetHTTPFixture) invoke(path, origin, network, key string, body []byte) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)).WithContext(f.ctx)
	r.Host, r.RemoteAddr, r.TLS = "identity.test", network+":1234", &tls.ConnectionState{}
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	r.AddCookie(f.device)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
		f.t.Fatal("reset HTTP delivered credentials or cacheable output")
	}
	if w.Header().Get("Content-Type") == "application/json" {
		schema := f.document.Raw()
		for _, name := range []string{"paths", path, "post", "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
			var ok bool
			schema, ok = schema.Lookup(name)
			if !ok {
				f.t.Fatal("undocumented reset HTTP outcome", w.Code)
			}
		}
		instance, err := parse.JSON(f.ctx, bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
		if err != nil {
			f.t.Fatal(err)
		}
		report, err := validate.SchemaInstance(f.ctx, f.document, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || !report.Valid() {
			f.t.Fatal("reset HTTP response violates actual schema", err)
		}
	}
	return w
}

func (f *resetHTTPFixture) request(r password.ResetRequestRequest) password.ResetRequestResult {
	f.t.Helper()
	body, err := json.Marshal(map[string]string{"commandID": string(r.CommandID), "identifier": string(r.Identifier), "callbackURL": r.CallbackURL})
	if err != nil {
		f.t.Fatal(err)
	}
	defer clear(body)
	if w := f.invoke("/v1/password/reset-request", "https://foreign.test", r.Network, "synthetic-public-reset-request-001", body); w.Code != 403 {
		f.t.Fatal("foreign reset Origin reached workflow")
	}
	w := f.invoke("/v1/password/reset-request", r.Origin, r.Network, "synthetic-public-reset-request-001", body)
	var out passwordhttp.ResetRequestResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 200 || !out.Accepted || out.CommitOutcome != "committed" || out.Recovery == nil || out.Recovery.AttemptID != r.CommandID {
		f.t.Fatal("native reset request HTTP", w.Code, out.Error)
	}
	if bytes.Contains(w.Body.Bytes(), []byte(r.Identifier)) {
		f.t.Fatal("reset request disclosed mailbox")
	}
	again := f.invoke("/v1/password/reset-request", r.Origin, r.Network, "synthetic-public-reset-request-001", body)
	if again.Code != 200 || !bytes.Equal(again.Body.Bytes(), w.Body.Bytes()) {
		f.t.Fatal("fresh HTTP correlation broke original request retry", again.Code)
	}
	return password.ResetRequestResult{CommandID: out.CommandID, Outcome: identity.CommitOutcomeCommitted, Accepted: true}
}

func (f *resetHTTPFixture) complete(r password.ResetCompleteRequest) password.ResetCompleteResult {
	f.t.Helper()
	var body []byte
	err := r.Token.Transfer(f.ctx, func(_ context.Context, raw []byte) error {
		return r.NewPassword.Use(func(secret []byte) error {
			var err error
			body, err = json.Marshal(map[string]string{"commandID": string(r.CommandID), "token": string(raw), "newPassword": string(secret)})
			return err
		})
	})
	if err != nil {
		f.t.Fatal("reset HTTP input custody", err)
	}
	defer clear(body)
	w := f.invoke("/v1/password/reset-complete", r.Origin, r.Network, "", body)
	var out passwordhttp.ResetCompleteResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 200 || !out.Completed || out.CommitOutcome != "committed" || !out.SessionsRevoked || out.Recovery == nil {
		f.t.Fatal("native reset completion HTTP", w.Code, out.Error)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("synthetic-full-public-reset")) {
		f.t.Fatal("reset completion disclosed password")
	}
	again := f.invoke("/v1/password/reset-complete", r.Origin, r.Network, "", body)
	if again.Code != 200 || !bytes.Equal(again.Body.Bytes(), w.Body.Bytes()) {
		f.t.Fatal("fresh HTTP correlation broke original completion replay", again.Code)
	}
	var changed map[string]string
	if err := json.Unmarshal(body, &changed); err != nil {
		f.t.Fatal(err)
	}
	changed["newPassword"] = "synthetic-conflicting-reset-password"
	changedBody, err := json.Marshal(changed)
	clear(changed)
	if err != nil {
		f.t.Fatal(err)
	}
	conflicting := f.invoke("/v1/password/reset-complete", r.Origin, r.Network, "", changedBody)
	clear(changedBody)
	var denied passwordhttp.ResetCompleteResponse
	if json.Unmarshal(conflicting.Body.Bytes(), &denied) != nil || conflicting.Code != http.StatusConflict || denied.Completed || denied.SessionsRevoked {
		f.t.Fatal("changed password reused committed reset command", conflicting.Code)
	}
	// The conflicting retry must neither replace the original result nor
	// contaminate the journal's original immutable input.
	original := f.invoke("/v1/password/reset-complete", r.Origin, r.Network, "", body)
	if original.Code != http.StatusOK || !bytes.Equal(original.Body.Bytes(), w.Body.Bytes()) {
		f.t.Fatal("conflicting reset retry corrupted original result", original.Code)
	}
	return password.ResetCompleteResult{CommandID: out.CommandID, Outcome: identity.CommitOutcomeCommitted, CredentialVersion: out.CredentialVersion, SessionsRevoked: out.SessionsRevoked}
}
