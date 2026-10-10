//go:build integration

package passwordpostgres_test

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

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	database "github.com/faustbrian/go-postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// Exercise selected router/Feature/OpenAPI against real primary/proof/password/
// session/risk/journal owners as the restart and recovery journey. HTTPS facts
// are supplied in process, not proof of socket/browser/provider interoperability.
// No domain reader, atomic counter, workflow or terminal result is doubled.
func testCookiePasswordChangeHTTP(t *testing.T, ctx context.Context, pool *database.Pool, source passworddb.ReauthenticationConfig, workflow password.CookieChangeService, input password.CookieChangeRequest) password.ChangeResult {
	t.Helper()
	for _, migration := range []ratepg.Migration{ratepg.SchemaMigration(), ratepg.AtomicSchemaMigration()} {
		if _, err := pool.Raw().Exec(ctx, migration.Up); err != nil {
			t.Fatal("HTTP atomic schema unavailable", err)
		}
	}
	backend, err := ratepg.NewStrict(pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "password-http-native", Key: [32]byte{81}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rate.Close()
	sessions, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: source.Session, Profile: source.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: source.Profile.Audience, Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: source.LookupKeys}})
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := passworddb.NewRepository(pool, source.Repository)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	config := passwordhttp.ChangeConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: input.Request.TenantID}}}, Sessions: sessions, Proofs: proofs, CookieChange: workflow, Rate: rate, Transport: session.CredentialCookie, Cookie: cookie, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}, PolicyRevision: input.Request.Caller.PolicyRevision, Now: time.Now, MaximumDuration: 5 * time.Second}
	feature, err := passwordhttp.NewChangeFeature(config)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(ops) != 1 || ops[0].Record.OperationID != "identity.password.change" {
		t.Fatal("native feature selection failed", err)
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: config.Network, HandlerTimeout: config.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Native password change", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil || doc.Version() != "3.1.1" || len(doc.Operations()) != 1 {
		t.Fatal("native selected document unavailable", err)
	}
	validateResponse := func(w *httptest.ResponseRecorder) {
		t.Helper()
		schema := parsed.Raw()
		for _, key := range []string{"paths", "/v1/password/change", "post", "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
			var ok bool
			schema, ok = schema.Lookup(key)
			if !ok {
				t.Fatal("native response undocumented")
			}
		}
		instance, e := parse.JSON(ctx, bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
		if e != nil {
			t.Fatal("native response not JSON")
		}
		report, e := validate.SchemaInstance(ctx, parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if e != nil || !report.Valid() {
			t.Fatal("native response violates selected schema")
		}
	}
	csrf, err := input.CSRFToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	err = input.Request.Password.Use(func(raw []byte) error {
		var e error
		body, e = json.Marshal(map[string]string{"proofID": string(input.Request.Proof.Proof.ID), "newPassword": string(raw)})
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/password/change", bytes.NewReader(body)).WithContext(ctx)
		r.Host, r.RemoteAddr, r.TLS = "tenant.example", input.Request.Network+":1234", &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "password-cookie-committed")
		r.Header.Set("Origin", "https://tenant.example")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: input.Request.Session.Token()})
		return r
	}
	bad := request()
	bad.Header.Del("X-CSRF-Token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bad)
	validateResponse(w)
	var commands int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM rate_limit_atomic_commands`).Scan(&commands); err != nil || w.Code != 403 || commands != 0 {
		t.Fatal("malformed cookie request reached native admission", err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request())
	validateResponse(w)
	var out passwordhttp.ChangeResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 200 || !out.Changed || out.CommitOutcome != "committed" || out.CommandID == "" || out.CredentialVersion != 10 || !out.AuthorityInvalidated || out.Recovery == nil || out.Recovery.CommandID != out.CommandID || out.Recovery.TenantID != input.Request.TenantID || out.Recovery.RecordID != "reauth-password" {
		t.Fatalf("native HTTP change failed: status=%d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("HTTP disclosed replacement credentials")
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM rate_limit_atomic_commands`).Scan(&commands); err != nil || commands != 1 {
		t.Fatal("HTTP lost original atomic admission", err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request())
	validateResponse(w)
	var replay passwordhttp.ChangeResponse
	if json.Unmarshal(w.Body.Bytes(), &replay) != nil || w.Code != 200 || replay.CommandID != out.CommandID || replay.CommitOutcome != out.CommitOutcome || replay.CredentialVersion != out.CredentialVersion || !replay.Changed {
		t.Fatalf("native HTTP replay lost original outcome: status=%d", w.Code)
	}
	changed := request()
	changedBody, err := json.Marshal(map[string]string{"proofID": string(input.Request.Proof.Proof.ID), "newPassword": "different-synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(changedBody)
	changed.Body = http.NoBody
	changed = httptest.NewRequest(http.MethodPost, changed.URL.String(), bytes.NewReader(changedBody)).WithContext(ctx)
	original := request()
	changed.Header, changed.Host, changed.RemoteAddr, changed.TLS = original.Header, original.Host, original.RemoteAddr, original.TLS
	w = httptest.NewRecorder()
	h.ServeHTTP(w, changed)
	validateResponse(w)
	var conflict passwordhttp.ChangeResponse
	if json.Unmarshal(w.Body.Bytes(), &conflict) != nil || w.Code != 409 || conflict.CommitOutcome != "conflict" || conflict.CommandID != "" || conflict.Recovery != nil || conflict.Changed {
		t.Fatalf("native HTTP conflict lost pre-command shape: status=%d", w.Code)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM rate_limit_atomic_commands`).Scan(&commands); err != nil || commands != 1 {
		t.Fatal("HTTP replay minted another rate command", err)
	}
	return password.ChangeResult{CommandID: out.CommandID, Outcome: identity.CommitOutcomeCommitted, CredentialVersion: out.CredentialVersion, AuthorityInvalidated: out.AuthorityInvalidated}
}
