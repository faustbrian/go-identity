//go:build integration

package passwordintegration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
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

// Real primary/rate/password/proof/command owners are reached through selected
// HTTP. Loading the signed original by its returned locator retains native
// authority; the client projection is never reconstructed into a proof.
func testBearerPasswordVerificationHTTP(t *testing.T, ctx context.Context, pool *database.Pool, source passworddb.ReauthenticationConfig, workflow password.VerificationService, input passworddb.ReauthenticationRequest) password.VerificationResult {
	return testPasswordVerificationHTTP(t, ctx, pool, source, workflow, nil, input, "")
}

func testCookiePasswordVerificationHTTP(t *testing.T, ctx context.Context, pool *database.Pool, source passworddb.ReauthenticationConfig, workflow password.CookieVerificationService, input password.CookieVerificationRequest, csrf string) password.VerificationResult {
	r := input.Request
	request := passworddb.ReauthenticationRequest{TenantID: r.TenantID, Session: r.Session, Password: r.Password, Target: passworddb.ReauthenticationTarget{Purpose: r.Target.Purpose, Action: r.Target.Action, Audience: r.Target.Audience}, Caller: r.Caller, Network: r.Network, Device: r.Device}
	return testPasswordVerificationHTTP(t, ctx, pool, source, nil, workflow, request, csrf)
}

func testPasswordVerificationHTTP(t *testing.T, ctx context.Context, pool *database.Pool, source passworddb.ReauthenticationConfig, workflow password.VerificationService, cookieWorkflow password.CookieVerificationService, input passworddb.ReauthenticationRequest, csrf string) password.VerificationResult {
	t.Helper()
	for _, migration := range []ratepg.Migration{ratepg.SchemaMigration(), ratepg.AtomicSchemaMigration()} {
		if _, err := pool.Raw().Exec(ctx, migration.Up); err != nil {
			t.Fatal("verification rate migration failed", err)
		}
		// This helper owns disposable rate tables; later change qualification
		// installs its own fresh schema and asserts its own command population.
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := pool.Raw().Exec(cleanup, migration.Down); err != nil {
				t.Error("verification rate cleanup failed", err)
			}
		}()
	}
	backend, err := ratepg.NewStrict(pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewPasswordVerificationRateLimiter(identityhttp.PasswordVerificationRateConfig{Shared: backend, Namespace: "password-verify-native", Key: [32]byte{82}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rate.Close()
	sessions, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: source.Session, Profile: source.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: source.Profile.Audience, Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: source.LookupKeys}})
	if err != nil {
		t.Fatal(err)
	}
	c := passwordhttp.BearerVerificationConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: input.TenantID}}}, Sessions: sessions, Verification: workflow, Rate: rate, PolicyRevision: authorization.Revision(source.Coordinator.QueryPolicy.PolicyVersion), Now: time.Now, MaximumDuration: 5 * time.Second}
	key, err := session.NewBrowserDeviceKey(1, []byte("native-verification-device-key-01"))
	if err != nil {
		t.Fatal(err)
	}
	cookiePolicy, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	deviceConfig := session.BrowserDeviceConfig{Namespace: "native-verification-test", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: cookiePolicy}
	codec, err := session.NewBrowserDeviceCodec(deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	// Initialization issues once at the trusted test boundary; the verifier
	// receives only original custody and cannot mint or replace it.
	device, err := codec.Issue(ctx, time.Now(), input.TenantID, "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := http.ParseSetCookie(device.CookieHeader())
	if err != nil {
		t.Fatal(err)
	}
	var feature identityhttp.Feature
	if cookieWorkflow == nil {
		feature, err = passwordhttp.NewBrowserDeviceBearerVerificationFeature(passwordhttp.BrowserDeviceBearerVerificationConfig{Verification: c, Device: deviceConfig})
	} else {
		policy, e := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
		if e != nil {
			t.Fatal(e)
		}
		feature, err = passwordhttp.NewCookieVerificationFeature(passwordhttp.CookieVerificationConfig{Network: c.Network, Sessions: c.Sessions, Verification: cookieWorkflow, Rate: c.Rate, Cookie: policy, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}, Device: deviceConfig, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration})
	}
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Native verification", Version: "1"}}, ops, nil)
	if err != nil || len(doc.Operations()) != 1 {
		t.Fatal("verification router unavailable", err)
	}
	var body []byte
	err = input.Password.Use(func(raw []byte) error {
		var e error
		body, e = json.Marshal(map[string]string{"password": string(raw), "purpose": string(input.Target.Purpose), "action": input.Target.Action, "audience": input.Target.Audience})
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	request := func(includeDevice bool) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/password/verify", bytes.NewReader(body)).WithContext(ctx)
		r.Host, r.RemoteAddr, r.TLS = "tenant.example", input.Network+":1234", &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		if cookieWorkflow == nil {
			r.Header.Set("Authorization", "Bearer "+input.Session.Token())
		} else {
			r.Header.Set("Origin", "https://tenant.example")
			r.Header.Set("X-CSRF-Token", csrf)
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: input.Session.Token()})
		}
		if includeDevice {
			r.AddCookie(deviceCookie)
		}
		return r
	}
	r := request(false)
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, r)
	var commands int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM rate_limit_atomic_commands`).Scan(&commands); err != nil || denied.Code != 400 || commands != 0 || len(denied.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("missing original device custody reached native admission", err)
	}
	if cookieWorkflow != nil {
		bad := request(true)
		bad.Header.Del("X-CSRF-Token")
		denied = httptest.NewRecorder()
		h.ServeHTTP(denied, bad)
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM rate_limit_atomic_commands`).Scan(&commands); err != nil || denied.Code != 403 || commands != 0 || bytes.Contains(denied.Body.Bytes(), []byte("proofID")) {
			t.Fatal("missing synchronizer reached native admission", err)
		}
	}
	r = request(true)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out passwordhttp.VerificationResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 200 || !out.Verified || out.Proof == nil || out.CommitOutcome != "committed" || out.CommandID == "" {
		t.Fatalf("native selected verification did not commit: status=%d outcome=%s", w.Code, out.CommitOutcome)
	}
	if w.Header().Get("Cache-Control") != "no-store" || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("native verification leaked response custody")
	}
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil || doc.Version() != "3.1.1" {
		t.Fatal("native verification document unavailable", err)
	}
	validateResponse := func(response *httptest.ResponseRecorder) {
		t.Helper()
		schema := parsed.Raw()
		for _, key := range []string{"paths", "/v1/password/verify", "post", "responses", strconv.Itoa(response.Code), "content", "application/json", "schema"} {
			var ok bool
			schema, ok = schema.Lookup(key)
			if !ok {
				t.Fatal("native verification response undocumented")
			}
		}
		instance, err := parse.JSON(ctx, bytes.NewReader(response.Body.Bytes()), parse.DefaultLimits())
		if err != nil {
			t.Fatal("native verification response not JSON")
		}
		report, err := validate.SchemaInstance(ctx, parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || !report.Valid() {
			t.Fatal("native verification response violates selected wire")
		}
	}
	validateResponse(w)
	if cookieWorkflow != nil {
		for _, scenario := range []string{"wrong-synchronizer", "wrong-password"} {
			var proofsBefore, outboxesBefore int
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records),(SELECT count(*) FROM public.identity_outbox_bindings)`).Scan(&proofsBefore, &outboxesBefore); e != nil {
				t.Fatal("denial baseline unavailable", e)
			}
			bad := request(true)
			if scenario == "wrong-synchronizer" {
				bad.Header.Set("X-CSRF-Token", strings.Repeat("A", 43))
			} else {
				var fields map[string]string
				if json.Unmarshal(body, &fields) != nil {
					t.Fatal("request fixture invalid")
				}
				fields["password"] = "incorrect-synthetic-password"
				badBody, e := json.Marshal(fields)
				if e != nil {
					t.Fatal(e)
				}
				defer clear(badBody)
				bad.Body = io.NopCloser(bytes.NewReader(badBody))
				bad.ContentLength = int64(len(badBody))
			}
			denied := httptest.NewRecorder()
			h.ServeHTTP(denied, bad)
			validateResponse(denied)
			var denial passwordhttp.VerificationResponse
			if json.Unmarshal(denied.Body.Bytes(), &denial) != nil || denied.Code != 403 || denial.Verified || denial.Proof != nil || len(denied.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("native cookie denial failed: case=%s status=%d", scenario, denied.Code)
			}
			// Mismatch may deliberately expose no command ID. Prove absence of
			// protected success effects independently of disclosure; failure audits
			// are allowed and do not make these serial fixture counts increase.
			var proofsAfter, outboxesAfter int
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records),(SELECT count(*) FROM public.identity_outbox_bindings)`).Scan(&proofsAfter, &outboxesAfter); e != nil || proofsAfter != proofsBefore || outboxesAfter != outboxesBefore {
				t.Fatal("denial retained protected success effects", e)
			}
		}
	}
	repository, err := passworddb.NewRepository(pool, source.Repository)
	if err != nil {
		t.Fatal(err)
	}
	original, err := repository.Reauthentication(ctx, auth.ProofID(out.Proof.ProofID))
	if err != nil || out.Proof.ProofID != string(out.CommandID) || out.Proof.Purpose != string(original.Proof.Proof.Purpose) || out.Proof.Action != original.Proof.Action || out.Proof.Audience != original.Proof.Proof.Audience || !out.Proof.IssuedAt.Equal(original.Proof.Proof.IssuedAt) || !out.Proof.ExpiresAt.Equal(original.Proof.Proof.ExpiresAt) {
		t.Fatal("native original proof projection changed", err)
	}
	return password.VerificationResult{Proof: original.Proof, CommandID: out.CommandID, Outcome: identity.CommitOutcomeCommitted}
}
