//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// This fixture composes public owners, not a second reference construction
// graph. It proves real HTTPS/durable initiation before the complete NewServer
// profile and OTP browser-completion transport are implemented.
func TestReferenceOriginalFlowHTTPUsesDurableOwners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	c, deps, worker := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	configureReferencePreAuth(t, &c)
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	c.OTP.PreAuth.Origin = origin
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := stores.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, worker)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := features.PreAuth()
	if err != nil {
		t.Fatal(err)
	}
	// Install the existing shared profile first, then enable initiation through
	// the public owner-local Plan/Apply path. The legacy fixture intentionally
	// requires all selected histories to be installed and does not install this
	// independently selectable initiation history.
	base := c
	baseOTP := *c.OTP
	baseOTP.PreAuth = nil
	base.OTP = &baseOTP
	baseStores, err := reference.ComposeStores(base, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := baseStores.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	installOTPGraphFixture(t, ctx, f, baseStores)
	request := applyRequest(t, ctx, stores, []reference.ModuleID{"identity/session/postgres"})
	if out, err := stores.ReferenceMigrationApply(ctx, request); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("selected initiation migration", err)
	}
	// The primitive owns this SQL. This test does not claim the unfinished
	// reference rate migration contributor or invent a process-memory authority.
	if _, err := f.pool.Raw().Exec(ctx, ratepg.SchemaMigration().Up); err != nil {
		t.Fatal("native rate schema", err)
	}
	backend, err := ratepg.OpenStrict(ctx, f.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}}
	makeSelection := func(namespace string) (http.Handler, identityhttp.OpenAPIDocument) {
		t.Helper()
		rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: namespace, IdentifierKey: [32]byte{1}, Now: time.Now, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rate.Close() })
		feature, err := sessionhttp.NewPreAuthFeature(sessionhttp.PreAuthConfig{Network: network, Service: owner, Rate: rate, Cookie: c.OTP.PreAuth.Cookie, Origin: identityhttp.Origin(origin), Action: c.OTP.PreAuthAction, CallbackURL: c.OTP.PreAuth.CallbackURL, PolicyID: c.OTP.PolicyID, PolicyVersion: c.OTP.PolicyVersion, Now: time.Now, MaximumDuration: 3 * time.Second, Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}})
		if err != nil {
			t.Fatal(err)
		}
		ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: network, HandlerTimeout: 4 * time.Second, Document: identityhttp.DocumentConfig{Title: "Reference initiation", Version: "1"}}, ops, nil)
		if err != nil {
			t.Fatal(err)
		}
		return h, doc
	}
	first, doc := makeSelection("reference-original-flow")
	// Independently constructed owners must share the authoritative IP budget.
	second, _ := makeSelection("reference-original-flow")
	// A distinct test-only deployment budget isolates shutdown from the already
	// exhausted live budget; otherwise a 429 could falsely prove closed admission.
	closedProbe, _ := makeSelection("reference-shutdown-probe")
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Owner") == "closed" {
			closedProbe.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-Test-Owner") == "second" {
			second.ServeHTTP(w, r)
			return
		}
		first.ServeHTTP(w, r)
	})
	server.StartTLS()
	client := server.Client()
	client.Timeout = 5 * time.Second
	call := func(body, requestOrigin, selectedOwner string) (*http.Response, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/session/preauth-issue", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", requestOrigin)
		r.Header.Set("X-Test-Owner", selectedOwner)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("real HTTPS initiation", err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		response.Body.Close()
		if err != nil || len(payload) > 16384 {
			t.Fatal("unbounded initiation response")
		}
		return response, payload
	}
	response, _ := call("{}", origin, "first")
	if response.StatusCode != 503 || len(response.Cookies()) != 0 {
		t.Fatal("uninitialized reference graph issued a cookie")
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	response, _ = call("{}", "https://foreign.example", "first")
	if response.StatusCode != 403 || len(response.Cookies()) != 0 {
		t.Fatal("foreign browser origin admitted")
	}
	response, _ = call(`{"remember":null}`, origin, "first")
	if response.StatusCode != 400 || len(response.Cookies()) != 0 {
		t.Fatal("ambiguous remember policy admitted")
	}
	if !strings.Contains(string(doc.JSON()), "/v1/session/preauth-issue") {
		t.Fatal("real selected route missing from document")
	}
	seen := make(map[string]bool)
	for i := 0; i < 19; i++ {
		selectedOwner := "first"
		if i%2 == 1 {
			selectedOwner = "second"
		}
		response, payload := call(`{"remember":true}`, origin, selectedOwner)
		var out sessionhttp.PreAuthResponse
		if response.StatusCode != 200 || json.Unmarshal(payload, &out) != nil || !out.Issued || out.CommitOutcome != "committed" || out.FlowID == "" || seen[string(out.FlowID)] || out.ExpiresAt.Sub(out.IssuedAt) != 5*time.Minute {
			t.Fatalf("original durable issuance %d failed with %d", i, response.StatusCode)
		}
		seen[string(out.FlowID)] = true
		cookies := response.Cookies()
		if len(cookies) != 1 || cookies[0].Name != "__Host-identity_flow" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" || cookies[0].MaxAge < 1 || cookies[0].MaxAge > 300 || strings.Contains(string(payload), cookies[0].Value) {
			t.Fatal("real network credential custody weakened")
		}
		var count int
		// Native instant is canonical nanosecond text, not timestamptz. Bind its
		// documented representation explicitly rather than pgx's time coercion.
		const nativeInstant = "2006-01-02T15:04:05.000000000Z"
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2 AND state='issued' AND issued_at=$3 AND expires_at=$4`, otpTenant, string(out.FlowID), out.IssuedAt.UTC().Format(nativeInstant), out.ExpiresAt.UTC().Format(nativeInstant)).Scan(&count); err != nil || count != 1 {
			t.Fatal("cookie did not correspond to original durable flow", err)
		}
	}
	response, _ = call("{}", origin, "second")
	if response.StatusCode != 429 || response.Header.Get("Retry-After") == "" || len(response.Cookies()) != 0 {
		t.Fatal("independent owner bypassed authoritative IP limit")
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// A fresh authoritative rate budget must not mask the closed owner guard.
	response, _ = call("{}", origin, "closed")
	if response.StatusCode != 503 || len(response.Cookies()) != 0 {
		t.Fatal("closed reference graph issued a credential")
	}
}
